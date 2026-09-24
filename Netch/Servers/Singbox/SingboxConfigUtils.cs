using Netch.Enums;
using Netch.Manager;
using Netch.Models;
using Netch.Utils;
using Netch.Services.Dns;
using System.Text.RegularExpressions;

#pragma warning disable VSTHRD200

namespace Netch.Servers;

public static class SingboxConfigUtils
{
    private static readonly string _tag = "CoreConfigSingboxService";
    public static async Task<SingboxConfig> GenerateClientConfigAsync(Server server)
    {
        var singboxConfig = new SingboxConfig();
        singboxConfig.log = new Log4Sbox()
        {
            level = Constants.LogLevels[2]
        };

        singboxConfig.dns = new Dns4Sbox
        {
            servers = [new Server4Sbox { type = "tcp", tag = "dns-policy", server = "127.0.0.1", server_port = DnsRuntime.CoreDnsPort }],
            final = "dns-policy", disable_cache = true
        };
        singboxConfig.inbounds = [GenerateInbound(), new Inbound4Sbox
        {
            tag = RemoteDnsService.TransportTag, type = "socks", listen = "127.0.0.1", listen_port = DnsRuntime.TransportPort
        }];

        singboxConfig.outbounds = [await GenerateOutbound(server)];
        singboxConfig.outbounds[0].tag = "proxy";
        singboxConfig.route = new Route4Sbox
        {
            default_domain_resolver = new Rule4Sbox { server = "dns-policy" },
            final = "proxy", rules = [new Rule4Sbox { inbound = [RemoteDnsService.TransportTag], action = "route", outbound = "proxy" }]
        };
        // sing-box 1.13 removed inbound.sniff. Keep DNS transport ahead of sniffing.
        singboxConfig.route.rules.Add(new Rule4Sbox { ip_cidr = [FakeIpPool.ReservedV4, FakeIpPool.ReservedV6], action = "reject" });
        if (Global.Settings.V2RayConfig.CoreBasicItem.SniffingEnabled)
            singboxConfig.route.rules.Add(new Rule4Sbox { inbound = [EInboundProtocol.mixed.ToString()], action = "sniff" });
        if (Global.Settings.DnsPolicy.FakeIpEnabled) AddFakeIpDomainRules(singboxConfig);
        return singboxConfig;
    }

    private static void AddFakeIpDomainRules(SingboxConfig config)
    {
        var profile = Global.Settings.RoutingProfiles.FirstOrDefault(p => p.Enabled && p.Id == Global.Settings.ActiveRoutingProfileId);
        foreach (var source in profile?.Rules.Where(r => r.Enabled) ?? [])
        {
            // Process identity is lost at the mixed inbound. Xray geodata and chained
            // outbounds cannot be translated by silently dropping their conditions.
            if (source.Ip.Count != 0 || source.Process.Count != 0 || source.InboundTag.Count != 0 ||
                source.OutboundServerId is not (RoutingOutbound.Proxy or RoutingOutbound.Direct or RoutingOutbound.Block))
                throw new MessageException("sing-box Fake-IP 当前支持域名、端口、TCP/UDP 和协议条件，以及 DIRECT/BLOCK/当前代理。请移除不兼容条件或改用 Xray。");
            var item = new Rule4Sbox();
            foreach (var value in source.Domain.Select(s => s.Trim()).Where(s => s.Length != 0))
            {
                if (value.StartsWith("full:")) (item.domain ??= []).Add(new System.Globalization.IdnMapping().GetAscii(value[5..].TrimEnd('.')));
                else if (value.StartsWith("domain:")) (item.domain_suffix ??= []).Add(new System.Globalization.IdnMapping().GetAscii(value[7..].TrimEnd('.')));
                else if (value.StartsWith("regexp:")) (item.domain_regex ??= []).Add(value[7..]);
                else if (value.Contains(':')) throw new MessageException("sing-box Fake-IP 不支持该域名规则：" + value);
                else (item.domain_keyword ??= []).Add(value);
            }
            foreach (var port in source.Port.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var bounds = port.Split('-');
                if (bounds.Length is < 1 or > 2 || bounds.Any(p => !int.TryParse(p, out var n) || n is < 1 or > 65535) ||
                    bounds.Length == 2 && int.Parse(bounds[0]) > int.Parse(bounds[1])) throw new MessageException("无效的路由端口：" + port);
                if (bounds.Length == 1) (item.port ??= []).Add(int.Parse(port));
                else (item.port_range ??= []).Add(string.Join(':', bounds));
            }
            var networks = source.Network.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (networks.Any(n => n is not ("tcp" or "udp"))) throw new MessageException("路由网络必须为 tcp 或 udp。");
            if (networks.Length != 0) item.network = networks.ToList();
            if (source.Protocol.Count != 0) item.protocol = source.Protocol.ToList();
            if (source.Domain.Count == 0 && item.port == null && item.port_range == null && item.network == null && item.protocol == null) continue;
            item.inbound = [EInboundProtocol.mixed.ToString()];
            item.action = source.OutboundServerId == RoutingOutbound.Block ? "reject" : "route";
            if (item.action == "route") item.outbound = source.OutboundServerId;
            if (item.outbound == RoutingOutbound.Direct && config.outbounds.All(o => o.tag != RoutingOutbound.Direct))
                config.outbounds.Add(new Outbound4Sbox { tag = RoutingOutbound.Direct, type = "direct" });
            config.route.rules.Add(item);
        }
    }

    private static Inbound4Sbox GenerateInbound()
    {
        var inbound = new Inbound4Sbox();
        inbound.tag = EInboundProtocol.mixed.ToString();
        inbound.type = EInboundProtocol.mixed.ToString();
        inbound.listen = Global.Settings.DnsPolicy.FakeIpEnabled ? "127.0.0.1" : Global.Settings.LocalAddress;
        inbound.listen_port = DnsRuntime.ApplicationCorePort;
        return inbound;
    }

    private static async Task<Outbound4Sbox> GenerateOutbound(Server node)
    {
        var protocolExtra = node.ProtoExtra;

        if (DnsRuntime.Strict && new[] { 53, 853, 5353, 5355, 137 }.Contains(node.Port))
            throw new MessageException("节点端口与严格 DNS 阻断端口冲突，请使用其他代理端口。");
        var ipAddress = await DnsRuntime.ConnectionAddressAsync(node.Address);

        var outbound = new Outbound4Sbox
        {
            server = ipAddress,
            server_port = node.Port,
            type = Constants.ProtocolTypes[node.ConfigType],
        };

        switch (node.ConfigType)
        {
            case EConfigType.VMess:
                {
                    outbound.uuid = node.Password;
                    outbound.alter_id = protocolExtra.AlterId ?? 0;
                    if (Constants.VmessSecurities.Contains(protocolExtra.VmessSecurity))
                    {
                        outbound.security = protocolExtra.VmessSecurity;
                    }
                    else
                    {
                        outbound.security = Constants.DefaultSecurity;
                    }

                    GenOutboundMux(node, outbound);
                    GenOutboundTransport(node, outbound);
                    break;
                }
            case EConfigType.Shadowsocks:
                {
                    outbound.method = Constants.SsSecuritiesInSingbox.Contains(protocolExtra.SsMethod)
                        ? protocolExtra.SsMethod : Constants.None;
                    outbound.password = node.Password;

                    if (node.Network == nameof(ETransport.tcp) && node.HeaderType == Constants.TcpHeaderHttp)
                    {
                        outbound.plugin = "obfs-local";
                        outbound.plugin_opts = $"obfs=http;obfs-host={node.RequestHost};";
                    }
                    else
                    {
                        var pluginArgs = string.Empty;
                        if (node.Network == nameof(ETransport.ws))
                        {
                            pluginArgs += "mode=websocket;";
                            pluginArgs += $"host={node.RequestHost};";
                            // https://github.com/shadowsocks/v2ray-plugin/blob/e9af1cdd2549d528deb20a4ab8d61c5fbe51f306/args.go#L172
                            // Equal signs and commas [and backslashes] must be escaped with a backslash.
                            var path = node.Path.Replace("\\", "\\\\").Replace("=", "\\=").Replace(",", "\\,");
                            pluginArgs += $"path={path};";
                        }
                        else if (node.Network == nameof(ETransport.quic))
                        {
                            pluginArgs += "mode=quic;";
                        }
                        if (node.StreamSecurity == Constants.StreamSecurity)
                        {
                            pluginArgs += "tls;";
                            var certs = CertPemManager.ParsePemChain(node.Cert);
                            if (certs.Count > 0)
                            {
                                var cert = certs.First();
                                const string beginMarker = "-----BEGIN CERTIFICATE-----\n";
                                const string endMarker = "\n-----END CERTIFICATE-----";

                                var base64Content = cert.Replace(beginMarker, "").Replace(endMarker, "").Trim();

                                base64Content = base64Content.Replace("=", "\\=");

                                pluginArgs += $"certRaw={base64Content};";
                            }
                        }
                        if (pluginArgs.Length > 0)
                        {
                            outbound.plugin = "v2ray-plugin";
                            pluginArgs += "mux=0;";
                            // pluginStr remove last ';'
                            pluginArgs = pluginArgs[..^1];
                            outbound.plugin_opts = pluginArgs;
                        }
                    }

                    GenOutboundMux(node, outbound);
                    break;
                }
            case EConfigType.SOCKS:
                {
                    outbound.version = "5";
                    if (node.Username.IsNotEmpty()
                        && node.Password.IsNotEmpty())
                    {
                        outbound.username = node.Username;
                        outbound.password = node.Password;
                    }
                    break;
                }
            case EConfigType.HTTP:
                {
                    if (node.Username.IsNotEmpty()
                        && node.Password.IsNotEmpty())
                    {
                        outbound.username = node.Username;
                        outbound.password = node.Password;
                    }
                    break;
                }
            case EConfigType.VLESS:
                {
                    outbound.uuid = node.Password;

                    outbound.packet_encoding = "xudp";

                    if (!protocolExtra.Flow.IsNullOrEmpty())
                    {
                        outbound.flow = protocolExtra.Flow;
                    }
                    else
                    {
                        GenOutboundMux(node, outbound);
                    }

                    GenOutboundTransport(node, outbound);
                    break;
                }
            case EConfigType.Trojan:
                {
                    outbound.password = node.Password;

                    GenOutboundMux(node, outbound);
                    GenOutboundTransport(node, outbound);
                    break;
                }
            case EConfigType.Hysteria2:
                {
                    outbound.password = node.Password;

                    if (!protocolExtra.SalamanderPass.IsNullOrEmpty())
                    {
                        outbound.obfs = new()
                        {
                            type = "salamander",
                            password = protocolExtra.SalamanderPass.TrimEx(),
                        };
                    }

                    outbound.up_mbps = protocolExtra?.UpMbps is { } su and >= 0
                        ? su
                        : Global.Settings.HysteriaItem.UpMbps;
                    outbound.down_mbps = protocolExtra?.DownMbps is { } sd and >= 0
                        ? sd
                        : Global.Settings.HysteriaItem.DownMbps;
                    var ports = protocolExtra?.Ports?.IsNullOrEmpty() == false ? protocolExtra.Ports : null;
                    if ((!ports.IsNullOrEmpty()) && (ports.Contains(':') || ports.Contains('-') || ports.Contains(',')))
                    {
                        outbound.server_port = null;
                        outbound.server_ports = ports.Split(',')
                            .Select(p => p.Trim())
                            .Where(p => p.IsNotEmpty())
                            .Select(p =>
                            {
                                var port = p.Replace('-', ':');
                                return port.Contains(':') ? port : $"{port}:{port}";
                            })
                            .ToList();
                        outbound.hop_interval = Global.Settings.HysteriaItem.HopInterval >= 5
                            ? $"{Global.Settings.HysteriaItem.HopInterval}s"
                            : $"{Constants.Hysteria2DefaultHopInt}s";
                        if (int.TryParse(protocolExtra.HopInterval, out var hiResult))
                        {
                            outbound.hop_interval = hiResult >= 5 ? $"{hiResult}s" : outbound.hop_interval;
                        }
                        else if (protocolExtra.HopInterval?.Contains('-') ?? false)
                        {
                            // may be a range like 5-10
                            var parts = protocolExtra.HopInterval.Split('-');
                            if (parts.Length == 2 && int.TryParse(parts[0], out var hiL) &&
                                int.TryParse(parts[0], out var hiH))
                            {
                                var hi = (hiL + hiH) / 2;
                                outbound.hop_interval = hi >= 5 ? $"{hi}s" : outbound.hop_interval;
                            }
                        }
                    }

                    break;
                }
            case EConfigType.TUIC:
                {
                    outbound.uuid = node.Username;
                    outbound.password = node.Password;
                    outbound.congestion_control = node.HeaderType;
                    break;
                }
            case EConfigType.Anytls:
                {
                    outbound.password = node.Password;
                    break;
                }
        }

        GenOutboundTls(node, outbound);

        return outbound;
    }

    private static void GenOutboundMux(Server node, Outbound4Sbox outbound)
    {
        try
        {
            var muxEnabled = node.MuxEnabled ?? Global.Settings.V2RayConfig.CoreBasicItem.MuxEnabled;
            if (muxEnabled && Global.Settings.SingboxConfig.Mux4SboxItem.Protocol.IsNotEmpty())
            {
                var mux = new Multiplex4Sbox()
                {
                    enabled = true,
                    protocol = Global.Settings.SingboxConfig.Mux4SboxItem.Protocol,
                    max_connections = Global.Settings.SingboxConfig.Mux4SboxItem.MaxConnections,
                    padding = Global.Settings.SingboxConfig.Mux4SboxItem.Padding,
                };
                outbound.multiplex = mux;
            }
        }
        catch (Exception ex)
        {
            Log.Error(_tag, ex);
        }
    }

    private static void GenOutboundTransport(Server node, Outbound4Sbox outbound)
    {
        try
        {
            var transport = new Transport4Sbox();

            switch (node.GetNetwork())
            {
                case nameof(ETransport.h2):
                    transport.type = nameof(ETransport.http);
                    transport.host = node.RequestHost.IsNullOrEmpty() ? null : Utils.Utils.String2List(node.RequestHost);
                    transport.path = node.Path.NullIfEmpty();
                    break;

                case nameof(ETransport.tcp):   //http
                    if (node.HeaderType == Constants.TcpHeaderHttp)
                    {
                        transport.type = nameof(ETransport.http);
                        transport.host = node.RequestHost.IsNullOrEmpty() ? null : Utils.Utils.String2List(node.RequestHost);
                        transport.path = node.Path.NullIfEmpty();
                    }
                    break;

                case nameof(ETransport.ws):
                    transport.type = nameof(ETransport.ws);
                    var wsPath = node.Path;

                    // Parse eh and ed parameters from path using regex
                    if (!wsPath.IsNullOrEmpty())
                    {
                        var edRegex = new Regex(@"[?&]ed=(\d+)");
                        var edMatch = edRegex.Match(wsPath);
                        if (edMatch.Success && int.TryParse(edMatch.Groups[1].Value, out var edValue))
                        {
                            transport.max_early_data = edValue;
                            transport.early_data_header_name = "Sec-WebSocket-Protocol";

                            wsPath = edRegex.Replace(wsPath, "");
                            wsPath = wsPath.Replace("?&", "?");
                            if (wsPath.EndsWith('?'))
                            {
                                wsPath = wsPath.TrimEnd('?');
                            }
                        }

                        var ehRegex = new Regex(@"[?&]eh=([^&]+)");
                        var ehMatch = ehRegex.Match(wsPath);
                        if (ehMatch.Success)
                        {
                            transport.early_data_header_name = Uri.UnescapeDataString(ehMatch.Groups[1].Value);
                        }
                    }

                    transport.path = wsPath.NullIfEmpty();
                    if (node.RequestHost.IsNotEmpty())
                    {
                        transport.headers = new()
                        {
                            Host = node.RequestHost
                        };
                    }
                    break;

                case nameof(ETransport.httpupgrade):
                    transport.type = nameof(ETransport.httpupgrade);
                    transport.path = node.Path.NullIfEmpty();
                    transport.host = node.RequestHost.NullIfEmpty();

                    break;

                case nameof(ETransport.quic):
                    transport.type = nameof(ETransport.quic);
                    break;

                case nameof(ETransport.grpc):
                    transport.type = nameof(ETransport.grpc);
                    transport.service_name = node.Path;
                    transport.idle_timeout = Global.Settings.V2RayConfig.GrpcItem.IdleTimeout?.ToString("##s");
                    transport.ping_timeout = Global.Settings.V2RayConfig.GrpcItem.HealthCheckTimeout?.ToString("##s");
                    transport.permit_without_stream = Global.Settings.V2RayConfig.GrpcItem.PermitWithoutStream;
                    break;

                default:
                    break;
            }
            if (transport.type != null)
            {
                outbound.transport = transport;
            }
        }
        catch (Exception ex)
        {
            Log.Error(_tag, ex);
        }
    }

    private static void GenOutboundTls(Server node, Outbound4Sbox outbound)
    {
        try
        {
            if (node.StreamSecurity is not (Constants.StreamSecurityReality or Constants.StreamSecurity))
            {
                return;
            }
            if (node.ConfigType is EConfigType.Shadowsocks or EConfigType.SOCKS or EConfigType.WireGuard)
            {
                return;
            }
            var server_name = node.Address;
            if (node.Sni.IsNotEmpty())
            {
                server_name = node.Sni;
            }
            else if (node.RequestHost.IsNotEmpty())
            {
                server_name = Utils.Utils.String2List(node.RequestHost)?.First();
            }
            var tls = new Tls4Sbox()
            {
                enabled = true,
                record_fragment = Global.Settings.V2RayConfig.CoreBasicItem.EnableFragment ? true : null,
                server_name = server_name,
                insecure = node.AllowInsecure ?? Global.Settings.V2RayConfig.CoreBasicItem.DefAllowInsecure,
                alpn = node.GetAlpn(),
            };
            if (node.Fingerprint.IsNotEmpty())
            {
                tls.utls = new Utls4Sbox()
                {
                    enabled = true,
                    fingerprint = node.Fingerprint.IsNullOrEmpty() ? Global.Settings.V2RayConfig.CoreBasicItem.DefFingerprint : node.Fingerprint
                };
            }
            if (node.StreamSecurity == Constants.StreamSecurity)
            {
                var certs = CertPemManager.ParsePemChain(node.Cert);
                if (certs.Count > 0)
                {
                    tls.certificate = certs;
                    tls.insecure = false;
                }
            }
            else if (node.StreamSecurity == Constants.StreamSecurityReality)
            {
                tls.reality = new Reality4Sbox()
                {
                    enabled = true,
                    public_key = node.PublicKey,
                    short_id = node.ShortId
                };
                tls.insecure = false;
            }
            var (ech, _) = ParseEchParam(node.EchConfigList);
            if (ech is not null)
            {
                tls.ech = ech;
            }
            outbound.tls = tls;
        }
        catch (Exception ex)
        {
            Log.Error(_tag, ex);
        }
    }

    private static (Ech4Sbox? ech, Server4Sbox? dnsServer) ParseEchParam(string? echConfig)
    {
        if (echConfig.IsNullOrEmpty())
        {
            return (null, null);
        }
        if (!echConfig.Contains("://"))
        {
            return (new Ech4Sbox()
            {
                enabled = true,
                config = [$"-----BEGIN ECH CONFIGS-----\n" +
                          $"{echConfig}\n" +
                          $"-----END ECH CONFIGS-----"],
            }, null);
        }
        var idx = echConfig.IndexOf('+');
        // NOTE: query_server_name, since sing-box 1.13.0
        //var queryServerName = idx > 0 ? echConfig[..idx] : null;
        var echDnsServer = idx > 0 ? echConfig[(idx + 1)..] : echConfig;
        return (new Ech4Sbox()
        {
            enabled = true,
            query_server_name = null,
        }, ParseDnsAddress(echDnsServer));
    }

    private static Server4Sbox? ParseDnsAddress(string address)
    {
        var addressFirst = address?.Split(address.Contains(',') ? ',' : ';').FirstOrDefault()?.Trim();
        if (string.IsNullOrEmpty(addressFirst))
        {
            return null;
        }

        var server = new Server4Sbox();

        if (addressFirst is "local" or "localhost")
        {
            server.type = "local";
            return server;
        }

        var (domain, scheme, port, path) = Utils.Utils.ParseUrl(addressFirst);

        if (scheme.Equals("dhcp", StringComparison.OrdinalIgnoreCase))
        {
            server.type = "dhcp";
            if ((!domain.IsNullOrEmpty()) && domain != "auto")
            {
                server.server = domain;
            }
            return server;
        }

        if (scheme.IsNullOrEmpty())
        {
            // udp dns
            server.type = "udp";
        }
        else
        {
            // server.type = scheme.ToLower();

            // remove "+local" suffix
            // TODO: "+local" suffix decide server.detour = "direct" ?
            server.type = scheme.Replace("+local", "", StringComparison.OrdinalIgnoreCase).ToLower();
        }

        server.server = domain;
        if (port != 0)
        {
            server.server_port = port;
        }
        if ((server.type == "https" || server.type == "h3") && !string.IsNullOrEmpty(path) && path != "/")
        {
            server.path = path;
        }
        return server;
    }
}
