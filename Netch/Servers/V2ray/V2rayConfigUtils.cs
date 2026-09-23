using Netch.Enums;
using Netch.Manager;
using Netch.Models;
using Netch.Utils;
using Netch.Services.Dns;

#pragma warning disable VSTHRD200

namespace Netch.Servers;

public static class V2rayConfigUtils
{
    private const string ProxyTag = RoutingOutbound.Proxy;
    private const string DirectTag = RoutingOutbound.Direct;
    private const string BlockTag = RoutingOutbound.Block;
    private const string BalancerPrefix = "balancer:";

    public static async Task<V2rayConfig> GenerateClientConfigAsync(Server server)
    {
        if (GroupServerHelper.IsSecondaryOnlyProxy(server))
        {
            throw new MessageException(GroupServerHelper.PrimaryProxyValidationMessage(server));
        }

        var v2rayConfig = new V2rayConfig();
        v2rayConfig.log = new Log4Ray
        {
            loglevel = server.IsComplexType() ? Constants.LogLevels[0] : Constants.LogLevels[2]
        };

        // The only core resolver is the local policy broker. It never performs system fallback.
        v2rayConfig.dns = new
        {
            servers = new[] { new { address = "tcp+local://127.0.0.1:53", domains = new[] { "regexp:.*" }, skipFallback = true } },
            disableCache = true, disableFallback = true
        };
        v2rayConfig.inbounds = [GenerateInbound(), new Inbounds4Ray
        {
            tag = RemoteDnsService.TransportTag, protocol = "socks", listen = "127.0.0.1",
            port = DnsRuntime.TransportPort, settings = new Inboundsettings4Ray { auth = "noauth", udp = false }
        }];

        v2rayConfig.outbounds = await BuildAllProxyOutbounds(server, ProxyTag, []);
        v2rayConfig.routing = await GenerateRoutingAsync(v2rayConfig, server);

        v2rayConfig.routing ??= new Routing4Ray { domainStrategy = "AsIs", rules = [] };
        var dnsRoute = new RulesItem4Ray { type = "field", inboundTag = [RemoteDnsService.TransportTag] };
        if (server.ConfigType == EConfigType.PolicyGroup)
        {
            v2rayConfig.routing.balancers ??= [];
            dnsRoute.balancerTag = EnsureBalancer(v2rayConfig, v2rayConfig.routing.balancers, ProxyTag);
        }
        else dnsRoute.outboundTag = ProxyTag;
        v2rayConfig.routing.rules.Insert(0, dnsRoute);
        if (v2rayConfig.routing.balancers is { Count: > 0 })
            v2rayConfig.observatory = new Observatory4Ray
            {
                subjectSelector = v2rayConfig.routing.balancers.SelectMany(b => b.selector ?? []).Distinct().ToList(),
                probeUrl = "https://www.gstatic.com/generate_204", probeInterval = "60s", enableConcurrency = true
            };


        return v2rayConfig;
    }

    private static async Task<List<Outbounds4Ray>> BuildAllProxyOutbounds(Server server, string baseTagName, HashSet<string> stack)
    {
        if (!stack.Add(server.Id))
        {
            throw new MessageException("Proxy chain contains a cycle.");
        }

        try
        {
            return server.ConfigType switch
            {
                EConfigType.ProxyChain => await BuildChainOutbounds(server, baseTagName, stack),
                EConfigType.PolicyGroup => await BuildPolicyGroupOutbounds(server, baseTagName, stack),
                _ => [await BuildProxyOutbound(server, baseTagName)]
            };
        }
        finally
        {
            stack.Remove(server.Id);
        }
    }

    private static async Task<Outbounds4Ray> BuildProxyOutbound(Server server, string tag)
    {
        var outbound = await GenerateOutbound(server);
        outbound.tag = tag;
        return outbound;
    }

    private static async Task<List<Outbounds4Ray>> BuildChainOutbounds(Server server, string baseTagName, HashSet<string> stack)
    {
        var childIds = GroupServerHelper.ChildIds(server);
        var nodes = GroupServerHelper.ChildServers(server);
        var missingIds = childIds.Where(id => nodes.All(s => s.Id != id)).ToList();
        if (missingIds.Count > 0)
        {
            throw new MessageException($"Proxy chain contains missing server reference(s): {string.Join(", ", missingIds)}");
        }

        if (nodes.Count < 2)
        {
            throw new MessageException($"Proxy chain requires at least two available servers. Current count: {nodes.Count}.");
        }

        if (GroupServerHelper.IsSecondaryOnlyProxy(nodes[0]))
        {
            throw new MessageException(GroupServerHelper.PrimaryProxyValidationMessage(nodes[0]));
        }

        Log.Information(
            "Build proxy chain {Remark}: {Nodes}",
            server.Remarks,
            string.Join(" -> ", nodes.Select(s => $"{s.ConfigType}:{s.Remarks}:{s.Id}")));

        // UI order is user-facing network order: local -> first hop -> ... -> final exit.
        // Xray dialerProxy works in the opposite direction: the final outbound is tagged
        // as proxy, and it dials through the previous hop.
        var nodesReverse = nodes.AsEnumerable().Reverse().ToList();
        var outbounds = new List<Outbounds4Ray>();
        for (var i = 0; i < nodesReverse.Count; i++)
        {
            var node = nodesReverse[i];
            var currentTag = i == 0 ? baseTagName : $"chain-{baseTagName}-{i}-{SafeTagPart(node)}";
            var dialerProxyTag = i != nodesReverse.Count - 1 ? $"chain-{baseTagName}-{i + 1}-{SafeTagPart(nodesReverse[i + 1])}" : null;

            var nodeOutbounds = await BuildAllProxyOutbounds(node, currentTag, stack);
            if (!dialerProxyTag.IsNullOrWhiteSpace())
            {
                foreach (var chainEndNode in nodeOutbounds.Where(o => o.streamSettings?.sockopt?.dialerProxy.IsNullOrWhiteSpace() ?? true))
                {
                    FillDialerProxy(chainEndNode, dialerProxyTag);
                }
            }

            outbounds.AddRange(nodeOutbounds);
        }

        return outbounds;
    }

    private static async Task<List<Outbounds4Ray>> BuildPolicyGroupOutbounds(Server server, string baseTagName, HashSet<string> stack)
    {
        var nodes = GroupServerHelper.ChildServers(server);
        if (nodes.Count < 1)
        {
            throw new MessageException("Policy group requires at least one available server.");
        }

        var outbounds = new List<Outbounds4Ray>();
        for (var i = 0; i < nodes.Count; i++)
        {
            var tag = nodes.Count == 1 ? baseTagName : $"{baseTagName}-{i + 1}-{SafeTagPart(nodes[i])}";
            outbounds.AddRange(await BuildAllProxyOutbounds(nodes[i], tag, stack));
        }

        return outbounds;
    }

    private static async Task<Routing4Ray?> GenerateRoutingAsync(V2rayConfig v2rayConfig, Server activeServer)
    {
        var routingProfile = Global.Settings.RoutingProfiles
            .FirstOrDefault(p => p.Id == Global.Settings.ActiveRoutingProfileId && p.Enabled);
        var enabledRules = routingProfile?.Rules.Where(r => r.Enabled).ToList() ?? [];
        var userRules = enabledRules.Where(HasRoutingMatcher).ToList();
        Log.Information(
            "Build routing profile {Profile}: {EnabledRules} enabled rule(s), {EffectiveRules} effective rule(s)",
            routingProfile?.Remarks ?? "-",
            enabledRules.Count,
            userRules.Count);
        EnsureGeoDataAvailable(userRules);
        var rules = new List<RulesItem4Ray>();
        var balancers = new List<BalancersItem4Ray>();
        var needsDirect = false;
        var needsBlock = false;

        foreach (var rule in userRules)
        {
            var outboundTag = await ResolveRoutingOutboundTagAsync(rule.OutboundServerId, v2rayConfig, activeServer);
            needsDirect |= outboundTag == DirectTag;
            needsBlock |= outboundTag == BlockTag;

            string? balancerTag = null;
            if (outboundTag.StartsWith(BalancerPrefix, StringComparison.Ordinal))
            {
                var baseTag = outboundTag[BalancerPrefix.Length..];
                balancerTag = EnsureBalancer(v2rayConfig, balancers, baseTag);
                outboundTag = string.Empty;
            }

            var item = BuildRoutingRule(rule, outboundTag, balancerTag);
            if (item != null)
            {
                rules.Add(item);
                Log.Information(
                    "Routing rule {Remark}: {Matchers} -> {Target}",
                    rule.Remarks.IsNullOrWhiteSpace() ? "-" : rule.Remarks,
                    DescribeRoutingRule(rule),
                    balancerTag ?? outboundTag);
            }
        }

        if (v2rayConfig.outbounds.Any(o => o.protocol == "http"))
        {
            rules.Add(new RulesItem4Ray
            {
                type = "field",
                network = "udp",
                outboundTag = BlockTag
            });
            needsBlock = true;
            Log.Information("Routing adds HTTP outbound UDP fallback block after user rules.");
        }

        if (activeServer.ConfigType == EConfigType.PolicyGroup && v2rayConfig.outbounds.Count > 1)
        {
            var balancerTag = EnsureBalancer(v2rayConfig, balancers, ProxyTag);
            rules.Add(new RulesItem4Ray
            {
                type = "field",
                network = "tcp,udp",
                balancerTag = balancerTag
            });
        }

        if (rules.Count == 0)
        {
            if (enabledRules.Count > 0)
            {
                Log.Warning("No Xray routing rules generated because enabled routing rules have no matcher fields.");
            }

            return null;
        }

        if (needsDirect && v2rayConfig.outbounds.All(o => o.tag != DirectTag))
        {
            v2rayConfig.outbounds.Add(BuildDirectOutbound());
        }

        if (needsBlock && v2rayConfig.outbounds.All(o => o.tag != BlockTag))
        {
            v2rayConfig.outbounds.Add(BuildBlockOutbound());
        }

        return new Routing4Ray
        {
            domainStrategy = "AsIs",
            rules = rules,
            balancers = balancers.Count > 0 ? balancers : null
        };
    }

    private static bool HasRoutingMatcher(RoutingRule rule)
    {
        return rule.Domain.Count > 0 ||
               rule.Ip.Count > 0 ||
               !rule.Port.IsNullOrWhiteSpace() ||
               !rule.Network.IsNullOrWhiteSpace() ||
               rule.Protocol.Count > 0 ||
               rule.InboundTag.Count > 0 ||
               rule.Process.Count > 0;
    }

    private static string DescribeRoutingRule(RoutingRule rule)
    {
        var parts = new List<string>();
        if (rule.Domain.Count > 0)
        {
            parts.Add($"domain=[{string.Join(",", rule.Domain)}]");
        }

        if (rule.Ip.Count > 0)
        {
            parts.Add($"ip=[{string.Join(",", rule.Ip)}]");
        }

        if (!rule.Port.IsNullOrWhiteSpace())
        {
            parts.Add($"port={rule.Port}");
        }

        if (!rule.Network.IsNullOrWhiteSpace())
        {
            parts.Add($"network={rule.Network}");
        }

        if (rule.Protocol.Count > 0)
        {
            parts.Add($"protocol=[{string.Join(",", rule.Protocol)}]");
        }

        if (rule.InboundTag.Count > 0)
        {
            parts.Add($"inboundTag=[{string.Join(",", rule.InboundTag)}]");
        }

        if (rule.Process.Count > 0)
        {
            parts.Add($"process=[{string.Join(",", rule.Process)}]");
        }

        return parts.Count > 0 ? string.Join("; ", parts) : "-";
    }

    private static void EnsureGeoDataAvailable(IEnumerable<RoutingRule> rules)
    {
        var needsGeoSite = rules.Any(rule => rule.Domain.Any(IsGeoSiteRule));
        var needsGeoIp = rules.Any(rule => rule.Ip.Any(IsGeoIpRule));

        if (needsGeoSite && !GeoDataUpdateUtil.HasGeoSite)
        {
            throw new MessageException("路由规则使用了 geosite，但 bin\\geosite.dat 不存在。请先在“链式/路由”菜单中更新 GeoSite/GeoIP 数据。");
        }

        if (needsGeoIp && !GeoDataUpdateUtil.HasGeoIp)
        {
            throw new MessageException("路由规则使用了 geoip，但 bin\\geoip.dat 不存在。请先在“链式/路由”菜单中更新 GeoSite/GeoIP 数据。");
        }
    }

    private static bool IsGeoSiteRule(string value)
    {
        return value.StartsWith("geosite:", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsGeoIpRule(string value)
    {
        return value.StartsWith("geoip:", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<string> ResolveRoutingOutboundTagAsync(string outboundServerId, V2rayConfig v2rayConfig, Server activeServer)
    {
        if (outboundServerId.IsNullOrWhiteSpace() || outboundServerId == ProxyTag)
        {
            return ProxyTag;
        }

        if (outboundServerId is DirectTag or BlockTag)
        {
            return outboundServerId;
        }

        var server = Global.Settings.Server.FirstOrDefault(s => s.Id == outboundServerId);
        if (server == null)
        {
            return ProxyTag;
        }

        var tag = $"{server.Id}-{ProxyTag}-{SafeTagPart(server)}";
        if (v2rayConfig.outbounds.Any(o => o.tag != null && o.tag.StartsWith(tag, StringComparison.Ordinal)))
        {
            return tag;
        }

        var outbounds = await BuildAllProxyOutbounds(server, tag, []);
        v2rayConfig.outbounds.AddRange(outbounds);
        return server.ConfigType == EConfigType.PolicyGroup && outbounds.Count > 1 ? $"{BalancerPrefix}{tag}" : tag;
    }

    private static RulesItem4Ray? BuildRoutingRule(RoutingRule rule, string outboundTag, string? balancerTag)
    {
        var item = new RulesItem4Ray
        {
            type = "field",
            outboundTag = outboundTag.NullIfEmpty(),
            balancerTag = balancerTag,
            port = rule.Port.NullIfEmpty(),
            network = rule.Network.NullIfEmpty(),
            domain = rule.Domain.Count > 0 ? rule.Domain : null,
            ip = rule.Ip.Count > 0 ? rule.Ip : null,
            protocol = rule.Protocol.Count > 0 ? rule.Protocol : null,
            inboundTag = rule.InboundTag.Count > 0 ? rule.InboundTag : null,
            process = rule.Process.Count > 0 ? rule.Process : null
        };

        if (item.port == null &&
            item.network == null &&
            item.domain == null &&
            item.ip == null &&
            item.protocol == null &&
            item.inboundTag == null &&
            item.process == null)
        {
            return null;
        }

        return item;
    }

    private static string EnsureBalancer(V2rayConfig v2rayConfig, List<BalancersItem4Ray> balancers, string baseTag)
    {
        var balancerTag = $"{baseTag}-balancer";
        if (balancers.Any(b => b.tag == balancerTag))
        {
            return balancerTag;
        }

        var selector = v2rayConfig.outbounds
            .Where(o => o.tag == baseTag || (o.tag?.StartsWith($"{baseTag}-", StringComparison.Ordinal) ?? false))
            .Select(o => o.tag)
            .Where(tag => !tag.IsNullOrWhiteSpace())
            .ToList();

        balancers.Add(new BalancersItem4Ray
        {
            tag = balancerTag,
            fallbackTag = selector.FirstOrDefault(),
            selector = selector,
            strategy = new BalancersStrategy4Ray
            {
                type = "leastPing"
            }
        });

        return balancerTag;
    }

    private static Outbounds4Ray BuildDirectOutbound()
    {
        return new Outbounds4Ray
        {
            tag = DirectTag,
            protocol = "freedom",
            settings = new Outboundsettings4Ray { domainStrategy = "ForceIP" }
        };
    }

    private static Outbounds4Ray BuildBlockOutbound()
    {
        return new Outbounds4Ray
        {
            tag = BlockTag,
            protocol = "blackhole",
            settings = new Outboundsettings4Ray
            {
                response = new Response4Ray
                {
                    type = "none"
                }
            }
        };
    }

    private static void FillDialerProxy(Outbounds4Ray outbound, string dialerProxyTag)
    {
        outbound.streamSettings ??= new StreamSettings4Ray();
        outbound.streamSettings.sockopt ??= new Sockopt4Ray();
        outbound.streamSettings.sockopt.dialerProxy = dialerProxyTag;
    }

    private static string SafeTagPart(Server server)
    {
        var id = server.Id.IsNullOrWhiteSpace()
            ? Guid.NewGuid().ToString("N")
            : server.Id;

        return $"{server.ConfigType.ToString().ToLowerInvariant()}-{id[..Math.Min(12, id.Length)]}";
    }

    private static async Task<Outbounds4Ray> GenerateOutbound(Server server)
    {
        var outbound = new Outbounds4Ray
        {
            settings = new Outboundsettings4Ray(),
        };

        if (server.ConfigType is EConfigType.TUIC or EConfigType.Anytls)
            throw new MessageException("TUIC / AnyTLS 请作为单独节点使用；当前 Xray 代理链不支持混入这些协议。");
        if (DnsRuntime.Strict && new[] { 53, 853, 5353, 5355, 137 }.Contains(server.Port))
            throw new MessageException("节点端口与严格 DNS 阻断端口冲突，请使用其他代理端口。");
        var ipAddress = await DnsRuntime.ConnectionAddressAsync(server.Address);
        var muxEnabled = server.MuxEnabled ?? Global.Settings.V2RayConfig.CoreBasicItem.MuxEnabled;
        GenOutboundMux(outbound);
        switch (server)
        {
            case SocksServer socks:
            case HttpServer http:
                {
                    outbound.protocol = server is SocksServer ? "socks" : "http";
                    var authServer = server as dynamic;
                    outbound.settings.servers = [
                        new ServersItem4Ray
                        {
                            address = ipAddress,
                            port = server.Port,
                            users = authServer.Auth() ? [
                            new SocksUsersItem4Ray
                            {
                                    user = server.Username,
                                    pass = server.Password,
                                    level = 1
                            }]: null
                        }
                    ];
                    //没有mux选项，强制关闭
                    GenOutboundMux(outbound);
                    break;
                }
            case VLESSServer vless:
                {
                    outbound.protocol = "vless";
                    outbound.settings.vnext = [

                        new VnextItem4Ray
                        {
                            address = ipAddress,
                            port = server.Port,
                            users =[
                                new UsersItem4Ray
                                {
                                    id = vless.Password,
                                    encryption = vless.ProtoExtra.VlessEncryption
                                }
                            ]
                        }
                    ];

                    if (!string.IsNullOrWhiteSpace(vless.ProtoExtra.Flow))
                    {
                        outbound.settings.vnext[0].users[0].flow = vless.ProtoExtra.Flow;
                    }

                    GenOutboundMux(outbound, false, muxEnabled);
                    break;
                }
            case VMessServer vmess:
                {
                    outbound.protocol = "vmess";
                    if (vmess.ProtoExtra.VmessSecurity == "auto" && vmess.StreamSecurity != "none" && !Global.Settings.V2RayConfig.CoreBasicItem.DefAllowInsecure)
                    {
                        vmess.ProtoExtra.VmessSecurity = "zero";
                    }
                    outbound.settings.vnext = [
                        new VnextItem4Ray
                        {
                            address = ipAddress,
                            port = server.Port,
                            users = [
                                new UsersItem4Ray()
                                {
                                    id = vmess.Password,
                                    alterId = vmess.ProtoExtra.AlterId??0,
                                    security = vmess.ProtoExtra.VmessSecurity
                                }
                            ]
                        }
                    ];

                    GenOutboundMux(outbound, muxEnabled, muxEnabled);
                    break;
                }
            case ShadowsocksServer ss:
                outbound.protocol = "shadowsocks";
                outbound.settings.servers =
                [
                    new ServersItem4Ray
                    {
                        address = ipAddress,
                        port = server.Port,
                        password = ss.Password,
                        method = Constants.SsSecuritiesInXray.Contains( ss.ProtoExtra.SsMethod)?ss.ProtoExtra.SsMethod:"none",
                        ota = false,
                        level = 1
                    }
                ];
                //没有mux选项，强制关闭
                GenOutboundMux(outbound);
                break;
            case TrojanServer trojan:
                outbound.protocol = "trojan";
                outbound.settings.servers = [

                    new ServersItem4Ray() // I'm not serious
                    {
                        address = ipAddress,
                        port = server.Port,
                        password = trojan.Password,
                        ota = false,
                        level = 1
                    }
                ];

                if (!string.IsNullOrWhiteSpace(trojan.ProtoExtra.Flow))
                {
                    outbound.settings.servers[0].flow = trojan.ProtoExtra.Flow;
                }

                //没有mux选项，强制关闭
                GenOutboundMux(outbound);
                break;
            case WireGuardServer wg:
                outbound.protocol = "wireguard";
                var address = ipAddress;
                if (Utils.Utils.IsIpv6(address))
                {
                    address = $"[{address}]";
                }
                outbound.settings.address = Utils.Utils.String2List(wg.ProtoExtra.WgInterfaceAddress);
                outbound.settings.secretKey = wg.Password;
                outbound.settings.reserved = Utils.Utils.String2List(wg.ProtoExtra.WgReserved)?.Select(int.Parse).ToList();
                outbound.settings.mtu = wg.ProtoExtra.WgMtu > 0 ? wg.ProtoExtra.WgMtu : Constants.TunMtus.First();
                outbound.settings.peers = [
                    new WireguardPeer4Ray
                    {
                        publicKey = wg.PublicKey,
                        endpoint = address + ":" + server.Port.ToString()
                    }
                ];
                break;
            case Hysteria2Server hysteria2Server:
                outbound.protocol = "hysteria";
                outbound.settings.address = ipAddress;
                outbound.settings.port = server.Port;
                outbound.settings.version = 2;
                break;
        }

        outbound.streamSettings = GenBoundStreamSettings(server, outbound);

        return outbound;
    }

    private static StreamSettings4Ray GenBoundStreamSettings(Server server, Outbounds4Ray outbound)
    {
        var streamSettings = new StreamSettings4Ray();
        try
        {
            var network = server.GetNetwork();
            if (server.ConfigType == EConfigType.Hysteria2)
            {
                network = "hysteria";
            }
            streamSettings.network = network;
            var host = server.RequestHost.TrimEx();
            if (string.IsNullOrWhiteSpace(host) && network is "ws" or "httpupgrade" or "xhttp" or "h2" or "grpc")
                host = server.Address;
            var path = server.Path.TrimEx();
            var sni = server.Sni.TrimEx();
            var useragent = "";
            if (!Global.Settings.V2RayConfig.CoreBasicItem.DefFingerprint.IsNullOrEmpty())
            {
                try
                {
                    useragent = Constants.UserAgentTexts[Global.Settings.V2RayConfig.CoreBasicItem.DefFingerprint];
                }
                catch (KeyNotFoundException)
                {
                    useragent = Constants.UserAgentTexts["chrome"];
                }
            }

            //if tls
            if (server.StreamSecurity == Constants.StreamSecurity)
            {
                streamSettings.security = server.StreamSecurity;

                TlsSettings4Ray tlsSettings = new()
                {
                    allowInsecure = server.AllowInsecure ?? Global.Settings.V2RayConfig.CoreBasicItem.DefAllowInsecure,
                    alpn = server.GetAlpn(),
                    fingerprint = server.Fingerprint.IsNullOrEmpty() ? Global.Settings.V2RayConfig.CoreBasicItem.DefFingerprint : server.Fingerprint,
                    echConfigList = server.EchConfigList,
                    echForceQuery = server.EchForceQuery
                };
                if (!string.IsNullOrWhiteSpace(sni))
                {
                    tlsSettings.serverName = sni;
                }
                else if (!string.IsNullOrWhiteSpace(host))
                {
                    tlsSettings.serverName = Utils.Utils.String2List(host)?.First();
                }
                else tlsSettings.serverName = server.Address;
                var certs = CertPemManager.ParsePemChain(server.Cert);
                if (certs.Count > 0)
                {
                    var certsettings = new List<CertificateSettings4Ray>();
                    foreach (var cert in certs)
                    {
                        var certPerLine = cert.Split("\n").ToList();
                        certsettings.Add(new CertificateSettings4Ray
                        {
                            certificate = certPerLine,
                            usage = "verify",
                        });
                    }
                    tlsSettings.certificates = certsettings;
                    tlsSettings.disableSystemRoot = true;
                    tlsSettings.allowInsecure = false;
                }
                else if (!server.CertSha.IsNullOrEmpty())
                {
                    tlsSettings.pinnedPeerCertSha256 = server.CertSha;
                    tlsSettings.allowInsecure = false;
                }
                streamSettings.tlsSettings = tlsSettings;
            }

            //if Reality
            if (server.StreamSecurity == Constants.StreamSecurityReality)
            {
                streamSettings.security = server.StreamSecurity;

                TlsSettings4Ray realitySettings = new()
                {
                    fingerprint = server.Fingerprint.IsNullOrEmpty() ? Global.Settings.V2RayConfig.CoreBasicItem.DefFingerprint : server.Fingerprint,
                    serverName = sni,
                    publicKey = server.PublicKey,
                    shortId = server.ShortId,
                    spiderX = server.SpiderX,
                    mldsa65Verify = server.Mldsa65Verify,
                    show = false,
                };

                streamSettings.realitySettings = realitySettings;
            }

            //streamSettings
            switch (network)
            {
                case nameof(ETransport.kcp):
                    KcpSettings4Ray kcpSettings = new()
                    {
                        mtu = Global.Settings.V2RayConfig.KcpItem.Mtu,
                        tti = Global.Settings.V2RayConfig.KcpItem.Tti
                    };

                    kcpSettings.uplinkCapacity = Global.Settings.V2RayConfig.KcpItem.UplinkCapacity;
                    kcpSettings.downlinkCapacity = Global.Settings.V2RayConfig.KcpItem.DownlinkCapacity;

                    kcpSettings.congestion = Global.Settings.V2RayConfig.KcpItem.Congestion;
                    kcpSettings.readBufferSize = Global.Settings.V2RayConfig.KcpItem.ReadBufferSize;
                    kcpSettings.writeBufferSize = Global.Settings.V2RayConfig.KcpItem.WriteBufferSize;
                    streamSettings.finalmask ??= new();
                    if (Constants.KcpHeaderMaskMap.TryGetValue(server.HeaderType, out var header))
                    {
                        streamSettings.finalmask.udp =
                        [
                            new Mask4Ray
                            {
                                type = header,
                                settings = server.HeaderType == "dns" && !host.IsNullOrEmpty() ? new MaskSettings4Ray { domain = host } : null
                            }
                        ];
                    }
                    streamSettings.finalmask.udp ??= [];
                    if (path.IsNullOrEmpty())
                    {
                        streamSettings.finalmask.udp.Add(new Mask4Ray
                        {
                            type = "mkcp-original"
                        });
                    }
                    else
                    {
                        streamSettings.finalmask.udp.Add(new Mask4Ray
                        {
                            type = "mkcp-aes128gcm",
                            settings = new MaskSettings4Ray { password = path }
                        });
                    }
                    streamSettings.kcpSettings = kcpSettings;
                    break;
                //ws
                case nameof(ETransport.ws):
                    WsSettings4Ray wsSettings = new();
                    wsSettings.headers = new Headers4Ray();

                    if (!string.IsNullOrWhiteSpace(host))
                    {
                        wsSettings.host = host;
                    }
                    if (!string.IsNullOrWhiteSpace(path))
                    {
                        wsSettings.path = path;
                    }
                    if (!string.IsNullOrWhiteSpace(useragent))
                    {
                        wsSettings.headers.UserAgent = useragent;
                    }
                    streamSettings.wsSettings = wsSettings;

                    break;
                //httpupgrade
                case nameof(ETransport.httpupgrade):
                    HttpupgradeSettings4Ray httpupgradeSettings = new();

                    if (!string.IsNullOrWhiteSpace(path))
                    {
                        httpupgradeSettings.path = path;
                    }
                    if (!string.IsNullOrWhiteSpace(host))
                    {
                        httpupgradeSettings.host = host;
                    }
                    streamSettings.httpupgradeSettings = httpupgradeSettings;

                    break;
                //xhttp
                case nameof(ETransport.xhttp):
                    streamSettings.network = ETransport.xhttp.ToString();
                    XhttpSettings4Ray xhttpSettings = new();

                    if (!string.IsNullOrWhiteSpace(path))
                    {
                        xhttpSettings.path = path;
                    }
                    if (!string.IsNullOrWhiteSpace(host))
                    {
                        xhttpSettings.host = host;
                    }
                    if (!string.IsNullOrWhiteSpace(server.HeaderType) && Constants.XhttpMode.Contains(server.HeaderType))
                    {
                        xhttpSettings.mode = server.HeaderType;
                    }
                    if (!string.IsNullOrWhiteSpace(server.Extra))
                    {
                        xhttpSettings.extra = JsonUtils.ParseJson(server.Extra);
                    }

                    streamSettings.xhttpSettings = xhttpSettings;
                    GenOutboundMux(outbound);

                    break;
                //h2
                case nameof(ETransport.h2):
                    HttpSettings4Ray httpSettings = new();

                    if (host.IsNotEmpty())
                    {
                        httpSettings.host = Utils.Utils.String2List(host);
                    }
                    httpSettings.path = path;

                    streamSettings.httpSettings = httpSettings;

                    break;
                //quic
                case nameof(ETransport.quic):
                    QuicSettings4Ray quicsettings = new()
                    {
                        security = host,
                        key = path,
                        header = new Header4Ray
                        {
                            type = server.HeaderType
                        }
                    };
                    streamSettings.quicSettings = quicsettings;
                    if (server.StreamSecurity == Constants.StreamSecurity)
                    {
                        if (!string.IsNullOrWhiteSpace(sni))
                        {
                            streamSettings.tlsSettings.serverName = sni;
                        }
                        else
                        {
                            streamSettings.tlsSettings.serverName = server.Address;
                        }
                    }
                    break;

                case nameof(ETransport.grpc):
                    GrpcSettings4Ray grpcSettings = new()
                    {
                        authority = host ?? string.Empty,
                        serviceName = path,
                        multiMode = server.HeaderType == Constants.GrpcMultiMode,
                        idle_timeout = Global.Settings.V2RayConfig.GrpcItem.IdleTimeout,
                        health_check_timeout = Global.Settings.V2RayConfig.GrpcItem.HealthCheckTimeout,
                        permit_without_stream = Global.Settings.V2RayConfig.GrpcItem.PermitWithoutStream,
                        initial_windows_size = Global.Settings.V2RayConfig.GrpcItem.InitialWindowsSize,
                    };
                    streamSettings.grpcSettings = grpcSettings;
                    break;

                case "hysteria":
                    var protocolExtra = server.ProtoExtra;
                    var ports = protocolExtra?.Ports;
                    int? upMbps = protocolExtra?.UpMbps is { } su and >= 0
                        ? su
                        : Global.Settings.HysteriaItem.UpMbps;
                    int? downMbps = protocolExtra?.DownMbps is { } sd and >= 0
                        ? sd
                        : Global.Settings.HysteriaItem.UpMbps;
                    var hopInterval = !protocolExtra.HopInterval.IsNullOrEmpty()
                        ? protocolExtra.HopInterval
                        : (Global.Settings.HysteriaItem.HopInterval >= 5
                            ? Global.Settings.HysteriaItem.HopInterval
                            : Constants.Hysteria2DefaultHopInt).ToString();
                    HysteriaUdpHop4Ray? udpHop = null;
                    if (!ports.IsNullOrEmpty() &&
                        (ports.Contains(':') || ports.Contains('-') || ports.Contains(',')))
                    {
                        udpHop = new HysteriaUdpHop4Ray
                        {
                            ports = ports.Replace(':', '-'),
                            interval = hopInterval,
                        };
                    }
                    streamSettings.hysteriaSettings = new()
                    {
                        version = 2,
                        auth = server.Password,
                        up = upMbps > 0 ? $"{upMbps}mbps" : null,
                        down = downMbps > 0 ? $"{downMbps}mbps" : null,
                        udphop = udpHop,
                    };
                    if (!protocolExtra.SalamanderPass.IsNullOrEmpty())
                    {
                        streamSettings.finalmask ??= new();
                        streamSettings.finalmask.udp =
                        [
                            new Mask4Ray
                            {
                                type = "salamander",
                                settings = new MaskSettings4Ray { password = protocolExtra.SalamanderPass.TrimEx(), }
                            }
                        ];
                    }
                    break;

                default:
                    //tcp
                    if (server.HeaderType == Constants.TcpHeaderHttp)
                    {
                        TcpSettings4Ray tcpSettings = new()
                        {
                            header = new Header4Ray
                            {
                                type = server.HeaderType
                            }
                        };

                        //request Host
                        var request = EmbedUtils.GetEmbedText(Constants.V2raySampleHttpRequestFileName);
                        var arrHost = host.Split(',');
                        var host2 = string.Join(",".AppendQuotes(), arrHost);
                        request = request.Replace("$requestHost$", $"{host2.AppendQuotes()}");
                        request = request.Replace("$requestUserAgent$", $"{useragent.AppendQuotes()}");
                        //Path
                        var pathHttp = @"/";
                        if (!string.IsNullOrWhiteSpace(path))
                        {
                            var arrPath = path.Split(',');
                            pathHttp = string.Join(",".AppendQuotes(), arrPath);
                        }
                        request = request.Replace("$requestPath$", $"{pathHttp.AppendQuotes()}");
                        tcpSettings.header.request = JsonUtils.Deserialize<object>(request);

                        streamSettings.tcpSettings = tcpSettings;
                    }
                    break;
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex.ToString());
        }

        return streamSettings;
    }

    public static string getUUID(string uuid)
    {
        if (uuid.Length == 36 || uuid.Length == 32)
        {
            return uuid;
        }
        return uuid.GenerateUUIDv5();
    }

    private static Inbounds4Ray GenerateInbound()
    {
        var inbound = new Inbounds4Ray();
        inbound.tag = EInboundProtocol.mixed.ToString();
        inbound.port = Global.Settings.Socks5LocalPort;
        inbound.protocol = EInboundProtocol.mixed.ToString();
        inbound.listen = Global.Settings.LocalAddress;

        inbound.settings = new Inboundsettings4Ray();
        inbound.settings.auth = "noauth";
        inbound.settings.udp = true;
        inbound.sniffing = GenerateSniffing();

        return inbound;
    }

    private static Sniffing4Ray GenerateSniffing()
    {
        var item = Global.Settings.V2RayConfig.CoreBasicItem;
        return new Sniffing4Ray
        {
            enabled = item.SniffingEnabled,
            destOverride = item.DestOverride.Count > 0 ? item.DestOverride : ["http", "tls", "quic"],
            routeOnly = item.RouteOnly
        };
    }

    private static void GenOutboundMux(Outbounds4Ray outbound, bool enabledTCP = false, bool enabledUDP = false)
    {
        try
        {
            outbound.mux = new Mux4Ray();
            outbound.mux.enabled = false;
            outbound.mux.concurrency = -1;

            if (enabledTCP)
            {
                outbound.mux.enabled = true;
                outbound.mux.concurrency = Global.Settings.V2RayConfig.Mux4RayItem.Concurrency;
            }
            else if (enabledUDP)
            {
                outbound.mux.enabled = true;
                outbound.mux.xudpConcurrency = Global.Settings.V2RayConfig.Mux4RayItem.XudpConcurrency;
                outbound.mux.xudpProxyUDP443 = Global.Settings.V2RayConfig.Mux4RayItem.XudpProxyUDP443;
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex.ToString());
        }
    }
}
