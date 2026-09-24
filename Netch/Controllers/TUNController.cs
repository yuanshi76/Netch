using Netch.Interfaces;
using Netch.Interops;
using Netch.Models;
using Netch.Models.Modes;
using Netch.Models.Modes.TunMode;
using Netch.Servers;
using Netch.Utils;
using Netch.Services.Dns;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Netch.Services;

namespace Netch.Controllers
{
    public class TUNController : IModeController
    {
        private OwnedRouteJournal? _routes;

        private TunMode _mode = new();
        private TUNConfig _tunConfig = new();

        private NetRoute _tun;
        private NetRoute _outbound;

        public string Name => "tun2socks";
        public string InterfaceName => "Netch";

        public ModeFeature Features => ModeFeature.SupportSocks5Auth;

        public async Task StartAsync(SocksServer server, Mode mode)
        {
            if (mode is not TunMode tunMode)
                throw new InvalidOperationException();

            _mode = tunMode;
            _tunConfig = Global.Settings.TUNTAP;
            _routes = new(Path.Combine(Configuration.DataDirectoryFullName, "tun-owned-routes.json"));
            _routes.Restore();

            _outbound = NetRoute.GetBestRouteTemplate();
            if (!File.Exists(Path.Combine(Global.NetchDir, Constants.WintunDllFile)))
                throw new MessageException("缺少 bin 中的 wintun.dll。");

            // 组装 tun2socks 参数
            string proxyHost = await server.AutoResolveHostnameAsync();
            int proxyPort = server.Port;
            string? username = server.Auth() ? server.Username : null;
            string? password = server.Auth() ? server.Password : null;
            //string dns = _tunConfig.UseCustomDNS ? _tunConfig.DNS : $"127.0.0.1:{Global.Settings.AioDNS.ListenPort}";

            if (!TUN2Socks.Init(InterfaceName, proxyHost, proxyPort, username, password)) throw new MessageException("tun2socks start failed.");

            int tunIndex = -1;

            // Wait for adapter to be created
            for (var i = 0; i < 30; i++)
            {
                await Task.Delay(200);
                var now = NetworkInterface.GetAllNetworkInterfaces();
                var networkInterface = now.FirstOrDefault(x => x.Name == InterfaceName);
                if (networkInterface == null)
                {
                    continue;
                }
                tunIndex = networkInterface.GetIndex();
                break;
            }
            if (tunIndex == -1)
            {
                Log.Error("虚拟网卡不存在");
                throw new MessageException("tun2socks start failed.");
            }

            _tun = NetRoute.TemplateBuilder(_tunConfig.Gateway, tunIndex);

            if (!RouteHelper.CreateUnicastIP(AddressFamily.InterNetwork, _tunConfig.Address, (byte)Utils.Utils.SubnetToCidr(_tunConfig.Netmask), (ulong)tunIndex))
                throw new MessageException("无法配置 TUN 地址，已停止启动。");

            SetupRouteTable();
            await DnsProtectionController.SetDnsAsync(tunIndex, false, ["127.0.0.1"]);
        }

        public async Task StopAsync()
        {
            try { await Task.Run(ClearRouteTable); }
            finally { if (!await TUN2Socks.FreeAsync()) throw new MessageException("tun2socks 停止失败。"); }
        }

        #region Route

        private void SetupRouteTable()
        {
            //UI 层显示状态：“正在设置路由规则”
            Global.MainForm.StatusText(i18N.Translate("Setup Route Table Rule"));
            foreach (var address in DnsRuntime.ConnectionAddresses.Where(a => !IPAddress.IsLoopback(a)))
                AddRoute(_outbound.FillTemplate(address.ToString(), 32));

            // Global Bypass IPs
            AddRoutes(_outbound, _tunConfig.BypassIPs);

            // rule
            AddRoutes(_tun, _mode.Handle);
            AddRoutes(_outbound, _mode.Bypass);

            if (Global.Settings.DnsPolicy.FakeIpEnabled)
                AddRoute(_tun.FillTemplate("198.18.0.0", 15));

            NetworkInterfaceUtils.SetInterfaceMetric(_tun.InterfaceIndex, 0);
        }

        private void ClearRouteTable()
        {
            _routes?.Restore();
        }

        private void AddRoute(NetRoute route)
        {
            _routes!.Add(OwnedRouteJournal.Describe(route));
        }

        private void AddRoutes(NetRoute template, IEnumerable<string> rules)
        {
            foreach (var rule in rules)
            {
                if (!RouteUtils.TryParseIPNetwork(rule, out var network, out var cidr) || cidr is < 0 or > 32 ||
                    !IPAddress.TryParse(network, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
                    throw new MessageException($"无效的 IPv4 路由：{rule}");
                AddRoute(template.FillTemplate(network, (byte)cidr));
            }
        }

        #endregion
    }
}
