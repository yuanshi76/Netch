using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Netch.Models;
using Netch.Models.Modes;
using Netch.Models.Modes.ProcessMode;
using Netch.Models.Modes.TunMode;

namespace Netch.Services.Dns;

public static class FakeIpModePolicy
{
    public static void Validate(Mode? mode)
    {
        if (!Global.Settings.DnsPolicy.FakeIpEnabled) return;
        if (mode is TunMode tun)
        {
            foreach (var route in tun.Bypass.Concat(Global.Settings.TUNTAP.BypassIPs))
                if (OverlapsV4(route)) throw new MessageException("TUN 绕过规则与 Fake-IP 保留地址池重叠，请先移除冲突规则。");
            return;
        }
        if (mode is Redirector process && process.Handle.Any(r => r is ".*" or "^.*$") && process.Bypass.Count == 0 &&
            (process.FilterTCP ?? Global.Settings.Redirector.FilterTCP) && (process.FilterUDP ?? Global.Settings.Redirector.FilterUDP) && process.FilterIntranet)
            return;
        throw new MessageException("Fake-IP 需要 TUN 或全进程接管（Handle=.*、无绕过项、开启 TCP/UDP 和内网过滤）。选择性进程、共享和仅 SOCKS 模式请关闭 Fake-IP，使用远程真实 IP。");
    }

    public static bool OverlapsV4(string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(parts[1], out var bits) || bits is < 0 or > 32) throw new MessageException("无效的 IPv4 路由：" + cidr);
        var number = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(ip.GetAddressBytes());
        var mask = bits == 0 ? 0 : uint.MaxValue << (32 - bits);
        var begin = number & mask; var end = begin | ~mask;
        return begin <= 0xc613ffff && end >= 0xc6120000;
    }

    public static void CheckNetworkConflicts(bool allowNetchRoute = false)
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        foreach (var address in ni.GetIPProperties().UnicastAddresses)
            if (FakeIpPool.IsFake(address.Address)) throw new MessageException("现有网卡地址与 Fake-IP 地址池冲突，未修改网络。请保持 Fake-IP 关闭。");
        using var search = new ManagementObjectSearcher("root\\StandardCimv2", "SELECT DestinationPrefix, InterfaceAlias FROM MSFT_NetRoute");
        using var routes = search.Get();
        foreach (ManagementObject route in routes)
        {
            using (route)
            {
                if (allowNetchRoute && (string?)route["InterfaceAlias"] == "Netch") continue;
                var prefix = route["DestinationPrefix"] as string ?? "";
                var parts = prefix.Split('/');
                if (parts.Length == 2 && IPAddress.TryParse(parts[0], out var ip) && int.TryParse(parts[1], out var bits))
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork && bits >= 15 && OverlapsV4(prefix) ||
                        ip.AddressFamily == AddressFamily.InterNetworkV6 && FakeIpPool.IsFake(ip))
                        throw new MessageException("现有路由与 Fake-IP 地址池冲突，未修改网络：" + prefix);
                }
            }
        }
    }
}
