using System.Diagnostics;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Windows.Win32;
using Netch.Models;

namespace Netch.Utils;

public static class NetworkInterfaceUtils
{
    public static NetworkInterface GetBest(AddressFamily addressFamily = AddressFamily.InterNetwork)
    {
        string ipAddress;
        switch (addressFamily)
        {
            case AddressFamily.InterNetwork:
                ipAddress = "114.114.114.114";
                break;
            case AddressFamily.InterNetworkV6:
                throw new NotImplementedException();
            default:
                throw new InvalidOperationException();
        }

        if (PInvoke.GetBestRoute(BitConverter.ToUInt32(IPAddress.Parse(ipAddress).GetAddressBytes(), 0), 0, out var route) != 0)
            throw new MessageException("GetBestRoute 搜索失败");

        return Get((int)route.dwForwardIfIndex);
    }

    public static NetworkInterface Get(int interfaceIndex)
    {
        return NetworkInterface.GetAllNetworkInterfaces().First(n => n.GetIndex() == interfaceIndex);
    }

    public static NetworkInterface Get(Func<NetworkInterface, bool> expression)
    {
        return NetworkInterface.GetAllNetworkInterfaces().First(expression);
    }

    public static void SetInterfaceMetric(int interfaceIndex, int? metric = null)
    {
        var arguments = $"interface ip set interface {interfaceIndex} ";
        if (metric != null)
            arguments += $"metric={metric} ";

        using var process = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe"), arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true
        }) ?? throw new MessageException("无法启动网卡设置工具。");
        if (!process.WaitForExit(15000)) { process.Kill(); throw new MessageException("设置网卡优先级超时。"); }
        if (process.ExitCode != 0) throw new MessageException("设置网卡优先级失败。");
    }
}

public static class NetworkInterfaceExtension
{
    public static int GetIndex(this NetworkInterface ni)
    {
        var ipProperties = ni.GetIPProperties();
        if (ni.Supports(NetworkInterfaceComponent.IPv4))
            return ipProperties.GetIPv4Properties().Index;

        if (ni.Supports(NetworkInterfaceComponent.IPv6))
            return ipProperties.GetIPv6Properties().Index;

        throw new Exception();
    }

    public static void SetDns(this NetworkInterface ni, string primaryDns, string? secondDns = null)
    {
        void VerifyDns(ref string s)
        {
            s = s.Trim();
            if (s.IsNullOrEmpty())
                throw new ArgumentException("DNS format invalid", nameof(primaryDns));
        }

        VerifyDns(ref primaryDns);
        if (secondDns != null)
            VerifyDns(ref primaryDns);

        var wmi = new ManagementClass("Win32_NetworkAdapterConfiguration");
        var mos = wmi.GetInstances().Cast<ManagementObject>();

        var mo = mos.First(m => m["Description"].ToString() == ni.Description);

        var dns = new[] { primaryDns };
        if (secondDns != null)
            dns = dns.Append(secondDns).ToArray();

        var inPar = mo.GetMethodParameters("SetDNSServerSearchOrder");
        inPar["DNSServerSearchOrder"] = dns;

        mo.InvokeMethod("SetDNSServerSearchOrder", inPar, null);
    }
}
