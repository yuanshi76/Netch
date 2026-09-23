using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Netch.Models;
using Netch.Utils;

namespace Netch.Services.Dns;

public static class DnsRuntime
{
    public static DnsProtectionController Protection { get; } = new(Configuration.DataDirectoryFullName);
    public static RemoteDnsService? Service { get; private set; }
    private static RemoteDnsTransport? _transport;
    public static int TransportPort { get; private set; }
    public static bool TransportReady { get; private set; }
    public static string Status { get; private set; } = "";
    public static event Action<string>? StatusChanged;
    public static bool Strict => !Global.Settings.DnsPolicy.AllowLocalResolution;
    public static HashSet<IPAddress> ConnectionAddresses { get; } = [];
    public static bool Ipv4Only { get; set; }

    static DnsRuntime() => Protection.Failed += Report;
    public static void Report(string status)
    {
        Status = status;
        try { StatusChanged?.Invoke(status); }
        catch (Exception ex) { Log.Warning(ex, "DNS status display failed"); }
    }

    public static async Task PrepareAsync()
    {
        Global.Settings.DnsPolicy.Validate();
        if (Global.Settings.Socks5LocalPort == 53 || Global.Settings.Socks5LocalPort == 0)
            throw new MessageException("SOCKS 监听端口不能为 0 或 DNS 使用的 53。");
        await DisposeServiceAsync();
        ConnectionAddresses.Clear();
        TransportPort = PortHelper.GetAvailablePort(PortType.TCP);
        while (TransportPort == Global.Settings.Socks5LocalPort || TransportPort == 53)
            TransportPort = PortHelper.GetAvailablePort(PortType.TCP);
        var snapshot = JsonSerializer.Deserialize<DnsPolicyConfig>(JsonSerializer.Serialize(Global.Settings.DnsPolicy))!;
        _transport = new(TransportPort);
        var local = snapshot.AllowLocalResolution ? new LocalDnsTransport() : null;
        Service = new(snapshot, _transport.QueryAsync, local == null ? null : local.QueryAsync);
        Service.StatusChanged += Report;
        Service.ListenerFailed += OnListenerFailed;
        try { Service.Listen(); }
        catch { await DisposeServiceAsync(); throw; }
    }

    public static async Task ReadyAsync()
    {
        if (Service == null) throw new InvalidOperationException();
        TransportReady = true;
        try { await Service.ProbeAsync(); }
        catch { TransportReady = false; throw; }
    }

    public static void Suspend()
    {
        TransportReady = false;
        Service?.MarkUnavailable();
        if (Protection.Active) Report("代理已停止，DNS 保护保持；可在设置中恢复系统 DNS。");
    }

    public static async Task DisposeServiceAsync()
    {
        TransportReady = false;
        var service = Service;
        var transport = _transport;
        // Detach first: cleanup errors cannot leave an unusable object pinned to the
        // runtime and make every subsequent startup retry dispose that same object.
        Service = null;
        _transport = null;
        try
        {
            if (service != null)
            {
                service.StatusChanged -= Report;
                service.ListenerFailed -= OnListenerFailed;
                await service.DisposeAsync();
            }
        }
        finally { transport?.Dispose(); }
    }

    private static void OnListenerFailed(string message) { TransportReady = false; Report(message); }

    public static async Task<string> ConnectionAddressAsync(string hostname)
    {
        var pinned = Global.Settings.DnsPolicy.FindBootstrapAddress(hostname);
        if (pinned != null) return TrackAddress(pinned);
        if (Strict)
            throw new MessageException($"节点 {hostname} 缺少可用连接 IP，本地 DNS 已关闭。请在“DNS 与隐私”中填写 域名=IP 映射，或明确启用本地解析。");
        var addresses = await System.Net.Dns.GetHostAddressesAsync(hostname);
        return TrackAddress(addresses.FirstOrDefault(a => !Ipv4Only || a.AddressFamily == AddressFamily.InterNetwork)?.ToString()
            ?? throw new MessageException("节点域名解析失败，或没有当前模式支持的地址。"));
    }

    private static string TrackAddress(string address)
    {
        var ip = IPAddress.Parse(address);
        if (Ipv4Only && ip.AddressFamily != AddressFamily.InterNetwork)
            throw new MessageException("当前 TUN 只支持 IPv4，请为节点提供 IPv4 连接地址。");
        ConnectionAddresses.Add(ip);
        return ip.ToString();
    }

    public static async Task<IPAddress?> LookupAsync(string hostname, AddressFamily family = AddressFamily.Unspecified, CancellationToken token = default)
    {
        if (IPAddress.TryParse(hostname, out var ip)) return family == AddressFamily.Unspecified || family == ip.AddressFamily ? ip : null;
        if (!TransportReady || Service == null)
        {
            if (Strict) throw new MessageException("远程 DNS 尚未连接，本地解析已关闭。请先连接具有可用 IP 的代理节点。");
            var pinned = Global.Settings.DnsPolicy.FindBootstrapAddress(hostname);
            if (pinned != null) return IPAddress.Parse(pinned);
            return (await System.Net.Dns.GetHostAddressesAsync(hostname, token)).FirstOrDefault(a => family == AddressFamily.Unspecified || a.AddressFamily == family);
        }
        foreach (var type in family == AddressFamily.InterNetworkV6 ? new ushort[] { 28 } : family == AddressFamily.InterNetwork ? new ushort[] { 1 } : new ushort[] { 1, 28 })
        {
            var response = await Service.QueryAsync(DnsWire.Query(hostname, type, (ushort)Random.Shared.Next(65536)), token);
            var code = DnsWire.U16(response, 2) & 15;
            if (code == 2) throw new MessageException("远程 DNS 不可用，未回退本地。");
            if (code == 3) return null;
            if (code != 0) throw new MessageException($"DNS 查询失败（{code}）。");
            var answer = DnsWire.Addresses(response).FirstOrDefault(a => type == 1 ? a.AddressFamily == AddressFamily.InterNetwork : a.AddressFamily == AddressFamily.InterNetworkV6);
            if (answer != null) return answer;
        }
        return null;
    }
}
