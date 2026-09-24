using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using Netch.Models;
using Netch.Utils;

namespace Netch.Services;

/// <summary>Durable write-ahead ownership, so a crash does not lose TUN route cleanup.</summary>
public sealed class OwnedRouteJournal
{
    public sealed record Entry(string InterfaceId, string DestinationPrefix, string NextHop, int Metric);
    private readonly string _path;
    private readonly Func<Entry, bool, bool> _exists;
    private readonly Func<Entry, bool> _create, _remove;
    private readonly List<Entry> _entries;

    public OwnedRouteJournal(string path, Func<Entry, bool, bool>? exists = null,
        Func<Entry, bool>? create = null, Func<Entry, bool>? remove = null)
    {
        _path = path; _exists = exists ?? Exists;
        _create = create ?? (entry => RouteUtils.CreateRoute(ToRoute(entry)));
        _remove = remove ?? (entry => RouteUtils.DeleteRoute(ToRoute(entry)));
        _entries = File.Exists(path) ? JsonSerializer.Deserialize<List<Entry>>(File.ReadAllText(path))
            ?? throw new MessageException("TUN 路由恢复记录无效。") : [];
        foreach (var entry in _entries) Validate(entry);
    }

    public static Entry Describe(NetRoute route)
    {
        var adapter = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(ni =>
            ni.Supports(NetworkInterfaceComponent.IPv4) && ni.GetIPProperties().GetIPv4Properties().Index == route.InterfaceIndex)
            ?? throw new MessageException("TUN 路由网卡不存在。");
        return new(adapter.Id, route.Network + "/" + route.Cidr, route.Gateway, route.Metric);
    }

    public void Add(Entry entry)
    {
        Validate(entry);
        if (_entries.Contains(entry)) return;
        // Do not claim a preexisting route, even when its metric differs.
        if (_exists(entry, false)) throw new MessageException("TUN 路由已存在，未接管或覆盖：" + entry.DestinationPrefix);
        _entries.Add(entry);
        try { Save(); } catch { _entries.Remove(entry); throw; }
        if (_create(entry)) return;
        _entries.Remove(entry); Save();
        throw new MessageException("TUN 路由创建失败：" + entry.DestinationPrefix);
    }

    public void Restore()
    {
        var failed = false;
        foreach (var entry in _entries.ToArray().Reverse())
        {
            try
            {
                // A removed adapter or a route changed by someone else is no
                // longer this exact owned route. Never delete by prefix alone.
                if (_exists(entry, true) && !_remove(entry)) { failed = true; continue; }
                _entries.Remove(entry); Save();
            }
            catch (Exception error) { failed = true; Log.Warning(error, "TUN owned route cleanup failed"); }
        }
        if (failed) throw new MessageException("部分 TUN 路由尚未恢复，记录已保留供重试。");
    }

    private void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        using (var file = new FileStream(_path + ".tmp", FileMode.Create, FileAccess.Write, FileShare.None))
        { JsonSerializer.Serialize(file, _entries); file.Flush(true); }
        File.Move(_path + ".tmp", _path, true);
    }

    private static void Validate(Entry entry)
    {
        var prefix = entry.DestinationPrefix.Split('/');
        if (!Guid.TryParse(entry.InterfaceId, out _) || prefix.Length != 2 ||
            !IPAddress.TryParse(prefix[0], out var address) || address.AddressFamily != AddressFamily.InterNetwork ||
            !byte.TryParse(prefix[1], out var bits) || bits > 32 ||
            !IPAddress.TryParse(entry.NextHop, out var gateway) || gateway.AddressFamily != AddressFamily.InterNetwork || entry.Metric < 0)
            throw new MessageException("TUN 路由恢复记录包含无效条目。");
    }

    private static NetworkInterface? Adapter(Entry entry) => NetworkInterface.GetAllNetworkInterfaces()
        .FirstOrDefault(ni => Guid.TryParse(ni.Id, out var id) && id == Guid.Parse(entry.InterfaceId) && ni.Supports(NetworkInterfaceComponent.IPv4));

    private static NetRoute ToRoute(Entry entry)
    {
        var index = Adapter(entry)?.GetIPProperties().GetIPv4Properties().Index ?? throw new MessageException("原 TUN 路由网卡已不存在。");
        var parts = entry.DestinationPrefix.Split('/');
        return new() { InterfaceIndex = index, Network = parts[0], Cidr = byte.Parse(parts[1]), Gateway = entry.NextHop, Metric = entry.Metric };
    }

    private static bool Exists(Entry entry, bool exactMetric)
    {
        var adapter = Adapter(entry); if (adapter == null) return false;
        var index = adapter.GetIPProperties().GetIPv4Properties().Index;
        using var search = new ManagementObjectSearcher("root\\StandardCimv2",
            $"SELECT DestinationPrefix, NextHop, RouteMetric FROM MSFT_NetRoute WHERE InterfaceIndex={index} AND AddressFamily=2");
        using var routes = search.Get();
        foreach (ManagementObject route in routes)
        using (route)
            if ((string?)route["DestinationPrefix"] == entry.DestinationPrefix && (string?)route["NextHop"] == entry.NextHop &&
                (!exactMetric || Convert.ToInt32(route["RouteMetric"]) == entry.Metric)) return true;
        return false;
    }
}
