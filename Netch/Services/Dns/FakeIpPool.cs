using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Netch.Models;

namespace Netch.Services.Dns;

/// <summary>Session-scoped leases; durable allocation cursor prevents address reuse after restart.</summary>
public sealed class FakeIpPool : IDisposable
{
    public const string ReservedV4 = "198.18.0.0/15";
    public const string ReservedV6 = "fdfe:dcba:9876::/96";
    private const uint First = 0xc6120000;
    private const int Slots = 131072;
    private readonly object _gate = new();
    private readonly string _journal;
    private readonly FileStream _owner;
    private readonly Func<DateTimeOffset> _now;
    private readonly Dictionary<string, Lease> _names = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<IPAddress, Lease> _addresses = [];
    private readonly int _start, _end, _capacity;
    private int _next, _reserved;
    private bool _disposed;
    public sealed record Lease(string Domain, ushort Type, IPAddress Address, DateTimeOffset Expires);
    private sealed class Cursor { public int Version { get; set; } = 1; public int Next { get; set; } = 1; }

    public FakeIpPool(string dataDirectory, string range, int capacity = 32768, Func<DateTimeOffset>? now = null)
    {
        (_start, _end) = ParseRange(range); _capacity = capacity; _now = now ?? (() => DateTimeOffset.UtcNow);
        Directory.CreateDirectory(dataDirectory);
        _journal = Path.Combine(dataDirectory, "fakeip-cursor.json");
        _owner = new FileStream(_journal + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try
        {
            var cursor = File.Exists(_journal) ? JsonSerializer.Deserialize<Cursor>(File.ReadAllText(_journal)) : new Cursor();
            if (cursor == null || cursor.Version != 1 || cursor.Next is < 1 or > Slots)
                throw new MessageException("Fake-IP 地址分配记录损坏，已停止分配；请保留 data/fakeip-cursor.json 供排查。");
            _next = _reserved = Math.Max(_start, cursor.Next);
        }
        catch { _owner.Dispose(); throw; }
    }

    public static (int Start, int End) ParseRange(string range)
    {
        var parts = (range ?? "").Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(parts[1], out var prefix) || prefix is < 15 or > 24)
            throw new MessageException("Fake-IP IPv4 地址池必须是 198.18.0.0/15 内的 /15 至 /24 子网。");
        var value = BinaryPrimitives.ReadUInt32BigEndian(ip.GetAddressBytes());
        var count = 1u << (32 - prefix);
        if (value < First || value + count > First + Slots || value % count != 0)
            throw new MessageException("Fake-IP 地址池必须按子网边界对齐，且位于 198.18.0.0/15 内。");
        return ((int)(value - First) + 1, (int)(value - First + count) - 1);
    }

    public static bool IsFake(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        var bytes = address.GetAddressBytes();
        if (bytes.Length == 4) { var value = BinaryPrimitives.ReadUInt32BigEndian(bytes); return value >= First && value < First + Slots; }
        return bytes.AsSpan(0, 12).SequenceEqual(IPAddress.Parse("fdfe:dcba:9876::").GetAddressBytes().AsSpan(0, 12));
    }

    public static void ValidateDomainRule(string rule)
    {
        var value = rule?.Trim() ?? "";
        if (value.StartsWith("*.")) value = value[2..];
        if (value.Length == 0 || value.Contains('*') || value.Contains('/') || value.Contains(':'))
            throw new MessageException("Fake-IP 兼容规则仅支持完整域名或 *.example.com 后缀，每行一条。");
        try { _ = DnsWire.Query(value, 1); }
        catch (Exception ex) { throw new MessageException("Fake-IP 兼容域名格式无效。", ex); }
    }

    public static bool MatchesDomain(string domain, IEnumerable<string> rules)
    {
        var name = Normalize(domain);
        return rules.Any(rule =>
        {
            var suffix = rule.Trim(); var wildcard = suffix.StartsWith("*.");
            if (wildcard) suffix = suffix[2..]; suffix = Normalize(suffix);
            return name == suffix || wildcard && name.EndsWith("." + suffix, StringComparison.Ordinal);
        });
    }

    private static string Normalize(string name) => new IdnMapping().GetAscii(name.TrimEnd('.')).ToLowerInvariant();

    public IPAddress Allocate(string domain, ushort type, uint ttl)
    {
        if (type is not (1 or 28) || ttl == 0) throw new InvalidDataException("Fake-IP requires a positive address lease");
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var name = Normalize(domain); var key = type + ":" + name; var now = _now();
            if (!_names.TryGetValue(key, out var old))
            {
                foreach (var entry in _names.Where(p => p.Value.Expires <= now).ToArray())
                { _names.Remove(entry.Key); _addresses.Remove(entry.Value.Address); }
                if (_names.Count >= _capacity) throw new MessageException("Fake-IP 映射已满，请稍后重试。");
                if (_next >= _end) throw new MessageException("Fake-IP 地址池已耗尽，已停止分配。请关闭 Fake-IP 使用真实 IP；不要删除地址分配记录。");
                if (_next >= _reserved)
                {
                    var reserved = Math.Min(_end, _next + 64);
                    var temporary = _journal + ".tmp";
                    using (var file = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
                    { JsonSerializer.Serialize(file, new Cursor { Next = reserved }); file.Flush(true); }
                    File.Move(temporary, _journal, true); // Durable reservation precedes any DNS answer.
                    _reserved = reserved;
                }
                var index = _next++;
                var bytes = type == 1 ? new byte[4] : IPAddress.Parse("fdfe:dcba:9876::").GetAddressBytes();
                BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(bytes.Length - 4), type == 1 ? First + (uint)index : (uint)index);
                old = new(name, type, new IPAddress(bytes), now);
            }
            var lease = old with { Expires = now.AddSeconds(ttl) };
            _names[key] = lease; _addresses[lease.Address] = lease;
            return lease.Address;
        }
    }

    public string Restore(string host)
    {
        if (!IPAddress.TryParse(host, out var address) || !IsFake(address)) return host;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        lock (_gate)
        {
            if (!_disposed && _addresses.TryGetValue(address, out var lease) && lease.Expires > _now()) return lease.Domain;
        }
        throw new MessageException("Fake-IP 映射已失效，请重新解析或重启使用该地址的应用。");
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true; _names.Clear(); _addresses.Clear(); _owner.Dispose();
        }
    }
}
