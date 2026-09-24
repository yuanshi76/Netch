using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Win32;
using Netch.Models;

namespace Netch.Services.Dns;

public sealed class DnsProtectionController
{
    private const string RulePrefix = "Netch.StrictDNS.v1.";
    private const string RemoteAddresses = "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
    private readonly SemaphoreSlim _gate = new(1);
    private readonly string _journalPath;
    private bool _watching;
    private bool _active;
    private Journal _journal = new();
    public event Action<string>? Failed;
    public bool Active => _active || File.Exists(_journalPath);
    public DnsProtectionController(string dataDirectory) => _journalPath = Path.Combine(dataDirectory, "dns-protection.json");

    public sealed class Journal
    {
        public int Version { get; set; } = 1;
        public bool BlockIpv6 { get; set; }
        public bool BlockFakeIp { get; set; }
        public List<AdapterState> Adapters { get; set; } = [];
    }
    public sealed class AdapterState
    {
        public string Id { get; set; } = "";
        public int Index { get; set; }
        public bool V6 { get; set; }
        public string[] StaticServers { get; set; } = [];
    }

    public static string[] RuleNames => [RulePrefix + "TCP", RulePrefix + "UDP", RulePrefix + "IPv6", RulePrefix + "FakeIP"];

    public async Task EnableAsync(bool blockIpv6, bool blockFakeIp = false)
    {
        await _gate.WaitAsync();
        try
        {
            LoadJournal();
            _journal.BlockIpv6 = blockIpv6;
            _journal.BlockFakeIp |= blockFakeIp;
            await SaveJournalAsync(); // Save recovery metadata before any system mutation.
            await Task.Run(() => InstallRules(_journal.BlockIpv6, _journal.BlockFakeIp));
            _active = true;
            await ProtectAdaptersAsync();
            if (!_watching)
            {
                NetworkChange.NetworkAddressChanged += OnNetworkChanged;
                _watching = true;
            }
        }
        finally { _gate.Release(); }
    }

    private void LoadJournal()
    {
        if (!File.Exists(_journalPath)) return;
        _journal = JsonSerializer.Deserialize<Journal>(File.ReadAllText(_journalPath)) ?? throw new MessageException("DNS 保护恢复记录损坏，未自动解除保护。");
        if (_journal.Version != 1) throw new MessageException("DNS 保护恢复记录版本不兼容。");
    }

    private async Task SaveJournalAsync()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_journalPath)!);
        var temporary = _journalPath + ".tmp";
        await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(_journal));
        File.Move(temporary, _journalPath, true);
    }

    private static dynamic Policy()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2") ?? throw new MessageException("Windows 防火墙不可用，无法建立 DNS 保护。");
        return Activator.CreateInstance(type)!;
    }

    private static void InstallRules(bool blockIpv6, bool blockFakeIp)
    {
        dynamic policy = Policy();
        foreach (var profile in new[] { 1, 2, 4 })
            if (!(bool)policy.FirewallEnabled[profile])
                throw new MessageException("严格 DNS 需要启用 Windows 防火墙（域、专用、公用配置）。未更改你的防火墙开关。");
        if ((int)policy.LocalPolicyModifyState != 0)
            throw new MessageException("系统策略禁止应用本地防火墙规则，无法启用严格 DNS。");
        AddRule(policy, RulePrefix + "TCP", 6, "53,853,5353,5355,137", RemoteAddresses, true);
        AddRule(policy, RulePrefix + "UDP", 17, "53,853,5353,5355,137", RemoteAddresses, true);
        if (blockIpv6) AddRule(policy, RulePrefix + "IPv6", 256, null, "::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true);
        if (!blockIpv6) RemoveOwnedRule((object)policy.Rules, RulePrefix + "IPv6");
        if (blockFakeIp) AddFakeIpRule((object)policy, NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback && n.Name != "Netch" &&
                (n.Supports(NetworkInterfaceComponent.IPv4) || n.Supports(NetworkInterfaceComponent.IPv6))).Select(n => n.Name).ToArray());
    }

    private static void AddFakeIpRule(object policyObject, string[] interfaces)
    {
        if (interfaces.Length == 0) throw new MessageException("无法确定 Fake-IP 外部出口，已停止启动。");
        dynamic policy = policyObject;
        var name = RulePrefix + "FakeIP";
        dynamic existing = FindRule((object)policy.Rules, name);
        if (existing != null && ((string)existing.Grouping != "Netch DNS Protection" ||
            !string.IsNullOrEmpty((string?)existing.ApplicationName) || !string.IsNullOrEmpty((string?)existing.ServiceName) || (int)existing.Protocol != 256))
            throw new MessageException("已有 Fake-IP 防护规则不属于当前范围，请先停止并恢复系统 DNS。");
        dynamic rule = existing ?? Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule")!)!;
        if (existing == null)
        {
            rule.Name = name; rule.Grouping = "Netch DNS Protection";
            rule.Description = "Netch Fake-IP addresses cannot leave external interfaces. Restore using Netch.";
        }
        rule.Action = 0; rule.Direction = 2; rule.Protocol = 256;
        rule.LocalAddresses = "*"; rule.RemoteAddresses = FakeIpPool.ReservedV4 + "," + FakeIpPool.ReservedV6;
        rule.Profiles = int.MaxValue;
        rule.Interfaces = interfaces.Cast<object>().ToArray();
        rule.Enabled = true;
        if (existing == null) policy.Rules.Add(rule);
    }

    private static void AddRule(dynamic policy, string name, int protocol, string? ports, string addresses, bool enabled)
    {
        dynamic existing = FindRule((object)policy.Rules, name);
        if (existing != null && (string)existing.Grouping != "Netch DNS Protection")
            throw new MessageException("存在其他程序创建的同名防火墙规则，无法启用 DNS 保护。");

        // Windows rejects empty application/service strings on an installed rule.
        // Leave these optional properties unset on creation and never rewrite them
        // during reconnect. Refuse unexpectedly narrowed rules instead of silently
        // accepting an incomplete DNS guard or temporarily removing protection.
        if (existing != null && (!string.IsNullOrEmpty((string?)existing.ApplicationName)
            || !string.IsNullOrEmpty((string?)existing.ServiceName) || (int)existing.Protocol != protocol))
            throw new MessageException("已有 DNS 防护规则的适用范围被修改。请使用“停止并恢复系统 DNS”清理后重试。");

        dynamic rule = existing ?? Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule")!)!;
        if (existing == null)
        {
            rule.Name = name;
            rule.Description = "Netch DNS protection. Use Netch: 停止并恢复系统 DNS to restore the saved settings.";
            rule.Grouping = "Netch DNS Protection";
        }
        rule.Action = 0;
        rule.Direction = 2;
        rule.Protocol = protocol;
        rule.LocalAddresses = "*";
        if (ports != null) { rule.LocalPorts = "*"; rule.RemotePorts = ports; }
        rule.RemoteAddresses = addresses;
        rule.Profiles = int.MaxValue;
        rule.Enabled = enabled;
        // A fresh rule with the same display name has a different Windows identifier:
        // registering it would create a duplicate. Reuse our existing COM rule.
        if (existing == null) policy.Rules.Add(rule);
    }

    private static bool IsMissingRule(Exception exception) =>
        exception.HResult == unchecked((int)0x80070002) &&
        exception is FileNotFoundException or System.Runtime.InteropServices.COMException;

    private static object? FindRule(object rules, string name)
    {
        try { return ((dynamic)rules).Item(name); }
        // COM's HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) is translated by .NET
        // into FileNotFoundException. It means the rule is absent, not a missing DLL.
        catch (Exception exception) when (IsMissingRule(exception)) { return null; }
    }

    private static void RemoveOwnedRule(object rules, string name)
    {
        dynamic rule = FindRule(rules, name);
        if (rule == null || (string)rule.Grouping != "Netch DNS Protection") return;
        try { ((dynamic)rules).Remove(name); }
        catch (Exception exception) when (IsMissingRule(exception)) { } // Already removed by another caller.
    }

    private static string RegistryPath(string id, bool v6) => $@"SYSTEM\CurrentControlSet\Services\{(v6 ? "Tcpip6" : "Tcpip")}\Parameters\Interfaces\{id}";
    private static string[] ReadStaticDns(string id, bool v6)
    {
        using var key = Registry.LocalMachine.OpenSubKey(RegistryPath(id, v6));
        var raw = key?.GetValue("NameServer") as string;
        return (raw ?? "").Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private async Task ProtectAdaptersAsync()
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback || ni.OperationalStatus != OperationalStatus.Up || ni.Name == "Netch") continue;
            var properties = ni.GetIPProperties();
            foreach (var v6 in new[] { false, true })
            {
                if (!ni.Supports(v6 ? NetworkInterfaceComponent.IPv6 : NetworkInterfaceComponent.IPv4)) continue;
                var index = v6 ? properties.GetIPv6Properties().Index : properties.GetIPv4Properties().Index;
                var state = _journal.Adapters.FirstOrDefault(a => a.Id == ni.Id && a.V6 == v6);
                if (state == null)
                {
                    state = new() { Id = ni.Id, Index = index, V6 = v6, StaticServers = ReadStaticDns(ni.Id, v6) };
                    _journal.Adapters.Add(state);
                    await SaveJournalAsync();
                }
                var expected = v6 ? "::1" : "127.0.0.1";
                if (!ReadStaticDns(ni.Id, v6).SequenceEqual(new[] { expected }))
                    await SetDnsAsync(index, v6, [expected]);
            }
        }
    }

    public static async Task SetDnsAsync(int index, bool v6, string[] addresses)
    {
        foreach (var address in addresses)
            if (!IPAddress.TryParse(address, out _)) throw new MessageException("DNS 恢复记录中包含无效 IP。");
        var family = v6 ? "ipv6" : "ipv4";
        if (addresses.Length == 0)
            await NetshAsync(["interface", family, "set", "dnsservers", $"name={index}", "source=dhcp"]);
        else
        {
            await NetshAsync(["interface", family, "set", "dnsservers", $"name={index}", "source=static", $"address={addresses[0]}", "validate=no"]);
            for (var i = 1; i < addresses.Length; i++)
                await NetshAsync(["interface", family, "add", "dnsservers", $"name={index}", $"address={addresses[i]}", $"index={i + 1}", "validate=no"]);
        }
    }

    private static async Task NetshAsync(IEnumerable<string> arguments)
    {
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        using var process = Process.Start(info) ?? throw new IOException("无法启动系统网络配置工具。");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { process.Kill(); throw new MessageException("设置 DNS 超时，保护保持。请使用恢复按钮重试。"); }
        await Task.WhenAll(output, error);
        if (process.ExitCode != 0) throw new MessageException($"系统 DNS 设置失败（{process.ExitCode}）：{output.Result} {error.Result}");
    }

    private async void OnNetworkChanged(object? sender, EventArgs e)
    {
        if (!await _gate.WaitAsync(0)) return;
        try
        {
            if (!_active) return;
            await Task.Run(() => InstallRules(_journal.BlockIpv6, _journal.BlockFakeIp));
            if (_journal.BlockFakeIp) FakeIpModePolicy.CheckNetworkConflicts(true);
            await ProtectAdaptersAsync();
        }
        catch (Exception ex) { Log.Error(ex, "DNS protection update failed"); Failed?.Invoke("网络变化后 DNS 保护更新失败，外部 DNS 阻断保持。" + ex.Message); }
        finally { _gate.Release(); }
    }

    public async Task RestoreAsync()
    {
        await _gate.WaitAsync();
        try
        {
            if (_watching) { NetworkChange.NetworkAddressChanged -= OnNetworkChanged; _watching = false; }
            LoadJournal();
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var state in _journal.Adapters.ToArray())
            {
                var ni = interfaces.FirstOrDefault(n => n.Id == state.Id);
                if (ni == null) continue; // Keep recovery metadata for a disconnected/removed adapter.
                var expected = state.V6 ? "::1" : "127.0.0.1";
                if (ReadStaticDns(state.Id, state.V6).SequenceEqual(new[] { expected }))
                {
                    var properties = ni.GetIPProperties();
                    var index = state.V6 ? properties.GetIPv6Properties().Index : properties.GetIPv4Properties().Index;
                    await SetDnsAsync(index, state.V6, state.StaticServers);
                }
                _journal.Adapters.Remove(state);
                await SaveJournalAsync();
            }
            if (_journal.Adapters.Count != 0)
                throw new MessageException("部分网卡当前不可用；DNS 保护暂时保留。请连接原网卡后再次恢复。");
            await Task.Run(() =>
            {
                dynamic policy = Policy();
                foreach (var name in RuleNames)
                    RemoveOwnedRule((object)policy.Rules, name);
            });
            _active = false;
            if (File.Exists(_journalPath)) File.Delete(_journalPath);
            _journal = new();
            NativeMethods.RefreshDNSCache();
        }
        finally { _gate.Release(); }
    }
}
