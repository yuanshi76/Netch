using System.Reflection;
using System.Security.Principal;
using Netch.Services.Dns;

// Opt-in elevated test. Every rule is disabled before registration, uses a random
// test-only name and is removed in finally. No live protection rule is touched.
internal static class FirewallIntegration
{
    public static void Run()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("Disabled-rule integration tests require an elevated process.");

        var policy = new DisabledFirewallPolicy();
        var add = typeof(DnsProtectionController).GetMethod("AddRule", BindingFlags.NonPublic | BindingFlags.Static)!;
        var remove = typeof(DnsProtectionController).GetMethod("RemoveOwnedRule", BindingFlags.NonPublic | BindingFlags.Static)!;
        var addresses = (string)typeof(DnsProtectionController).GetField("RemoteAddresses", BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()!;
        foreach (var protocol in new[] { 6, 17, 256 })
        {
            var name = "Netch.DisabledRegression." + Guid.NewGuid().ToString("N");
            var ports = protocol == 256 ? null : "53,853,5353,5355,137";
            var remote = protocol == 256 ? "::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" : addresses;
            try
            {
                for (var pass = 0; pass < 3; pass++)
                {
                    // Reconnect must reapply address coverage without duplicate rules.
                    if (pass == 2)
                    {
                        dynamic existing = policy.Rules.Item(name);
                        existing.RemoteAddresses = "192.0.2.0/24";
                    }
                    add.Invoke(null, new object?[] { policy, name, protocol, ports, remote, false });
                    dynamic rule = policy.Rules.Item(name);
                    Check(!(bool)rule.Enabled, "test rule must remain disabled");
                    Check((int)rule.Action == 0 && (int)rule.Direction == 2 && (int)rule.Protocol == protocol, "rule action, direction and protocol");
                    Check((int)rule.Profiles == int.MaxValue, "all profiles");
                    Check(string.IsNullOrEmpty((string?)rule.ApplicationName) && string.IsNullOrEmpty((string?)rule.ServiceName), "unrestricted application and service");
                    Check((string)rule.RemoteAddresses == remote && (string)rule.LocalAddresses == "*", "address coverage");
                    if (ports != null)
                        Check(((string)rule.RemotePorts).Split(',').Order().SequenceEqual(ports.Split(',').Order()) && (string)rule.LocalPorts == "*", "port coverage");
                    Check(policy.Rules.CountNamed(name) == 1, "repeated registration must not create duplicate rules");
                    Console.WriteLine($"PASS disabled Windows rule protocol={protocol} pass={pass + 1}");
                }
                dynamic narrowed = policy.Rules.Item(name);
                narrowed.ApplicationName = Path.Combine(Environment.SystemDirectory, "notepad.exe");
                narrowed.ServiceName = "Dnscache";
                try { add.Invoke(null, new object?[] { policy, name, protocol, ports, remote, false }); throw new Exception("narrowed protection accepted"); }
                catch (TargetInvocationException ex) when (ex.InnerException is Netch.Models.MessageException) { }
                Check(!(bool)narrowed.Enabled && (string)narrowed.ServiceName == "Dnscache", "refusal preserves the existing disabled rule");
                Console.WriteLine($"PASS disabled Windows rule protocol={protocol} rejects restricted scope");
                remove.Invoke(null, new object[] { policy.Rules, name });
                remove.Invoke(null, new object[] { policy.Rules, name });
                Check(policy.Rules.CountNamed(name) == 0, "repeated recovery");
                Console.WriteLine($"PASS disabled Windows rule protocol={protocol} recovery");
            }
            catch (Exception ex) { Console.Error.WriteLine(ex); throw; }
            finally
            {
                policy.Rules.RemoveIfPresent(name);
                Check(policy.Rules.CountNamed(name) == 0, "temporary rule cleanup");
            }
        }
        Console.WriteLine("PASS: disabled Windows firewall integration; no network settings changed");
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }
}

public sealed class DisabledFirewallPolicy
{
    public DisabledFirewallRules Rules { get; } = new();
}

public sealed class DisabledFirewallRules
{
    private readonly dynamic _policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")!)!;
    public object Item(string name) => _policy.Rules.Item(name);
    public void Add(object value)
    {
        dynamic rule = value;
        CheckTestName((string)rule.Name);
        if ((bool)rule.Enabled) throw new InvalidOperationException("Integration test rules must be disabled before registration.");
        _policy.Rules.Add(rule);
    }
    public void Remove(string name) { CheckTestName(name); _policy.Rules.Remove(name); }
    public void RemoveIfPresent(string name)
    {
        // Windows permits different rule identifiers with the same display name.
        // Clean up all copies if a regression introduced duplicates.
        while (CountNamed(name) > 0) Remove(name);
    }
    public int CountNamed(string name)
    {
        var count = 0;
        foreach (dynamic rule in _policy.Rules) if ((string)rule.Name == name) count++;
        return count;
    }
    private static void CheckTestName(string name)
    {
        if (!name.StartsWith("Netch.DisabledRegression.", StringComparison.Ordinal))
            throw new InvalidOperationException("Integration tests may only modify their own temporary rules.");
    }
}
