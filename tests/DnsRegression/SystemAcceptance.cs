using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;
using Netch;
using Netch.Controllers;
using Netch.JsonConverter;
using Netch.Models;
using Netch.Services.Dns;
using Netch.Utils;
using Serilog;

// Separately built developer harness, never packaged in Netch.exe. This opt-in
// suite changes system DNS temporarily and always restores its own journal.
internal static class SystemAcceptance
{
    public static async Task RestoreAsync(string root)
    {
        Check(Global.NetchDir.StartsWith(Path.Combine(root, ".build", "acceptance-host"), StringComparison.OrdinalIgnoreCase), "isolated recovery directory");
        if (File.Exists(Path.Combine(Global.NetchDir, "data", "dns-protection.json"))) await DnsRuntime.Protection.RestoreAsync();
        Firewall.RemoveNetchFwRules();
        Console.WriteLine("PASS independent recovery completed");
    }
    public static int Run(string root, bool captureOnly = false)
    {
        var result = 1;
        _ = Global.MainForm.Handle;
        Global.MainForm.BeginInvoke(async () =>
        {
            try { await RunAsync(root, captureOnly); result = 0; }
            catch (Exception ex) { Console.Error.WriteLine(ex); }
            finally { Application.ExitThread(); }
        });
        Application.Run();
        return result;
    }
    private static void Check(bool ok, string text)
    {
        if (!ok) throw new Exception(text);
        Console.WriteLine("PASS " + text);
    }

    public static async Task RunAsync(string root, bool captureOnly)
    {
        Check(new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator), "administrator context");
        Check(Global.NetchDir.StartsWith(Path.Combine(root, ".build", "acceptance-host"), StringComparison.OrdinalIgnoreCase), "isolated harness directory");
        Check(Process.GetProcessesByName("Netch").Length == 0, "no running Netch instance");
        Check(!File.Exists(@"D:\Netch\data\dns-protection.json") && !DnsRuntime.Protection.Active, "no existing DNS protection journal");
        Check(!IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(e => e.Port == 53)
            && !IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().Any(e => e.Port == 53), "port 53 initially free");
        dynamic firewall = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")!)!;
        foreach (dynamic rule in firewall.Rules)
            if (DnsProtectionController.RuleNames.Contains((string)rule.Name)) throw new Exception("Existing guard must be handled by its owner before this test.");
        Console.WriteLine("PASS no preexisting DNS guard rules");

        Directory.SetCurrentDirectory(Global.NetchDir);
        Directory.CreateDirectory("logging"); Directory.CreateDirectory("data");
        Environment.SetEnvironmentVariable("PATH", Path.Combine(Global.NetchDir, "bin") + ";" + Environment.GetEnvironmentVariable("PATH"));
        Log.Logger = new LoggerConfiguration().MinimumLevel.Information().WriteTo.File("logging/acceptance.log").CreateLogger();
        var options = Global.NewCustomJsonSerializerOptions(); options.PropertyNameCaseInsensitive = true;
        options.Converters.Add(new ServerConverterWithTypeDiscriminator()); options.Converters.Add(new JsonStringEnumConverter());
        Global.Settings = JsonSerializer.Deserialize<Setting>(await File.ReadAllTextAsync(@"D:\Netch\data\settings.json"), options)!;
        Check(!Global.Settings.DnsPolicy.AllowLocalResolution && !Global.Settings.DnsPolicy.AllowLocalFallback, "user policy is strict");
        var server = Global.Settings.Server[Global.Settings.ServerComboBoxSelectedIndex];
        Global.Settings.Socks5LocalPort = (ushort)FreePort(); Global.Settings.LocalAddress = "127.0.0.1";
        var baseline = AdapterSnapshot();
        File.WriteAllText("data/baseline-adapters.json", baseline);
        // Use the same installed driver and process-mode settings, but restrict
        // intercepted applications to the acceptance probe, keeping other apps out.
        var mode = (Netch.Models.Modes.ProcessMode.Redirector)ModeHelper.LoadMode(@"D:\Netch\mode\Custom\桌面常用.json");
        mode.Handle = ["NetchAcceptanceProbe"]; mode.FilterParent = false;
        var originalPolicy = Global.Settings.DnsPolicy;
        var originalAddress = server.Address; var originalPort = server.Port;
        _ = Global.MainForm;
        try
        {
            if (captureOnly)
            {
                await MainController.StartAsync(server, mode);
                using var capture = new PacketCapture(root);
                capture.Start();
                await capture.ControlAsync();
                await Task.Delay(300);
                capture.Checkpoint("control-before");
                capture.ResetCounters();
                await LiveDnsAcceptance.RunAsync(root, true, "capture-connected.json");
                capture.Checkpoint("connected");
                var ownedCore = ((Guard)MainController.ServerController!).Instance;
                ownedCore.Kill(); await ownedCore.WaitForExitAsync();
                for (var i = 0; i < 30 && DnsRuntime.TransportReady; i++) await Task.Delay(100);
                Check(!DnsRuntime.TransportReady, "captured core crash suspends DNS");
                await LiveDnsAcceptance.RunAsync(root, false, "capture-disconnected.json");
                capture.Checkpoint("disconnected");
                await capture.ControlAsync();
                await Task.Delay(500);
                capture.Checkpoint("control-after");
                return;
            }
            // Exact reported failure path: controller allocated but mode never started.
            server.Address = "127.0.0.1"; server.Port = FreePort();
            Global.Settings.DnsPolicy = new DnsPolicyConfig { QueryTimeoutMs = 1000 };
            try { await MainController.StartAsync(server, mode); throw new Exception("unreachable proxy started"); }
            catch (MessageException ex) when (ex.Message.Contains("远程 DNS 验证失败")) { Console.WriteLine("PASS failure before Redirector init was reported"); }
            await QueryAllAsync(2);
            Check(DnsRuntime.Protection.Active && !DnsRuntime.TransportReady, "startup failure keeps DNS guard");
            await MainController.RestoreDnsAsync(); await MainController.RestoreDnsAsync();
            Check(AdapterSnapshot() == baseline, "startup failure restores original adapter settings exactly");
            server.Address = originalAddress; server.Port = originalPort; Global.Settings.DnsPolicy = originalPolicy;

            // Real proxy path, actual shipped xray and Redirector, standard timeout.
            for (var cycle = 0; cycle < 2; cycle++)
            {
                Console.WriteLine($"PHASE real-start-{cycle} {DateTimeOffset.Now:O}");
                await MainController.StartAsync(server, mode);
                await QueryAllAsync(0);
                Check(DnsRuntime.TransportReady, "real proxy DNS ready cycle " + cycle);
                if (cycle == 0)
                {
                    await LiveDnsAcceptance.RunAsync(root);
                    // Kill exactly the core owned by this harness, never by name.
                    var core = ((Guard)MainController.ServerController!).Instance;
                    core.Kill(); await core.WaitForExitAsync();
                    for (var i = 0; i < 30 && DnsRuntime.TransportReady; i++) await Task.Delay(100);
                    Check(!DnsRuntime.TransportReady, "core crash suspends DNS");
                    await QueryAllAsync(2);
                    Check(DnsRuntime.Protection.Active, "core crash retains guard");
                    await MainController.StopAsync(); await MainController.StopAsync();
                    await QueryAllAsync(2);
                }
                else
                {
                    await MainController.StopAsync(); await QueryAllAsync(2);
                    await MainController.RestoreDnsAsync();
                    Check(AdapterSnapshot() == baseline, "stop and restore recovers original adapter settings");
                }
            }
            Console.WriteLine("PHASE start-after-restore " + DateTimeOffset.Now.ToString("O"));
            await MainController.StartAsync(server, mode); await QueryAllAsync(0);
            Console.WriteLine("PASS restart after DNS restoration");
        }
        finally
        {
            Console.WriteLine("PHASE restore-final " + DateTimeOffset.Now.ToString("O"));
            server.Address = originalAddress; server.Port = originalPort; Global.Settings.DnsPolicy = originalPolicy;
            await MainController.RestoreDnsAsync();
            Firewall.RemoveNetchFwRules(); // Only this isolated directory's allow rules.
            Check(AdapterSnapshot() == baseline, "final adapter snapshot matches baseline");
            Check(!DnsRuntime.Protection.Active && DnsRuntime.Service == null, "test DNS guard and listeners removed");
            Log.CloseAndFlush();
        }
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop(); return port;
    }

    private static string AdapterSnapshot()
    {
        var result = new SortedDictionary<string, string>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        foreach (var family in new[] { "Tcpip", "Tcpip6" })
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{family}\Parameters\Interfaces\{ni.Id}");
            if (key != null) result[ni.Id + "/" + family] = key.GetValue("NameServer") as string ?? "";
        }
        return JsonSerializer.Serialize(result);
    }

    private static async Task QueryAllAsync(int expected)
    {
        foreach (var address in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
        foreach (var tcp in new[] { false, true })
        {
            using var timeout = new CancellationTokenSource(10000);
            var query = DnsWire.Query("example.com", 1); byte[] response;
            if (!tcp)
            {
                using var client = new UdpClient(address.AddressFamily);
                await client.SendAsync(query, new IPEndPoint(address, 53), timeout.Token);
                response = (await client.ReceiveAsync(timeout.Token)).Buffer;
            }
            else
            {
                using var client = new TcpClient(address.AddressFamily); await client.ConnectAsync(address, 53, timeout.Token);
                var stream = client.GetStream(); var prefix = new byte[2]; DnsWire.Put16(prefix, 0, (ushort)query.Length);
                await stream.WriteAsync(prefix, timeout.Token); await stream.WriteAsync(query, timeout.Token);
                await stream.ReadExactlyAsync(prefix, timeout.Token); response = new byte[DnsWire.U16(prefix, 0)];
                await stream.ReadExactlyAsync(response, timeout.Token);
            }
            DnsWire.ValidateResponse(query, response);
            Check((DnsWire.U16(response, 2) & 15) == expected, $"{address} {(tcp ? "TCP" : "UDP")} DNS RCODE {expected}");
        }
    }
}
