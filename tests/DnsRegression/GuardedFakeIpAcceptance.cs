using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Netch;
using Netch.Controllers;
using Netch.JsonConverter;
using Netch.Models;
using Netch.Models.Modes.ProcessMode;
using Netch.Models.Modes;
using Netch.Models.Modes.TunMode;
using Netch.Services.Dns;
using Serilog;

// Explicitly invoked developer acceptance only. The external recovery worker must
// be armed before this host is allowed to touch any live network settings.
internal static class GuardedFakeIpAcceptance
{
    private static void Check(bool ok, string message) { if (!ok) throw new Exception(message); Console.WriteLine("PASS " + message); }
    public static void Preflight(string planPath)
    {
        using var plan = JsonDocument.Parse(File.ReadAllText(planPath));
        var host = Path.Combine(plan.RootElement.GetProperty("TestDirectory").GetString()!, "host");
        Check(Global.NetchDir.TrimEnd(Path.DirectorySeparatorChar).Equals(host, StringComparison.OrdinalIgnoreCase), "isolated host path checked before original stop");
        Check(File.Exists(Path.Combine(host, "bin", "Redirector.bin")), "native Redirector is staged");
        Check(File.Exists(Path.Combine(Path.GetDirectoryName(planPath)!, "original-settings.json")), "private configuration snapshot exists");
        Check(!plan.RootElement.TryGetProperty("FastLinkAdapter", out _), "adapter-disable test path is prohibited: old Wintun may delete disabled adapters");
        FakeIpModePolicy.CheckNetworkConflicts();
        Console.WriteLine("PASS Fake-IP interface and route conflict preflight");
        if (IsTun(plan.RootElement))
        {
            Check(!NetworkInterface.GetAllNetworkInterfaces().Any(ni => ni.Name == "Netch"), "no preexisting Netch adapter will be reused");
            foreach (var file in new[] { Constants.WintunDllFile, Constants.TUN2SocksFile, "bin\\RouteHelper.bin" })
                Check(File.Exists(Path.Combine(host, file)), "TUN component staged: " + Path.GetFileName(file));
        }
    }
    private static bool IsTun(JsonElement plan) => plan.TryGetProperty("AcceptanceMode", out var mode) && mode.GetString() == "Tun";
    public static int Run(string plan)
    {
        var result = 1;
        _ = Global.MainForm.Handle;
        Global.MainForm.BeginInvoke(async () =>
        {
            try { await HostAsync(plan); result = 0; }
            catch (Exception error) { Console.Error.WriteLine(error); }
            finally { Application.ExitThread(); }
        });
        Application.Run(); return result;
    }

    private static void CheckDeadline(string session)
    {
        using var ready = JsonDocument.Parse(File.ReadAllText(Path.Combine(session, "ready.json")));
        var worker = Process.GetProcessById(ready.RootElement.GetProperty("WorkerId").GetInt32());
        Check(!worker.HasExited && ready.RootElement.GetProperty("DeadlineUtc").GetDateTimeOffset() > DateTimeOffset.UtcNow.AddSeconds(25), "local recovery deadline remains active");
        Check(File.Exists(Path.Combine(session, "backup-task.json")) && File.Exists(Path.Combine(session, "test-started")), "external supervisor authorized this bounded window");
    }

    private static async Task HostAsync(string planPath)
    {
        var session = Path.GetDirectoryName(Path.GetFullPath(planPath))!;
        using var plan = JsonDocument.Parse(File.ReadAllText(planPath));
        var testDirectory = plan.RootElement.GetProperty("TestDirectory").GetString()!;
        Check(Global.NetchDir.TrimEnd(Path.DirectorySeparatorChar).Equals(Path.Combine(testDirectory, "host"), StringComparison.OrdinalIgnoreCase), "isolated host path");
        Check(new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator), "administrator context");
        var until = Stopwatch.StartNew();
        while (!File.Exists(Path.Combine(session, "run-host")))
        { if (until.Elapsed > TimeSpan.FromSeconds(15)) throw new Exception("Supervisor did not register host"); await Task.Delay(50); }
        CheckDeadline(session);
        Check(Process.GetProcessesByName("Netch").Length == 0, "original Netch has exited");
        Directory.SetCurrentDirectory(Global.NetchDir);
        Environment.SetEnvironmentVariable("PATH", Path.Combine(Global.NetchDir, "bin") + ";" + Environment.GetEnvironmentVariable("PATH"));
        Directory.CreateDirectory("logging"); Directory.CreateDirectory("data");
        Log.Logger = new LoggerConfiguration().MinimumLevel.Information().WriteTo.File("logging/acceptance.log").CreateLogger();
        var options = Global.NewCustomJsonSerializerOptions(); options.PropertyNameCaseInsensitive = true;
        options.Converters.Add(new ServerConverterWithTypeDiscriminator()); options.Converters.Add(new JsonStringEnumConverter());
        Global.Settings = JsonSerializer.Deserialize<Setting>(File.ReadAllText(Path.Combine(session, "original-settings.json")), options)!;
        Check(!Global.Settings.DnsPolicy.AllowLocalResolution && !Global.Settings.DnsPolicy.AllowLocalFallback && !Global.Settings.DnsPolicy.FakeIpEnabled, "baseline is strict real-IP");
        var server = Global.Settings.Server[Global.Settings.ServerComboBoxSelectedIndex];
        Global.Settings.DnsPolicy.FakeIpEnabled = true;
        Global.Settings.LocalAddress = "127.0.0.1";
        var tun = IsTun(plan.RootElement);
        Mode mode = tun ? new TunMode { Handle = ["0.0.0.0/1", "128.0.0.0/1"] }
            : new Redirector { Handle = [".*"], FilterTCP = true, FilterUDP = true, FilterParent = false, FilterIntranet = true };
        var modeName = tun ? "TUN" : "full-process";
        try
        {
            Console.WriteLine("PHASE " + modeName + " start " + DateTimeOffset.Now.ToString("O"));
            await MainController.StartAsync(server, mode);
            Check(DnsRuntime.FakeReady, "Fake-IP ready after native " + modeName + " initialization");
            var fake = DnsWire.Addresses(await DnsRuntime.Service!.QueryAsync(DnsWire.Query("example.com", 1))).Single();
            Check(FakeIpPool.IsFake(fake), "real remote answer verified before allocation");
            File.WriteAllText(Path.Combine(session, "test-fake-address.txt"), fake.ToString());
            CheckDeadline(session);
            var client = Process.Start(new ProcessStartInfo(Path.Combine(testDirectory, "probe", "DnsRegression.exe"))
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
                ArgumentList = { testDirectory, "--guarded-client=" + session } })!;
            Global.Job.AddProcess(client);
            var clientOutput = client.StandardOutput.ReadToEndAsync();
            var clientError = client.StandardError.ReadToEndAsync();
            await client.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(40));
            await File.WriteAllTextAsync(Path.Combine(session, "client.log"), await clientOutput + await clientError);
            Check(client.ExitCode == 0 && File.Exists(Path.Combine(session, "client-passed")), "external process reached HTTPS through transparent Fake-IP restoration");
            CheckDeadline(session);
            var core = ((Guard)MainController.ServerController!).Instance;
            core.Kill(); await core.WaitForExitAsync();
            for (var i = 0; i < 30 && DnsRuntime.TransportReady; i++) await Task.Delay(100);
            Check(!DnsRuntime.TransportReady, "test-owned core exit suspends DNS");
            var failure = await QueryAsync(false);
            Check((DnsWire.U16(failure, 2) & 15) == 2 && DnsRuntime.Protection.Active, "core failure returns SERVFAIL and retains guard");
            await MainController.StopAsync();
            CheckDeadline(session);
            await MainController.StartAsync(server, mode);
            Check(DnsRuntime.FakeReady, modeName + " reconnect succeeds");
            try { DnsRuntime.FakePool!.Restore(fake.ToString()); throw new Exception("Old mapping reused"); }
            catch (MessageException) { Console.WriteLine("PASS old session address rejected after reconnect"); }
            File.WriteAllText(Path.Combine(session, "acceptance-passed"), DateTimeOffset.Now.ToString("O"));
        }
        finally
        {
            // The independent worker also repeats restoration if this process dies.
            await MainController.RestoreDnsAsync();
            Log.CloseAndFlush();
        }
    }

    private static async Task<byte[]> QueryAsync(bool tcp)
    {
        using var timeout = new CancellationTokenSource(12000);
        var query = DnsWire.Query("example.com", 1, 1934); byte[] response;
        if (!tcp)
        {
            using var socket = new UdpClient(AddressFamily.InterNetwork);
            await socket.SendAsync(query, new IPEndPoint(IPAddress.Loopback, 53), timeout.Token);
            response = (await socket.ReceiveAsync(timeout.Token)).Buffer;
        }
        else
        {
            using var socket = new TcpClient(); await socket.ConnectAsync(IPAddress.Loopback, 53, timeout.Token);
            var stream = socket.GetStream(); var prefix = new byte[2]; DnsWire.Put16(prefix, 0, (ushort)query.Length);
            await stream.WriteAsync(prefix, timeout.Token); await stream.WriteAsync(query, timeout.Token);
            await stream.ReadExactlyAsync(prefix, timeout.Token); response = new byte[DnsWire.U16(prefix, 0)];
            await stream.ReadExactlyAsync(response, timeout.Token);
        }
        DnsWire.ValidateResponse(query, response); return response;
    }

    public static async Task ClientAsync(string session)
    {
        // This executable is outside the host directory, so NF's self bypass does
        // not exempt it. No explicit SOCKS proxy is used for this request.
        foreach (var tcp in new[] { false, true })
        {
            var response = await QueryAsync(tcp);
            Check((DnsWire.U16(response, 2) & 15) == 0 && DnsWire.Addresses(response).All(FakeIpPool.IsFake), "loopback " + (tcp ? "TCP" : "UDP") + " Fake-IP DNS");
        }
        var address = IPAddress.Parse(File.ReadAllText(Path.Combine(session, "test-fake-address.txt")));
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false, AllowAutoRedirect = false,
            SslOptions = new SslClientAuthenticationOptions { CertificateChainPolicy = RemoteDnsTransport.OfflineCertificatePolicy() },
            ConnectCallback = async (_, token) =>
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try { await socket.ConnectAsync(address, 443, token); return new NetworkStream(socket, true); }
                catch { socket.Dispose(); throw; }
            }
        };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
        using var result = await http.GetAsync("https://example.com/");
        Check(result.IsSuccessStatusCode, "TLS name verified and HTTPS response received via virtual address");
        File.WriteAllText(Path.Combine(session, "client-passed"), DateTimeOffset.Now.ToString("O"));
    }
}
