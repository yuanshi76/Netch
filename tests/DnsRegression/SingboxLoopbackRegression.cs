using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Netch;
using Netch.Models;
using Netch.Servers;
using Netch.Services.Dns;

internal static class SingboxLoopbackRegression
{
    public static async Task RunAsync(string root, string executable, Func<string, Func<Task>, Task> test)
    {
        foreach (var tuic in new[] { false, true })
            await test($"sing-box {(tuic ? "TUIC/BBR" : "AnyTLS")} loopback TLS, DNS transport and mixed sniff route", () => RunProtocolAsync(root, executable, tuic));
    }

    private static async Task RunProtocolAsync(string root, string executable, bool tuic)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=core-fixture.invalid", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder(); names.AddDnsName("core-fixture.invalid");
        request.CertificateExtensions.Add(names.Build());
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var pem = certificate.ExportCertificatePem();
        var ports = new HashSet<int>();
        int Port()
        {
            while (true)
            {
                using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                var port = ((IPEndPoint)listener.LocalEndPoint!).Port;
                if (ports.Add(port)) return port;
            }
        }
        var nodePort = Port(); var mixedPort = Port(); var dnsPort = Port();
        Global.Settings = new();
        Global.Settings.LocalAddress = "127.0.0.1";
        Global.Settings.Socks5LocalPort = (ushort)mixedPort;
        Global.Settings.V2RayConfig.CoreBasicItem.SniffingEnabled = true;
        typeof(DnsRuntime).GetField("<TransportPort>k__BackingField", BindingFlags.Static | BindingFlags.NonPublic)!.SetValue(null, dnsPort);
        Server node = tuic ? new TUICServer() : new AnytlsServer();
        node.Address = "127.0.0.1"; node.Port = nodePort; node.Sni = "core-fixture.invalid";
        node.StreamSecurity = "tls"; node.Cert = pem; node.AllowInsecure = false;
        node.Username = "00000000-0000-4000-8000-000000000008"; node.Password = "isolated-test-only";
        node.HeaderType = "bbr"; node.Alpn = tuic ? "h3" : "";
        var clientConfig = await SingboxConfigUtils.GenerateClientConfigAsync(node);
        clientConfig.route.rules.Add(new Rule4Sbox { inbound = ["mixed"], action = "route", outbound = "proxy" });
        clientConfig.route.rules.Add(new Rule4Sbox { action = "reject" });
        var inbound = new Dictionary<string, object>
        {
            ["type"] = tuic ? "tuic" : "anytls", ["listen"] = "127.0.0.1", ["listen_port"] = nodePort,
            ["users"] = tuic
                ? new object[] { new { uuid = node.Username, password = node.Password } }
                : new object[] { new { name = "fixture", password = node.Password } },
            ["tls"] = new { enabled = true, certificate = new[] { pem }, key = new[] { key.ExportPkcs8PrivateKeyPem() }, alpn = tuic ? new[] { "h3" } : Array.Empty<string>() }
        };
        if (tuic) inbound["congestion_control"] = "bbr";
        var serverConfig = new
        {
            log = new { level = "info" }, inbounds = new[] { inbound },
            outbounds = new[] { new { type = "direct", tag = "echo" } },
            route = new { rules = new[] { new { action = "route", outbound = "echo", override_address = "127.0.0.1" } } }
        };
        var directory = Path.Combine(root, ".build", "core-upgrade", tuic ? "tuic-loopback" : "anytls-loopback");
        Directory.CreateDirectory(directory);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        var processes = new List<(Process Process, Task<string> Out, Task<string> Error, string Role)>();
        async Task StartAsync(string role, object config)
        {
            var path = Path.Combine(directory, role + ".json");
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(config, Global.NewCustomJsonSerializerOptions()));
            var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var argument in new[] { "run", "-c", path }) info.ArgumentList.Add(argument);
            var process = Process.Start(info)!;
            processes.Add((process, process.StandardOutput.ReadToEndAsync(), process.StandardError.ReadToEndAsync(), role));
        }
        var echo = new TcpListener(IPAddress.Loopback, 0); echo.Start();
        try
        {
            await StartAsync("server", serverConfig);
            await StartAsync("client", clientConfig);
            while (true)
            {
                if (processes.Any(p => p.Process.HasExited)) throw new Exception("Isolated sing-box exited before readiness; inspect loopback logs");
                try { using var probe = new TcpClient(); await probe.ConnectAsync(IPAddress.Loopback, dnsPort, timeout.Token); break; }
                catch (SocketException) { await Task.Delay(50, timeout.Token); }
            }
            foreach (var port in new[] { dnsPort, mixedPort })
            {
                var payload = RandomNumberGenerator.GetBytes(32768);
                var echoTask = Task.Run(async () =>
                {
                    using var accepted = await echo.AcceptTcpClientAsync(timeout.Token);
                    var bytes = new byte[payload.Length];
                    await accepted.GetStream().ReadExactlyAsync(bytes, timeout.Token);
                    await accepted.GetStream().WriteAsync(bytes, timeout.Token);
                });
                await using var stream = await SocksConnector.ConnectAsync(port, "remote-only.invalid", ((IPEndPoint)echo.LocalEndpoint).Port, timeout.Token);
                await stream.WriteAsync(payload, timeout.Token);
                var reply = new byte[payload.Length]; await stream.ReadExactlyAsync(reply, timeout.Token);
                await echoTask;
                if (!reply.SequenceEqual(payload)) throw new Exception("TLS proxy payload mismatch");
            }
        }
        finally
        {
            await timeout.CancelAsync(); echo.Stop();
            foreach (var item in processes)
            {
                if (!item.Process.HasExited) item.Process.Kill();
                await item.Process.WaitForExitAsync();
                await File.WriteAllTextAsync(Path.Combine(directory, item.Role + ".log"), await item.Out + await item.Error);
                item.Process.Dispose();
            }
        }
    }
}
