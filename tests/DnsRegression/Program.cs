using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Netch;
using Netch.Enums;
using Netch.Models;
using Netch.Services.Dns;
using Netch.Servers;
using Netch.Utils;

internal static class Program
{
    private static int _passed;
    private static readonly byte[] Query = DnsWire.Query("example.test", 1, 1234);
    private static string _root = "";
    private static bool _offline;
    private static int _offlinePort = 62000;

    [STAThread]
    private static int Main(string[] args)
    {
        _root = Path.GetFullPath(args.FirstOrDefault() ?? "../../../..");
        _offline = args.Contains("--offline") || !args.Contains("--allow-listeners");
        try
        {
            if (args.Contains("--render-ui")) { RenderUi(); return 0; }
            if (args.Contains("--firewall-integration")) { FirewallIntegration.Run(); return 0; }
            if (args.Contains("--live-dns")) { LiveDnsAcceptance.RunAsync(_root).GetAwaiter().GetResult(); return 0; }
            if (args.Contains("--system-acceptance")) return SystemAcceptance.Run(_root);
            if (args.Contains("--capture-acceptance")) return SystemAcceptance.Run(_root, true);
            if (args.Contains("--restore-acceptance")) { SystemAcceptance.RestoreAsync(_root).GetAwaiter().GetResult(); return 0; }
            if (args.Contains("--udp-client-lifecycle")) { _offline = false; TestUdpClientDeparture().GetAwaiter().GetResult(); Console.WriteLine("PASS UDP departed-client lifecycle"); return 0; }
            RunAsync().GetAwaiter().GetResult(); Console.WriteLine($"PASS: {_passed} regression groups"); return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }

    private static async Task Test(string name, Func<Task> test)
    {
        await test(); _passed++; Console.WriteLine("PASS " + name);
    }
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); }
    private static async Task Throws<T>(Func<Task> action) where T : Exception
    {
        try { await action(); } catch (T) { return; }
        throw new Exception($"Expected {typeof(T).Name}");
    }
    private static ushort Code(byte[] response) => (ushort)(DnsWire.U16(response, 2) & 15);
    private static byte[] Answer(byte[] query, uint ttl = 60)
    {
        var question = DnsWire.ParseQuestion(query);
        var result = DnsWire.Error(query, 0);
        var offset = result.Length;
        var address = question.Type == 28 ? IPAddress.Parse("2001:db8::7").GetAddressBytes() : new byte[] { 192, 0, 2, 7 };
        Array.Resize(ref result, offset + 12 + address.Length);
        DnsWire.Put16(result, 6, 1);
        result[offset] = 0xc0; result[offset + 1] = 12;
        DnsWire.Put16(result, offset + 2, question.Type);
        DnsWire.Put16(result, offset + 4, 1);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset + 6), ttl);
        DnsWire.Put16(result, offset + 10, (ushort)address.Length);
        address.CopyTo(result, offset + 12);
        return result;
    }

    private static async Task RunAsync()
    {
        await Test("policy defaults and compatibility validation", async () =>
        {
            var p = new DnsPolicyConfig(); p.Validate();
            Check(!p.AllowLocalResolution && !p.AllowLocalFallback, "strict defaults");
            foreach (var address in new[] { "udp://1.1.1.1", "http://1.1.1.1", "https://user:pass@resolver.test", "https://resolver.test/#direct" })
                await Throws<MessageException>(() => { new DnsPolicyConfig { RemoteResolvers = [address] }.Validate(); return Task.CompletedTask; });
            await Throws<MessageException>(() => { new DnsPolicyConfig { AllowLocalFallback = true }.Validate(); return Task.CompletedTask; });
            p.AllowLocalResolution = true; p.LocalDomainRules = ["*.LAN."];
            Check(p.IsLocalDomain("printer.lan") && !p.IsLocalDomain("evil-lan"), "local suffix boundary");
            Check(!JsonSerializer.Deserialize<Setting>("{}")!.DnsPolicy.AllowLocalResolution, "old settings migrate strict");
        });
        await Test("DNS codec IPv4 IPv6 IDN root and CNAME", () =>
        {
            foreach (var name in new[] { "example.test", "例子.测试", ".", "_https._tcp.example.test" })
            {
                var q = DnsWire.Query(name, 1); Check(DnsWire.NormalizeQuery(q).Length == q.Length, "name round trip");
            }
            foreach (var type in new ushort[] { 1, 28 })
            {
                var q = DnsWire.Query("example.test", type);
                var a = Answer(q); DnsWire.ValidateResponse(q, a);
                Check(DnsWire.Addresses(a).Single().AddressFamily == (type == 1 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6), "address type");
            }
            var cname = DnsWire.Error(Query, 0).Concat(new byte[] { 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 8, 5, (byte)'a', (byte)'l', (byte)'i', (byte)'a', (byte)'s', 0xc0, 20 }).ToArray();
            var targetOffset = DnsWire.Error(Query, 0).Length + 12;
            cname = cname.Concat(new byte[] { (byte)(0xc0 | (targetOffset >> 8)), (byte)targetOffset, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 9 }).ToArray();
            DnsWire.Put16(cname, 6, 2); DnsWire.ValidateResponse(Query, cname);
            Check(DnsWire.Addresses(cname).Single().ToString() == "192.0.2.9", "follow CNAME");
            return Task.CompletedTask;
        });
        await Test("strip ECS and cookies while preserving DNSSEC DO and CD", () =>
        {
            var q = Query.Concat(new byte[] { 0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 8, 0, 8, 0, 4, 0, 1, 0, 0 }).ToArray();
            DnsWire.Put16(q, 10, 1); DnsWire.Put16(q, 2, 0x110);
            var n = DnsWire.NormalizeQuery(q);
            Check(n.Length == Query.Length + 11 && DnsWire.U16(n, n.Length - 2) == 0, "EDNS payload stripped");
            Check((DnsWire.U16(n, 2) & 0x10) != 0 && n[Query.Length + 7] == 0x80, "DNSSEC flags");
            return Task.CompletedTask;
        });
        await Test("malformed query fuzz produces FORMERR without upstream access", async () =>
        {
            var calls = 0;
            await using var service = new RemoteDnsService(new(), (_, q, _) => { calls++; return Task.FromResult(Answer(q)); });
            var random = new Random(70);
            for (var i = 0; i < 2000; i++)
            {
                var bytes = new byte[random.Next(300)]; random.NextBytes(bytes);
                Check(Code(await service.QueryAsync(bytes)) == 1, "FORMERR for fuzz input");
            }
            var cycle = new byte[18]; DnsWire.Put16(cycle, 4, 1); cycle[12] = 0xc0; cycle[13] = 12;
            Check(Code(await service.QueryAsync(cycle)) == 1 && calls == 0, "pointer cycle rejected");
        });
        await Test("remote primary failure uses remote backup and never local", async () =>
        {
            var remote = 0; var local = 0;
            await using var service = new RemoteDnsService(new(), (_, q, _) => ++remote == 1 ? Task.FromException<byte[]>(new IOException()) : Task.FromResult(Answer(q)),
                (_, _) => { local++; return Task.FromResult(Answer(Query)); });
            Check(Code(await service.QueryAsync(Query)) == 0 && remote == 2 && local == 0, "only remote fallback");
        });
        await Test("all remote failures SERVFAIL including malformed mismatched and truncated responses", async () =>
        {
            foreach (var kind in new[] { 0, 1, 2, 3, 4 })
            {
                var local = 0;
                await using var service = new RemoteDnsService(new(), (_, q, _) =>
                {
                    var a = Answer(q);
                    if (kind == 0) return Task.FromException<byte[]>(new IOException());
                    if (kind == 1) DnsWire.Put16(a, 0, 9876);
                    if (kind == 2) DnsWire.Put16(a, 2, 0x8380);
                    if (kind == 3) a = a[..^1];
                    if (kind == 4) a[13] = (byte)'z';
                    return Task.FromResult(a);
                }, (_, _) => { local++; return Task.FromResult(Answer(Query)); });
                Check(Code(await service.QueryAsync(Query)) == 2 && local == 0, "failed closed " + kind);
            }
        });
        await Test("NXDOMAIN is a valid answer and never triggers fallback", async () =>
        {
            var remote = 0; var local = 0;
            await using var service = new RemoteDnsService(new() { AllowLocalResolution = true, AllowLocalFallback = true },
                (_, q, _) => { remote++; return Task.FromResult(DnsWire.Error(q, 3)); }, (_, q) => { local++; throw new Exception("unexpected local"); });
            Check(Code(await service.QueryAsync(Query)) == 3 && remote == 1 && local == 0, "NXDOMAIN semantics");
        });
        await Test("local rules and fallback require explicit opt in", async () =>
        {
            var local = 0; var remote = 0;
            await using var service = new RemoteDnsService(new() { AllowLocalResolution = true, AllowLocalFallback = true, LocalDomainRules = ["lan"] },
                (_, _, _) => { remote++; throw new IOException(); }, (q, _) => { local++; return Task.FromResult(Answer(q)); });
            Check(Code(await service.QueryAsync(DnsWire.Query("printer.lan", 1))) == 0 && remote == 0 && local == 1, "local domain");
            Check(Code(await service.QueryAsync(Query)) == 0 && remote == 2 && local == 2, "explicit fallback");
        });
        await Test("timeout is bounded and cancellation does not return NXDOMAIN", async () =>
        {
            await using var service = new RemoteDnsService(new() { QueryTimeoutMs = 1000 }, async (_, q, t) => { await Task.Delay(10000, t); return Answer(q); });
            var watch = Stopwatch.StartNew();
            Check(Code(await service.QueryAsync(Query)) == 2 && watch.ElapsedMilliseconds < 2200, "timeout bounded");
        });
        await Test("stalled primaries leave time for remote backup under the minimum total timeout", async () =>
        {
            foreach (var count in new[] { 2, 4 })
            {
                var attempts = 0; var local = 0;
                var policy = new DnsPolicyConfig { QueryTimeoutMs = 1000, RemoteResolvers = Enumerable.Range(1, count).Select(i => $"https://192.0.2.{i}/dns-query").ToList() };
                await using var service = new RemoteDnsService(policy, async (_, q, token) =>
                {
                    if (++attempts < count) await Task.Delay(10000, token);
                    return Answer(q);
                }, (_, _) => { local++; throw new Exception("unexpected local fallback"); });
                Check(Code(await service.QueryAsync(Query)) == 0 && attempts == count && local == 0, "backup gets its share of the total timeout");
            }
        });
        await Test("remote health probe cannot pass through local rules or local fallback", async () =>
        {
            var local = 0;
            await using var service = new RemoteDnsService(new() { AllowLocalResolution = true, AllowLocalFallback = true, LocalDomainRules = ["example.com"] },
                (_, _, _) => throw new IOException(), (q, _) => { local++; return Task.FromResult(Answer(q)); });
            await Throws<MessageException>(() => service.ProbeAsync());
            Check(local == 0, "probe requires remote resolution");
            Check(Code(await service.QueryAsync(DnsWire.Query("example.com", 1))) == 0 && local == 1, "explicit local rules still apply to normal requests");
        });
        await Test("health probe bypasses cache without flushing it", async () =>
        {
            var calls = 0;
            await using var service = new RemoteDnsService(new(), (_, q, _) => { calls++; return Task.FromResult(Answer(q)); });
            await service.QueryAsync(Query); await service.QueryAsync(Query);
            Check(calls == 1, "cached application request");
            await service.ProbeAsync();
            Check(calls == 2, "probe really reaches remote and preserves cache");
            await service.QueryAsync(Query);
            Check(calls == 2, "probe leaves the application cache intact");
            service.MarkUnavailable();
            Check(!service.Available && Code(await service.QueryAsync(Query)) == 2, "no stale healthy resolver after shutdown");
        });
        await Test("cache TTL expires and core exit invalidates cached and in flight answers", async () =>
        {
            var calls = 0;
            await using var service = new RemoteDnsService(new(), (_, q, _) => { calls++; return Task.FromResult(Answer(q, 1)); });
            await service.QueryAsync(Query);
            var q2 = (byte[])Query.Clone(); DnsWire.Put16(q2, 0, 4321);
            Check(DnsWire.U16(await service.QueryAsync(q2), 0) == 4321 && calls == 1, "cache returns current ID");
            await Task.Delay(1100); await service.QueryAsync(Query); Check(calls == 2, "TTL expiry");
            service.MarkUnavailable(); Check(Code(await service.QueryAsync(Query)) == 2 && calls == 2, "exit invalidates cache");
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            await using var pending = new RemoteDnsService(new(), async (_, q, _) => { entered.SetResult(); await release.Task; return Answer(q); });
            var task = pending.QueryAsync(Query); await entered.Task; pending.MarkUnavailable(); release.SetResult();
            Check(Code(await task) == 2, "in flight response after exit");
        });
        await Test("faulted DNS receive cleanup is idempotent and allows runtime disposal", TestFaultedDnsCleanup);
        if (!_offline)
        {
            await Test("UDP and TCP loopback listener supports both IP families", TestListeners);
            await Test("departed UDP clients cannot stop DNS for other clients", TestUdpClientDeparture);
            await Test("pre-init and repeated Redirector stop preserve Winsock and existing DNS sockets", TestUnstartedRedirectorStop);
            await Test("partial DNS bind failure retains cause and releases every acquired socket", TestBindFailure);
            await Test("repeated DNS disposal and rebind with active TCP clients", TestRebind);
            await Test("SOCKS passes domain names remotely and rejects unavailable proxy", TestSocks);
            await Test("DoH and DoT reject untrusted TLS certificates", TestTls);
        }
        await Test("core configs pin node IP preserve TLS and reserve DNS route", TestConfigs);
        await Test("Windows firewall rule properties validate without installing rules", TestFirewallRuleObjects);
        await Test("real Windows missing firewall rule lookup is treated as absent", TestMissingWindowsRule);
        await Test("firewall recovery tolerates absent rules and preserves unrelated rules and access errors", TestFirewallRuleRecovery);
        if (!_offline) await Test("Xray runtime uses DNS broker and gives DNS transport priority over DIRECT", TestXrayRuntime);
        await Test("strict helper requests and bootstrap fail before connection", async () =>
        {
            Global.Settings.DnsPolicy = new();
            await Throws<MessageException>(() => DnsRuntime.LookupAsync("never-resolve.example"));
            await Throws<MessageException>(() => DnsRuntime.ConnectionAddressAsync("never-resolve.example"));
            await Throws<MessageException>(() => WebUtil.DownloadBytesAsync("https://never-resolve.example"));
        });
        await Test("empty node list persists without resurrecting backup", async () =>
        {
            Global.Settings = new(); Global.Settings.Server.Add(Node("192.0.2.1"));
            await Configuration.SaveAsync(); Global.Settings.Server.Clear(); await Configuration.SaveAsync();
            await Configuration.LoadAsync(); Check(Global.Settings.Server.Count == 0, "empty config restored old nodes");
            Check(!Global.Settings.DnsPolicy.AllowLocalResolution, "strict persisted");
        });
    }

    private static int FreePort()
    {
        if (_offline) return ++_offlinePort; // Synthetic config value; never bind in offline mode.
        var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop(); return port;
    }
    private static async Task TestListeners()
    {
        await using var service = new RemoteDnsService(new(), (_, q, _) => Task.FromResult(Answer(q)));
        var port = FreePort(); service.Listen(port);
        using var timeout = new CancellationTokenSource(5000);
        foreach (var address in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
        {
            using var udp = new UdpClient(address.AddressFamily); udp.Connect(address, port);
            await udp.SendAsync(Query, timeout.Token);
            DnsWire.ValidateResponse(Query, (await udp.ReceiveAsync(timeout.Token)).Buffer);
            using var tcp = new TcpClient(address.AddressFamily); await tcp.ConnectAsync(address, port, timeout.Token);
            var stream = tcp.GetStream(); var prefix = new byte[2]; DnsWire.Put16(prefix, 0, (ushort)Query.Length);
            await stream.WriteAsync(prefix, timeout.Token); await stream.WriteAsync(Query, timeout.Token);
            await stream.ReadExactlyAsync(prefix, timeout.Token); var answer = new byte[DnsWire.U16(prefix, 0)];
            await stream.ReadExactlyAsync(answer, timeout.Token); DnsWire.ValidateResponse(Query, answer);
        }
    }

    private static async Task QueryListener(RemoteDnsService service, int port, ushort expected = 0)
    {
        using var timeout = new CancellationTokenSource(5000);
        foreach (var address in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
        {
            using var udp = new UdpClient(address.AddressFamily);
            await udp.SendAsync(Query, new IPEndPoint(address, port), timeout.Token);
            Check(Code((await udp.ReceiveAsync(timeout.Token)).Buffer) == expected, "UDP response " + address);
            using var tcp = new TcpClient(address.AddressFamily);
            await tcp.ConnectAsync(address, port, timeout.Token);
            var stream = tcp.GetStream(); var prefix = new byte[2]; DnsWire.Put16(prefix, 0, (ushort)Query.Length);
            await stream.WriteAsync(prefix, timeout.Token); await stream.WriteAsync(Query, timeout.Token);
            await stream.ReadExactlyAsync(prefix, timeout.Token);
            var response = new byte[DnsWire.U16(prefix, 0)]; await stream.ReadExactlyAsync(response, timeout.Token);
            Check(Code(response) == expected, "TCP response " + address);
        }
    }

    private static async Task TestUdpClientDeparture()
    {
        const int count = 8;
        foreach (var address in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
        foreach (var enableResetNotifications in new[] { false, true })
        {
            var received = 0; var listenerFailed = false;
            var release = Enumerable.Range(0, count).Select(_ => new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)).ToArray();
            await using var service = new RemoteDnsService(new() { QueryTimeoutMs = 10000 }, async (_, q, token) =>
            {
                var index = Interlocked.Increment(ref received) - 1;
                if (index < count) await release[index].Task.WaitAsync(token);
                return Answer(q);
            });
            service.ListenerFailed += _ => listenerFailed = true;
            var port = FreePort(); service.Listen(port);
            if (enableResetNotifications)
            {
                // Exercise the defensive receive path even after production turns
                // off Windows' optional ICMP-to-WSAECONNRESET notifications.
                var sockets = (List<UdpClient>)typeof(RemoteDnsService).GetField("_udp", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(service)!;
                sockets.Single(s => s.Client.AddressFamily == address.AddressFamily).Client.IOControl(unchecked((int)0x9800000C), BitConverter.GetBytes(1), null);
            }
            var clients = new List<UdpClient>();
            try
            {
                for (var i = 0; i < count; i++)
                {
                    var client = new UdpClient(address.AddressFamily); clients.Add(client);
                    await client.SendAsync(DnsWire.Query("departed-" + i + ".test", 1), new IPEndPoint(address, port));
                }
                using var wait = new CancellationTokenSource(5000);
                while (Volatile.Read(ref received) < count) await Task.Delay(10, wait.Token);
                foreach (var client in clients) client.Dispose();
                // Queue several ICMP errors without intervening successful receives,
                // reproducing the user's consecutive 10054 notifications.
                for (var i = 0; i < count; i++) { release[i].SetResult(); await Task.Delay(100); }
                Check(!listenerFailed && service.Available, $"departed peers must not stop {address} listener; notifications={enableResetNotifications}");
                await QueryListener(service, port);
                service.MarkUnavailable();
                await QueryListener(service, port, 2);
                Console.WriteLine($"PASS departed-client burst {address}, notifications={enableResetNotifications}, healthy peers and fail-closed stop");
            }
            finally { foreach (var client in clients) client.Dispose(); foreach (var item in release) item.TrySetResult(); }
        }
    }

    private static async Task TestUnstartedRedirectorStop()
    {
        await using var service = new RemoteDnsService(new(), (_, q, _) => Task.FromResult(Answer(q)));
        var port = FreePort(); service.Listen(port);
        var controller = new Netch.Controllers.NFController();
        for (var i = 0; i < 5; i++)
        {
            await controller.StopAsync();
            await QueryListener(service, port);
        }
        service.MarkUnavailable();
        await controller.StopAsync();
        await QueryListener(service, port, 2);
    }

    private static async Task TestBindFailure()
    {
        foreach (var address in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
        foreach (var tcp in new[] { false, true })
        {
            var port = FreePort();
            using var occupied = new Socket(address.AddressFamily, tcp ? SocketType.Stream : SocketType.Dgram, tcp ? ProtocolType.Tcp : ProtocolType.Udp);
            occupied.ExclusiveAddressUse = true;
            if (address.AddressFamily == AddressFamily.InterNetworkV6) occupied.DualMode = false;
            occupied.Bind(new IPEndPoint(address, port)); if (tcp) occupied.Listen();
            await using var service = new RemoteDnsService(new(), (_, q, _) => Task.FromResult(Answer(q)));
            try { service.Listen(port); throw new Exception("occupied endpoint accepted"); }
            catch (MessageException ex)
            {
                Check(ex.InnerException is SocketException { SocketErrorCode: SocketError.AddressAlreadyInUse or SocketError.AccessDenied }, "native socket error retained");
                Check(ex.Message.Contains((tcp ? "TCP " : "UDP ") + new IPEndPoint(address, port)), "precise failing endpoint");
            }
            occupied.Dispose();
            service.Listen(port);
            await QueryListener(service, port);
        }
    }

    private static async Task TestRebind()
    {
        var port = FreePort();
        for (var i = 0; i < 8; i++)
        {
            await using var service = new RemoteDnsService(new(), (_, q, _) => Task.FromResult(Answer(q)));
            service.Listen(port);
            await QueryListener(service, port);
            using var pending = new TcpClient(); await pending.ConnectAsync(IPAddress.Loopback, port);
            await service.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
            await service.DisposeAsync();
        }
    }

    private static async Task<string> SocksHandshake(Stream stream, CancellationToken token)
    {
        var greeting = new byte[3]; await stream.ReadExactlyAsync(greeting, token); Check(greeting.SequenceEqual(new byte[] { 5, 1, 0 }), "SOCKS greeting");
        await stream.WriteAsync(new byte[] { 5, 0 }, token);
        var head = new byte[4]; await stream.ReadExactlyAsync(head, token);
        var size = head[3] == 1 ? 4 : head[3] == 4 ? 16 : -1;
        if (size < 0) { var length = new byte[1]; await stream.ReadExactlyAsync(length, token); size = length[0]; }
        var host = new byte[size]; await stream.ReadExactlyAsync(host, token);
        var port = new byte[2]; await stream.ReadExactlyAsync(port, token);
        await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 }, token);
        return head[3] == 3 ? Encoding.ASCII.GetString(host) : new IPAddress(host).ToString();
    }
    private static async Task TestSocks()
    {
        foreach (var name in new[] { "nonexistent.invalid", "192.0.2.4", "2001:db8::3" })
        {
            var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            using var timeout = new CancellationTokenSource(5000);
            var server = Task.Run(async () => { using var client = await listener.AcceptTcpClientAsync(timeout.Token); return await SocksHandshake(client.GetStream(), timeout.Token); });
            await using var stream = await SocksConnector.ConnectAsync(((IPEndPoint)listener.LocalEndpoint).Port, name, 443, timeout.Token);
            Check(await server == name, "SOCKS preserves destination"); listener.Stop();
        }
        await Throws<SocketException>(async () => { await using var _ = await SocksConnector.ConnectAsync(FreePort(), "not-local.invalid", 443, CancellationToken.None); });
    }
    private static async Task TestTls()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=untrusted.invalid", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var certificate = new X509Certificate2(generated.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.UserKeySet);
        foreach (var scheme in new[] { "https", "tls" })
        {
            var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            using var timeout = new CancellationTokenSource(5000);
            var server = Task.Run(async () =>
            {
                using var client = await listener.AcceptTcpClientAsync(timeout.Token);
                Check(await SocksHandshake(client.GetStream(), timeout.Token) == "untrusted.invalid", "TLS name resolved remotely");
                using var tls = new SslStream(client.GetStream());
                try { await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate }, timeout.Token); await tls.ReadAsync(new byte[1], timeout.Token); }
                catch (Exception ex) when (ex is IOException or AuthenticationException) { Console.WriteLine("TLS fixture: " + ex.Message); }
            });
            using var transport = new RemoteDnsTransport(((IPEndPoint)listener.LocalEndpoint).Port);
            var rejected = false;
            try { await transport.QueryAsync(new Uri(scheme + "://untrusted.invalid"), Query, timeout.Token); }
            catch (Exception ex) when (ex is AuthenticationException or HttpRequestException) { rejected = true; }
            Check(rejected, "TLS certificate was accepted"); await server; listener.Stop();
        }
    }

    private static VMessServer Node(string address) => new()
    {
        Address = address, Port = 443, Network = "ws", Path = "/", HeaderType = "none",
        StreamSecurity = "tls", Password = "00000000-0000-4000-8000-000000000001", Remarks = "offline-test",
        MuxEnabled = false
    };

    private static async Task TestFaultedDnsCleanup()
    {
        // Reproduce the user's precise state without opening any socket: an earlier
        // receive task has already faulted with Win32 ERROR_OPERATION_ABORTED (995).
        var service = new RemoteDnsService(new(), (_, q, _) => Task.FromResult(Answer(q)));
        var loops = (List<Task>)typeof(RemoteDnsService).GetField("_loops", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(service)!;
        loops.Add(Task.FromException(new SocketException(995)));
        var pending = (System.Collections.Concurrent.ConcurrentDictionary<long, Task>)typeof(RemoteDnsService).GetField("_requests", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(service)!;
        pending[1] = Task.FromException(new IOException("synthetic completed request failure"));
        var field = typeof(DnsRuntime).GetField("<Service>k__BackingField", BindingFlags.Static | BindingFlags.NonPublic)!;
        field.SetValue(null, service);
        await DnsRuntime.DisposeServiceAsync();
        await Task.WhenAll(service.DisposeAsync().AsTask(), service.DisposeAsync().AsTask());
        Check(DnsRuntime.Service == null && !DnsRuntime.TransportReady, "runtime must detach the faulted instance");
        Check(Code(await service.QueryAsync(Query)) == 2, "disposed service must fail closed");
        var cancellation = (CancellationTokenSource)typeof(RemoteDnsService).GetField("_stop", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(service)!;
        await Throws<ObjectDisposedException>(() => { _ = cancellation.Token; return Task.CompletedTask; });

        await using var replacement = new RemoteDnsService(new(), (_, q, _) => Task.FromResult(Answer(q)));
        Check(Code(await replacement.QueryAsync(Query)) == 0, "replacement service can resolve synthetic requests");
        var notified = false;
        replacement.ListenerFailed += _ => notified = true;
        typeof(RemoteDnsService).GetMethod("ReportListenerFailure", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(replacement, new object[] { "UDP", new SocketException(995) });
        Check(notified && !replacement.Available && Code(await replacement.QueryAsync(Query)) == 2, "unexpected listener failure must be visible and fail closed");
    }

    private static async Task TestConfigs()
    {
        Global.Settings = new();
        typeof(DnsRuntime).GetField("<TransportPort>k__BackingField", BindingFlags.Static | BindingFlags.NonPublic)!.SetValue(null, FreePort());
        Global.Settings.Socks5LocalPort = (ushort)FreePort();
        Global.Settings.DnsPolicy.BootstrapMappings["node.test"] = "192.0.2.7";
        var profile = new RoutingProfile { Rules = [new RoutingRule { Domain = ["domain:example.test"], OutboundServerId = RoutingOutbound.Direct }] };
        Global.Settings.RoutingProfiles = [profile]; Global.Settings.ActiveRoutingProfileId = profile.Id;
        var node = Node("node.test");
        var config = await V2rayConfigUtils.GenerateClientConfigAsync(node);
        var outbound = config.outbounds.First(o => o.tag == "proxy");
        Check(outbound.settings.vnext[0].address == "192.0.2.7" && outbound.streamSettings.tlsSettings.serverName == "node.test", "pin IP keep SNI");
        Check(outbound.streamSettings.wsSettings.host == "node.test", "keep WebSocket host");
        Check(config.routing.rules[0].inboundTag.Contains(RemoteDnsService.TransportTag) && config.routing.rules[0].outboundTag == "proxy", "DNS route before direct");
        Check(config.outbounds.Single(o => o.tag == "direct").settings.domainStrategy == "ForceIP", "DIRECT fails closed through broker");
        await CheckCore("xray.exe", "xray-single", config);
        var second = Node("192.0.2.8"); Global.Settings.Server = [node, second];
        var chain = new ProxyChainServer(); chain.ProtoExtra.ChildItems = node.Id + "," + second.Id;
        var chainConfig = await V2rayConfigUtils.GenerateClientConfigAsync(chain);
        Check(chainConfig.outbounds.First(o => o.tag == "proxy").streamSettings.sockopt.dialerProxy != null, "chain order");
        await CheckCore("xray.exe", "xray-chain", chainConfig);
        var group = new PolicyGroupServer(); group.ProtoExtra.ChildItems = node.Id + "," + second.Id;
        var groupConfig = await V2rayConfigUtils.GenerateClientConfigAsync(group);
        Check(groupConfig.routing.rules[0].balancerTag != null && groupConfig.observatory != null, "DNS policy group target");
        await CheckCore("xray.exe", "xray-group", groupConfig);
        await Throws<MessageException>(() => V2rayConfigUtils.GenerateClientConfigAsync(new TUICServer { Address = "192.0.2.1", Port = 443 }));
        await Throws<MessageException>(() => V2rayConfigUtils.GenerateClientConfigAsync(Node("missing.invalid")));
        foreach (var protocol in new[] { EConfigType.TUIC, EConfigType.Anytls })
        {
            Server s = protocol == EConfigType.TUIC ? new TUICServer() : new AnytlsServer();
            s.Address = "node.test"; s.Port = 443; s.StreamSecurity = "tls"; s.Password = "example-only";
            s.Username = "00000000-0000-4000-8000-000000000001"; s.HeaderType = "bbr";
            var c = await SingboxConfigUtils.GenerateClientConfigAsync(s);
            Check(c.outbounds[0].server == "192.0.2.7" && c.outbounds[0].tls.server_name == "node.test", "sing-box SNI");
            await CheckCore("sing-box.exe", "singbox-" + protocol, c);
        }
    }
    private static async Task CheckCore<T>(string executable, string name, T config)
    {
        var directory = Path.Combine(_root, ".build", "regression"); Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, name + ".json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(config, Global.NewCustomJsonSerializerOptions()));
        if (_offline) return; // No proxy/core process is launched in offline mode.
        var info = new ProcessStartInfo(Path.Combine(_root, ".build", "baseline", executable))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = directory };
        foreach (var arg in executable == "xray.exe" ? new[] { "run", "-test", "-c", path } : new[] { "check", "-c", path }) info.ArgumentList.Add(arg);
        using var process = Process.Start(info)!;
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(15000);
        try { await process.WaitForExitAsync(timeout.Token); } catch { process.Kill(); throw; }
        var log = await output + await error; await File.WriteAllTextAsync(Path.Combine(directory, name + ".log"), log);
        Check(process.ExitCode == 0, name + " config check failed: " + log);
    }

    private static Task TestFirewallRuleObjects()
    {
        var method = typeof(DnsProtectionController).GetMethod("AddRule", BindingFlags.Static | BindingFlags.NonPublic)!;
        var addresses = (string)typeof(DnsProtectionController).GetField("RemoteAddresses", BindingFlags.Static | BindingFlags.NonPublic)!.GetRawConstantValue()!;
        var policy = new FakeFirewallPolicy();
        foreach (var protocol in new[] { 6, 17, 256 })
        {
            var name = "Netch.OfflineTest." + protocol;
            var ports = protocol == 256 ? null : "53,853,5353,5355,137";
            method.Invoke(null, new object?[] { policy, name, protocol, ports, addresses, true });
            method.Invoke(null, new object?[] { policy, name, protocol, ports, addresses, true });
            dynamic rule = policy.Rules.Item(name);
            Check((bool)rule.Enabled && (int)rule.Action == 0 && (int)rule.Direction == 2, "firewall properties");
            Check(string.IsNullOrEmpty((string?)rule.ApplicationName) && string.IsNullOrEmpty((string?)rule.ServiceName)
                && (int)rule.Profiles == int.MaxValue, "all programs, services and profiles");
            rule.Enabled = false;
            rule.RemoteAddresses = "192.0.2.0/24";
            method.Invoke(null, new object?[] { policy, name, protocol, ports, addresses, true });
            Check((bool)rule.Enabled && (string)rule.RemoteAddresses == addresses, "reapply owned protection on reconnect");
            rule.ApplicationName = Path.Combine(Environment.SystemDirectory, "notepad.exe");
            rule.ServiceName = "Dnscache";
            try { method.Invoke(null, new object?[] { policy, name, protocol, ports, addresses, true }); throw new Exception("narrowed protection accepted"); }
            catch (TargetInvocationException ex) when (ex.InnerException is MessageException) { }
            Check((string)rule.ServiceName == "Dnscache" && (bool)rule.Enabled, "refusal preserves existing protection");
        }
        Check(policy.Rules.Count == 3, "idempotent rules");
        return Task.CompletedTask;
    }

    private static Task TestMissingWindowsRule()
    {
        // Read-only reproduction of the actual Windows COM exception. No rule is added.
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")!)!;
        var name = "Netch.OfflineTest.Absent." + Guid.NewGuid().ToString("N");
        var method = typeof(DnsProtectionController).GetMethod("FindRule", BindingFlags.Static | BindingFlags.NonPublic)!;
        Check(method.Invoke(null, new object[] { (object)policy.Rules, name }) == null, "missing real COM rule must return null");
        return Task.CompletedTask;
    }

    private static Task TestFirewallRuleRecovery()
    {
        var add = typeof(DnsProtectionController).GetMethod("AddRule", BindingFlags.Static | BindingFlags.NonPublic)!;
        var remove = typeof(DnsProtectionController).GetMethod("RemoveOwnedRule", BindingFlags.Static | BindingFlags.NonPublic)!;
        var find = typeof(DnsProtectionController).GetMethod("FindRule", BindingFlags.Static | BindingFlags.NonPublic)!;
        var policy = new FakeFirewallPolicy();
        const string name = "Netch.OfflineTest.Recovery";
        foreach (var com in new[] { false, true })
        {
            policy.Rules.MissingAsComException = com;
            remove.Invoke(null, new object[] { policy.Rules, name });
            add.Invoke(null, new object?[] { policy, name, 6, "53", "192.0.2.0/24", true });
            Check(policy.Rules.Count == 1, "first rule creation must handle missing rule");
            remove.Invoke(null, new object[] { policy.Rules, name });
            remove.Invoke(null, new object[] { policy.Rules, name });
            Check(policy.Rules.Count == 0, "recovery is idempotent");
        }
        add.Invoke(null, new object?[] { policy, name, 6, "53", "192.0.2.0/24", true });
        dynamic rule = policy.Rules.Item(name); rule.Grouping = "Another application";
        remove.Invoke(null, new object[] { policy.Rules, name });
        Check(policy.Rules.Count == 1, "unrelated rule must be preserved");
        try { add.Invoke(null, new object?[] { policy, name, 6, "53", "192.0.2.0/24", true }); throw new Exception("unrelated rule replaced"); }
        catch (TargetInvocationException ex) when (ex.InnerException is MessageException) { }
        Check(ReferenceEquals((object)rule, policy.Rules.Item(name)), "unrelated rule is never replaced");
        policy.Rules.LookupFailure = new UnauthorizedAccessException("test access denied");
        foreach (var method in new[] { find, remove })
        {
            try { method.Invoke(null, new object[] { policy.Rules, name }); throw new Exception("access error swallowed"); }
            catch (TargetInvocationException ex) when (ex.InnerException is UnauthorizedAccessException) { }
        }
        return Task.CompletedTask;
    }

    private static async Task TestXrayRuntime()
    {
        Global.Settings = new();
        Global.Settings.Socks5LocalPort = (ushort)FreePort();
        typeof(DnsRuntime).GetField("<TransportPort>k__BackingField", BindingFlags.Static | BindingFlags.NonPublic)!.SetValue(null, FreePort());
        var profile = new RoutingProfile { Rules = [new RoutingRule { Network = "tcp,udp", OutboundServerId = RoutingOutbound.Direct }] };
        Global.Settings.RoutingProfiles = [profile]; Global.Settings.ActiveRoutingProfileId = profile.Id;
        var config = await V2rayConfigUtils.GenerateClientConfigAsync(Node("192.0.2.7"));
        var queries = 0;
        await using var broker = new RemoteDnsService(new(), (_, q, _) =>
        {
            Interlocked.Increment(ref queries);
            if (DnsWire.ParseQuestion(q).Name == "ok.invalid" && DnsWire.ParseQuestion(q).Type == 1)
            {
                var a = Answer(q); new byte[] { 127, 0, 0, 1 }.CopyTo(a, a.Length - 4); return Task.FromResult(a);
            }
            return Task.FromResult(DnsWire.Error(q, 3));
        });
        var brokerPort = FreePort(); broker.Listen(brokerPort);
        config.dns = new { servers = new[] { $"tcp+local://127.0.0.1:{brokerPort}" }, disableCache = true };
        config.log.loglevel = "debug";
        var proxy = new TcpListener(IPAddress.Loopback, 0); proxy.Start();
        var echo = new TcpListener(IPAddress.Loopback, 0); echo.Start();
        var outbound = config.outbounds.Single(o => o.tag == "proxy");
        outbound.protocol = "socks"; outbound.streamSettings = null; outbound.mux = null;
        outbound.settings = new Outboundsettings4Ray { servers = [new ServersItem4Ray { address = "127.0.0.1", port = ((IPEndPoint)proxy.LocalEndpoint).Port }] };
        var directory = Path.Combine(_root, ".build", "regression");
        var path = Path.Combine(directory, "xray-runtime.json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(config, Global.NewCustomJsonSerializerOptions()));
        var info = new ProcessStartInfo(Path.Combine(_root, ".build", "baseline", "xray.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = directory };
        foreach (var argument in new[] { "run", "-c", path }) info.ArgumentList.Add(argument);
        using var process = Process.Start(info)!;
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(15000);
        try
        {
            for (var i = 0; ; i++)
            {
                try { using var ready = new TcpClient(); await ready.ConnectAsync(IPAddress.Loopback, DnsRuntime.TransportPort, timeout.Token); break; }
                catch (SocketException) when (i < 50 && !process.HasExited) { await Task.Delay(50, timeout.Token); }
            }
            var viaProxy = Task.Run(async () =>
            {
                using var client = await proxy.AcceptTcpClientAsync(timeout.Token);
                var host = await SocksHandshake(client.GetStream(), timeout.Token);
                var data = new byte[1]; await client.GetStream().ReadExactlyAsync(data, timeout.Token);
                await client.GetStream().WriteAsync(data, timeout.Token); return host;
            });
            await using (var stream = await SocksConnector.ConnectAsync(DnsRuntime.TransportPort, "remote-only.invalid", 443, timeout.Token))
            {
                await stream.WriteAsync(new byte[] { 91 }, timeout.Token);
                var response = new byte[1]; await stream.ReadExactlyAsync(response, timeout.Token);
                Check(response[0] == 91 && await viaProxy == "remote-only.invalid" && queries == 0, "DNS transport must bypass DIRECT");
            }
            var localEcho = Task.Run(async () =>
            {
                using var client = await echo.AcceptTcpClientAsync(timeout.Token); var data = new byte[1];
                await client.GetStream().ReadExactlyAsync(data, timeout.Token); await client.GetStream().WriteAsync(data, timeout.Token);
            });
            await using (var stream = await SocksConnector.ConnectAsync(Global.Settings.Socks5LocalPort, "ok.invalid", ((IPEndPoint)echo.LocalEndpoint).Port, timeout.Token))
            {
                await stream.WriteAsync(new byte[] { 92 }, timeout.Token); var response = new byte[1];
                await stream.ReadExactlyAsync(response, timeout.Token); await localEcho;
                Check(response[0] == 92 && queries > 0, "DIRECT resolves through broker");
            }
            var failedClosed = false;
            try
            {
                await using var stream = await SocksConnector.ConnectAsync(Global.Settings.Socks5LocalPort, "nx.invalid", ((IPEndPoint)echo.LocalEndpoint).Port, timeout.Token);
                await stream.WriteAsync(new byte[] { 93 }, timeout.Token);
                failedClosed = await stream.ReadAsync(new byte[1], timeout.Token) == 0;
            }
            catch (IOException) { failedClosed = true; }
            Check(failedClosed && !echo.Pending(), "failed DNS must not connect");
        }
        finally
        {
            proxy.Stop(); echo.Stop();
            if (!process.HasExited) process.Kill(); await process.WaitForExitAsync();
            await File.WriteAllTextAsync(Path.Combine(directory, "xray-runtime.log"), await output + await error);
        }
    }

    private static void RenderUi()
    {
        Application.SetHighDpiMode(HighDpiMode.DpiUnaware);
        Application.EnableVisualStyles(); i18N.Load("zh-CN");
        Global.Settings = new();
        using var main = new Netch.Forms.MainForm();
        using var settings = new Netch.Forms.SettingForm(main);
        settings.ShowInTaskbar = false; settings.StartPosition = FormStartPosition.Manual;
        settings.Location = new Point(-32000, -32000);
        settings.Show(); Application.DoEvents(); settings.PerformLayout();
        using var bitmap = new Bitmap(settings.Width, settings.Height);
        settings.DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size));
        var directory = Path.Combine(_root, ".build", "regression"); Directory.CreateDirectory(directory);
        bitmap.Save(Path.Combine(directory, "dns-settings.png"));
        settings.Hide();
        Console.WriteLine("Rendered settings without starting the application or changing network settings.");
    }
}

// A memory-only collection: COM FWRule objects are never registered with Windows.
public sealed class FakeFirewallPolicy { public FakeFirewallRules Rules { get; } = new(); }
public sealed class FakeFirewallRules
{
    private readonly Dictionary<string, object> _rules = new();
    public bool MissingAsComException { get; set; }
    public Exception? LookupFailure { get; set; }
    public int Count => _rules.Count;
    public object Item(string name)
    {
        if (LookupFailure != null) throw LookupFailure;
        if (_rules.TryGetValue(name, out var item)) return item;
        if (MissingAsComException) throw new System.Runtime.InteropServices.COMException("Missing", unchecked((int)0x80070002));
        throw new FileNotFoundException("Missing firewall rule");
    }
    public void Add(object value) { dynamic rule = value; _rules.Add((string)rule.Name, value); }
    public void Remove(string name) { if (!_rules.Remove(name)) throw new FileNotFoundException("Missing firewall rule"); }
}
