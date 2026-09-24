using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Netch;
using Netch.Models;
using Netch.Models.Modes.ProcessMode;
using Netch.Models.Modes.TunMode;
using Netch.Servers;
using Netch.Services;
using Netch.Services.Dns;
using Serilog;

internal static class FakeIpRegression
{
    private static void Check(bool value, string text) { if (!value) throw new Exception(text); }
    private static void Reject(Action action) { try { action(); } catch (Exception e) when (e is MessageException or IOException or JsonException) { return; } throw new Exception("Expected fail-closed rejection"); }
    private static string DirectoryFor(string root) { var dir = Path.Combine(root, ".build", "fakeip-tests", Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir); return dir; }
    private static int Port() { var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); var port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop(); return port; }
    private static void RuntimePort(string name, int value) => typeof(DnsRuntime).GetField("<" + name + ">k__BackingField", BindingFlags.Static | BindingFlags.NonPublic)!.SetValue(null, value);
    private static byte[] Answer(byte[] q, uint ttl = 60) => DnsWire.AddressAnswer(q, IPAddress.Parse(DnsWire.ParseQuestion(q).Type == 28 ? "2001:db8::7" : "127.0.0.1"), ttl);
    private static int Code(byte[] a) => DnsWire.U16(a, 2) & 15;

    public static async Task RunAsync(string root, bool listeners, Func<string, Func<Task>, Task> test)
    {
        await test("Fake-IP strict policy, range and mode gates", () =>
        {
            Check(!new DnsPolicyConfig().FakeIpEnabled, "default off");
            foreach (var range in new[] { "192.0.2.0/24", "198.18.0.1/15", "198.18.0.0/25", "198.18.0.0/14" }) Reject(() => FakeIpPool.ParseRange(range));
            _ = FakeIpPool.ParseRange("198.19.255.0/24");
            Reject(() => new DnsPolicyConfig { FakeIpEnabled = true, AllowLocalResolution = true }.Validate());
            Check(FakeIpPool.MatchesDomain("A.例子.测试.", ["*.例子.测试"]) && !FakeIpPool.MatchesDomain("evil-example.test", ["*.example.test"]), "IDN suffix boundary");
            var old = Global.Settings;
            try
            {
                Global.Settings = new(); Global.Settings.DnsPolicy.FakeIpEnabled = true; Global.Settings.TUNTAP.BypassIPs = [];
                Reject(() => FakeIpModePolicy.Validate(null)); Reject(() => FakeIpModePolicy.Validate(new Redirector { Handle = ["browser"] }));
                FakeIpModePolicy.Validate(new Redirector { Handle = [".*"], Bypass = [], FilterTCP = true, FilterUDP = true, FilterIntranet = true });
                FakeIpModePolicy.Validate(new TunMode { Handle = ["0.0.0.0/0"] });
                Reject(() => FakeIpModePolicy.Validate(new TunMode { Bypass = ["198.18.0.0/15"] }));
            }
            finally { Global.Settings = old; }
            return Task.CompletedTask;
        });
        await test("Fake-IP durable non-reuse, expiry, exhaustion, corruption and exclusive owner", () =>
        {
            var dir = DirectoryFor(root); var now = DateTimeOffset.UtcNow; IPAddress first;
            using (var pool = new FakeIpPool(dir, "198.18.0.0/24", now: () => now))
            {
                first = pool.Allocate("EXAMPLE.test.", 1, 2);
                Check(pool.Allocate("example.test", 1, 2).Equals(first), "same name stable within session");
                Check(pool.Restore(first.ToString()) == "example.test", "domain restored");
                var v6 = pool.Allocate("example.test", 28, 2); Check(FakeIpPool.IsFake(v6) && pool.Restore(v6.ToString()) == "example.test", "IPv6 restored");
                Reject(() => { using var second = new FakeIpPool(dir, "198.18.0.0/24"); });
                now = now.AddSeconds(3); Reject(() => pool.Restore(first.ToString()));
                Check(pool.Restore("192.0.2.1") == "192.0.2.1", "real IP preserved");
                Reject(() => pool.Restore("198.19.200.1"));
                for (var i = 0; i < 252; i++) pool.Allocate("n" + i + ".test", 1, 1);
                Reject(() => pool.Allocate("exhausted.test", 1, 1));
            }
            using (var pool = new FakeIpPool(dir, "198.18.0.0/15"))
            { Check(!pool.Allocate("example.test", 1, 2).Equals(first), "restart never reuses old lease"); Reject(() => pool.Restore(first.ToString())); }
            Check(!File.ReadAllText(Path.Combine(dir, "fakeip-cursor.json")).Contains("example"), "cursor stores no hostname history");
            File.WriteAllText(Path.Combine(dir, "fakeip-cursor.json"), "{\"Version\":99,\"Next\":1}");
            Reject(() => { using var pool = new FakeIpPool(dir, "198.18.0.0/15"); });
            return Task.CompletedTask;
        });
        await test("Fake-IP concurrent allocation and bounded live mappings", async () =>
        {
            var now = DateTimeOffset.UtcNow;
            using var pool = new FakeIpPool(DirectoryFor(root), "198.18.0.0/15", 2, () => now);
            var answers = await Task.WhenAll(Enumerable.Range(0, 64).Select(_ => Task.Run(() => pool.Allocate("same.test", 1, 1))));
            Check(answers.Distinct().Count() == 1, "concurrent queries share one lease"); pool.Allocate("other.test", 1, 1);
            Reject(() => pool.Allocate("full.test", 1, 1)); now = now.AddSeconds(2);
            var next = pool.Allocate("new.test", 1, 1); Check(!answers.Contains(next), "expired eviction never reassigns IP"); Reject(() => pool.Restore(answers[0].ToString()));
        });
        await test("Fake-IP remote verification, compatibility, DNSSEC, real core DNS and suspension", async () =>
        {
            using var pool = new FakeIpPool(DirectoryFor(root), "198.18.0.0/15");
            var ready = true; var fail = false; var local = 0;
            await using var service = new RemoteDnsService(new() { FakeIpEnabled = true, FakeIpBypassDomains = ["*.compat.test"] },
                (_, q, _) => fail ? Task.FromException<byte[]>(new IOException()) : Task.FromResult(Answer(q)),
                (_, q) => { local++; throw new Exception("Local resolver called"); }, pool, fakeReady: () => ready);
            var query = DnsWire.Query("normal.test", 1);
            var answer = await service.QueryAsync(query); var fake = DnsWire.Addresses(answer).Single();
            Check(FakeIpPool.IsFake(fake) && pool.Restore(fake.ToString()) == "normal.test", "verified lease");
            Check(!FakeIpPool.IsFake(DnsWire.Addresses(await service.QueryRealAsync(query)).Single()), "core gets real IP");
            Check(!FakeIpPool.IsFake(DnsWire.Addresses(await service.QueryAsync(DnsWire.Query("a.compat.test", 1))).Single()), "compatibility is remote real IP");
            var dnssec = DnsWire.Query("signed.test", 1); DnsWire.Put16(dnssec, 2, 0x110);
            Check(!FakeIpPool.IsFake(DnsWire.Addresses(await service.QueryAsync(dnssec)).Single()), "DNSSEC CD bypass");
            dnssec = DnsWire.Query("do.test", 1).Concat(new byte[] { 0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0 }).ToArray(); DnsWire.Put16(dnssec, 10, 1);
            Check(!FakeIpPool.IsFake(DnsWire.Addresses(await service.QueryAsync(dnssec)).Single()), "DNSSEC DO bypass");
            ready = false; Check(Code(await service.QueryAsync(query)) == 2, "no address before interception ready"); ready = true;
            fail = true; Check(Code(await service.QueryAsync(DnsWire.Query("failed.test", 1))) == 2 && local == 0, "remote failure does not synthesize or resolve locally");
            service.MarkUnavailable(); Check(Code(await service.QueryAsync(query)) == 2, "suspension invalidates cached answers");
        });
        await test("Fake-IP negative, empty, zero TTL, reserved upstream and TUN AAAA answers", async () =>
        {
            using var pool = new FakeIpPool(DirectoryFor(root), "198.18.0.0/15");
            foreach (var kind in new[] { 0, 1, 2, 3, 4 })
            {
                await using var service = new RemoteDnsService(new() { FakeIpEnabled = true }, (_, q, _) => Task.FromResult(kind switch
                { 0 => DnsWire.Error(q, 3), 1 => DnsWire.Error(q, 0), 2 => Answer(q, 0), 3 => DnsWire.AddressAnswer(q, IPAddress.Parse("198.18.1.1"), 60), _ => Answer(q) }), fakeIp: pool, fakeIpv6: false);
                var answer = await service.QueryAsync(DnsWire.Query("n" + kind + ".test", (ushort)(kind == 4 ? 28 : 1)));
                Check(!DnsWire.Addresses(answer).Any(FakeIpPool.IsFake) && Code(answer) == (kind == 0 ? 3 : kind == 3 ? 2 : 0), "answer policy " + kind);
            }
        });
        await test("Fake-IP CNAME compatibility preserves the complete remote answer", async () =>
        {
            using var pool = new FakeIpPool(DirectoryFor(root), "198.18.0.0/15");
            byte[] Response(byte[] query)
            {
                var result = DnsWire.Error(query, 0);
                var target = DnsWire.Query("alias.compat.test", 1)[12..^4];
                var address = new byte[] { 127, 0, 0, 1 };
                var cname = new byte[] { 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, (byte)target.Length }.Concat(target);
                result = result.Concat(cname).Concat(target).Concat(new byte[] { 0, 1, 0, 1, 0, 0, 0, 30, 0, 4 }).Concat(address).ToArray();
                DnsWire.Put16(result, 6, 2); return result;
            }
            await using var service = new RemoteDnsService(new() { FakeIpEnabled = true, FakeIpBypassDomains = ["*.compat.test"] }, (_, q, _) => Task.FromResult(Response(q)), fakeIp: pool);
            var query = DnsWire.Query("source.test", 1); var answer = await service.QueryAsync(query);
            Check(DnsWire.Records(answer).Count(r => r.Type == 5) == 1 && DnsWire.Addresses(answer).Single().Equals(IPAddress.Loopback), "CNAME target compatibility preserved");
        });
        await test("Fake-IP external-interface guard object is scoped and idempotent", () =>
        {
            var method = typeof(DnsProtectionController).GetMethod("AddFakeIpRule", BindingFlags.NonPublic | BindingFlags.Static)!;
            var policy = new FakeFirewallPolicy();
            var names = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Where(n => n.Supports(System.Net.NetworkInformation.NetworkInterfaceComponent.IPv4) && n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback && n.Name != "Netch").Select(n => n.Name).ToArray();
            method.Invoke(null, [policy, names]); method.Invoke(null, [policy, names]);
            Check(policy.Rules.Count == 1, "single guard");
            dynamic rule = policy.Rules.Item(DnsProtectionController.RuleNames.Single(n => n.EndsWith("FakeIP")));
            Check((int)rule.Action == 0 && (int)rule.Direction == 2 && (bool)rule.Enabled, "block outbound");
            Check(((Array)rule.Interfaces).Cast<string>().Order().SequenceEqual(names.Order()), "all real external adapter names");
            return Task.CompletedTask;
        });
        if (!listeners) return;
        await test("Fake-IP SOCKS TCP/UDP, HTTP CONNECT/plain, stale rejection and cancellation", () => GatewayAsync(root));
        foreach (var singbox in new[] { false, true })
        foreach (var sniff in new[] { false, true })
            await test($"Fake-IP {(singbox ? "sing-box" : "Xray")} native domain DIRECT/BLOCK/proxy routing, sniff={sniff}", () => NativeAsync(root, singbox, sniff));
    }

    private static byte[] Address(string host, int port)
    {
        var name = Encoding.ASCII.GetBytes(host);
        var result = IPAddress.TryParse(host, out var ip) ? new[] { (byte)(ip.AddressFamily == AddressFamily.InterNetwork ? 1 : 4) }.Concat(ip.GetAddressBytes()).ToArray() : new byte[] { 3, (byte)name.Length }.Concat(name).ToArray();
        return result.Concat(new byte[] { (byte)(port >> 8), (byte)port }).ToArray();
    }
    private static async Task<(string Host, int Port)> ReadAddressAsync(Stream stream, CancellationToken token)
    {
        async Task<byte> One() { var b = new byte[1]; await stream.ReadExactlyAsync(b, token); return b[0]; }
        var type = await One(); var size = type == 1 ? 4 : type == 4 ? 16 : type == 3 ? await One() : throw new IOException();
        var data = new byte[size + 2]; await stream.ReadExactlyAsync(data, token);
        return (type == 3 ? Encoding.ASCII.GetString(data, 0, size) : new IPAddress(data.AsSpan(0, size)).ToString(), (data[size] << 8) | data[size + 1]);
    }
    private static async Task<(TcpClient Client, byte Code, (string Host, int Port) Bound)> SocksAsync(int port, string host, int destinationPort, byte command, CancellationToken token)
    {
        var client = new TcpClient();
        try
        {
            await client.ConnectAsync(IPAddress.Loopback, port, token); var s = client.GetStream(); await s.WriteAsync(new byte[] { 5, 1, 0 }, token);
            var g = new byte[2]; await s.ReadExactlyAsync(g, token); Check(g.SequenceEqual(new byte[] { 5, 0 }), "SOCKS hello");
            await s.WriteAsync(new byte[] { 5, command, 0 }.Concat(Address(host, destinationPort)).ToArray(), token);
            var h = new byte[3]; await s.ReadExactlyAsync(h, token); var bound = await ReadAddressAsync(s, token); return (client, h[1], bound);
        }
        catch { client.Dispose(); throw; }
    }
    private static async Task<string> HeaderAsync(Stream stream, CancellationToken token)
    {
        var data = new List<byte>(); var b = new byte[1];
        while (data.Count < 32768) { await stream.ReadExactlyAsync(b, token); data.Add(b[0]); if (data.TakeLast(4).SequenceEqual(new byte[] { 13, 10, 13, 10 })) return Encoding.ASCII.GetString(data.ToArray()); }
        throw new IOException();
    }
    private static async Task GatewayAsync(string root)
    {
        var oldLog = Serilog.Log.Logger;
        using var logger = new Serilog.LoggerConfiguration().MinimumLevel.Debug().WriteTo.File(Path.Combine(root, ".build", "fakeip-gateway.log")).CreateLogger();
        Serilog.Log.Logger = logger;
        using var timeout = new CancellationTokenSource(20000); var token = timeout.Token;
        var core = new TcpListener(IPAddress.Loopback, 0); core.Start();
        var now = DateTimeOffset.UtcNow; using var pool = new FakeIpPool(DirectoryFor(root), "198.18.0.0/15", now: () => now);
        await using var gateway = new FakeIpProxy(pool, ((IPEndPoint)core.LocalEndpoint).Port, IPAddress.Loopback, 0, () => true); gateway.Start();
        var fake = pool.Allocate("target.test", 1, 10).ToString(); var fake6 = pool.Allocate("target.test", 28, 10).ToString();
        async Task ServeAsync(bool http = false, bool udp = false)
        {
            using var c = await core.AcceptTcpClientAsync(token); var s = c.GetStream();
            if (http)
            { var h = await HeaderAsync(s, token); Check(h.StartsWith("GET http://target.test:8080/path ") && h.Contains("Host: target.test:8080\r\n"), "plain HTTP restored"); await s.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"), token); return; }
            var g = new byte[3]; await s.ReadExactlyAsync(g, token); await s.WriteAsync(new byte[] { 5, 0 }, token);
            await s.ReadExactlyAsync(g, token); var target = await ReadAddressAsync(s, token);
            if (udp)
            {
                using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
                await s.WriteAsync(new byte[] { 5, 0, 0 }.Concat(Address("127.0.0.1", ((IPEndPoint)socket.Client.LocalEndPoint!).Port)).ToArray(), token);
                var packet = await socket.ReceiveAsync(token); using var input = new MemoryStream(packet.Buffer, 3, packet.Buffer.Length - 3); var decoded = await ReadAddressAsync(input, token);
                Check(decoded.Host == "target.test" && decoded.Port == 443, "UDP restored before core"); await socket.SendAsync(packet.Buffer, packet.RemoteEndPoint, token);
                await s.ReadAsync(new byte[1], token); return;
            }
            Check(target.Host == "target.test" && target.Port == 443, "TCP/CONNECT restored before core"); await s.WriteAsync(new byte[] { 5, 0, 0 }.Concat(Address("127.0.0.1", 1)).ToArray(), token);
            var data = new byte[4]; await s.ReadExactlyAsync(data, token); await s.WriteAsync(data, token);
        }
        try
        {
            foreach (var address in new[] { fake, fake6 })
            {
                var serve = ServeAsync(); var result = await SocksAsync(gateway.Port, address, 443, 1, token);
                using (result.Client) { Check(result.Code == 0, "TCP ready"); await result.Client.GetStream().WriteAsync("PING"u8.ToArray(), token); var data = new byte[4]; await result.Client.GetStream().ReadExactlyAsync(data, token); Check(Encoding.ASCII.GetString(data) == "PING", "TCP echo"); }
                await serve;
            }
            var connectServe = ServeAsync();
            using (var c = new TcpClient()) { await c.ConnectAsync(IPAddress.Loopback, gateway.Port, token); var s = c.GetStream(); await s.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT {fake}:443 HTTP/1.1\r\nHost: {fake}:443\r\n\r\n"), token); Check((await HeaderAsync(s, token)).Contains("200"), "CONNECT response"); await s.WriteAsync("PING"u8.ToArray(), token); await s.ReadExactlyAsync(new byte[4], token); }
            await connectServe;
            var httpServe = ServeAsync(http: true);
            using (var c = new TcpClient()) { await c.ConnectAsync(IPAddress.Loopback, gateway.Port, token); var s = c.GetStream(); await s.WriteAsync(Encoding.ASCII.GetBytes($"GET http://{fake}:8080/path HTTP/1.1\r\nHost: {fake}:8080\r\n\r\n"), token); Check((await HeaderAsync(s, token)).Contains("200"), "HTTP response"); }
            await httpServe;
            foreach (var address in new[] { fake, fake6 })
            {
                var serve = ServeAsync(udp: true); var result = await SocksAsync(gateway.Port, "0.0.0.0", 0, 3, token);
                using (result.Client)
                using (var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
                {
                    var packet = new byte[3].Concat(Address(address, 443)).Concat("PING"u8.ToArray()).ToArray();
                    var fragmented = packet.ToArray(); fragmented[2] = 1;
                    await udp.SendAsync(fragmented, new IPEndPoint(IPAddress.Parse(result.Bound.Host), result.Bound.Port), token);
                    await udp.SendAsync(packet, new IPEndPoint(IPAddress.Parse(result.Bound.Host), result.Bound.Port), token);
                    var response = await udp.ReceiveAsync(token); Check(response.Buffer.SequenceEqual(packet), "UDP reply retains original fake source");
                }
                await serve;
            }
            now = now.AddSeconds(11); var rejected = await SocksAsync(gateway.Port, fake, 443, 1, token); rejected.Client.Dispose(); Check(rejected.Code != 0 && !core.Pending(), "expired address never reaches core");
            rejected = await SocksAsync(gateway.Port, "198.19.255.1", 443, 1, token); rejected.Client.Dispose(); Check(rejected.Code != 0 && !core.Pending(), "unknown address never reaches core");
            await Task.WhenAll(gateway.DisposeAsync().AsTask(), gateway.DisposeAsync().AsTask());
        }
        finally { core.Stop(); Serilog.Log.Logger = oldLog; }
    }

    private static async Task NativeAsync(string root, bool singbox, bool sniff)
    {
        var saved = Global.Settings; var previousDns = DnsRuntime.CoreDnsPort; var previousProxy = DnsRuntime.CoreProxyPort; var previousTransport = DnsRuntime.TransportPort;
        var dir = DirectoryFor(root); using var timeout = new CancellationTokenSource(30000); var token = timeout.Token;
        using var pool = new FakeIpPool(dir, "198.18.0.0/15");
        await using var dns = new RemoteDnsService(new() { FakeIpEnabled = true }, (_, q, _) => Task.FromResult(DnsWire.ParseQuestion(q).Type == 1 ? Answer(q) : DnsWire.Error(q, 3)), fakeIp: pool);
        var broker = Port(); dns.ListenRealOnly(broker);
        var echo = new TcpListener(IPAddress.Loopback, 0); echo.Start(); var outbound = new TcpListener(IPAddress.Loopback, 0); outbound.Start();
        Process? process = null; Task<string>? output = null, error = null;
        try
        {
            Global.Settings = new(); Global.Settings.DnsPolicy.FakeIpEnabled = true; Global.Settings.Socks5LocalPort = (ushort)Port(); Global.Settings.V2RayConfig.CoreBasicItem.SniffingEnabled = sniff;
            RuntimePort("CoreDnsPort", broker); RuntimePort("CoreProxyPort", Port()); RuntimePort("TransportPort", Port());
            var profile = new RoutingProfile { Rules = [new() { Domain = ["full:direct.test"], OutboundServerId = RoutingOutbound.Direct }, new() { Domain = ["domain:blocked.test"], OutboundServerId = RoutingOutbound.Block }] };
            Global.Settings.RoutingProfiles = [profile]; Global.Settings.ActiveRoutingProfileId = profile.Id;
            var server = new SocksServer("127.0.0.1", (ushort)((IPEndPoint)outbound.LocalEndpoint).Port, "");
            object config;
            if (singbox) config = await SingboxConfigUtils.GenerateClientConfigAsync(server);
            else
            {
                var node = new VLESSServer { Address = "127.0.0.1", Port = server.Port, Password = "00000000-0000-4000-8000-000000000009" };
                var xray = await V2rayConfigUtils.GenerateClientConfigAsync(node);
                var proxy = xray.outbounds.Single(o => o.tag == "proxy"); proxy.protocol = "socks"; proxy.streamSettings = null; proxy.mux = null;
                proxy.settings = new Outboundsettings4Ray { servers = [new ServersItem4Ray { address = "127.0.0.1", port = server.Port }] };
                config = xray;
            }
            var path = Path.Combine(dir, "core.json"); await File.WriteAllTextAsync(path, JsonSerializer.Serialize(config, Global.NewCustomJsonSerializerOptions()), token);
            var info = new ProcessStartInfo(BundledCoreManager.ResolveExecutable(singbox ? "sing-box.exe" : "xray.exe", Global.NetchDir)) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var arg in new[] { "run", "-c", path }) info.ArgumentList.Add(arg);
            process = Process.Start(info)!; output = process.StandardOutput.ReadToEndAsync(); error = process.StandardError.ReadToEndAsync();
            while (true) { if (process.HasExited) throw new Exception("Native fixture exited: " + await error); try { using var probe = new TcpClient(); await probe.ConnectAsync(IPAddress.Loopback, DnsRuntime.CoreProxyPort, token); break; } catch (SocketException) { await Task.Delay(40, token); } }
            await using var gateway = new FakeIpProxy(pool, DnsRuntime.CoreProxyPort, IPAddress.Loopback, 0, () => true); gateway.Start();
            async Task<string> Fake(string domain) => DnsWire.Addresses(await dns.QueryAsync(DnsWire.Query(domain, 1), token)).Single().ToString();
            var direct = await SocksAsync(gateway.Port, await Fake("direct.test"), ((IPEndPoint)echo.LocalEndpoint).Port, 1, token);
            using (direct.Client)
            {
                Check(direct.Code == 0, "direct request ready"); await direct.Client.GetStream().WriteAsync("PING"u8.ToArray(), token);
                using var accepted = await echo.AcceptTcpClientAsync(token); var data = new byte[4]; await accepted.GetStream().ReadExactlyAsync(data, token); await accepted.GetStream().WriteAsync(data, token); await direct.Client.GetStream().ReadExactlyAsync(data, token);
                Check(!outbound.Pending(), "DIRECT did not use proxy outbound");
            }
            var blocked = await SocksAsync(gateway.Port, await Fake("a.blocked.test"), ((IPEndPoint)echo.LocalEndpoint).Port, 1, token);
            using (blocked.Client)
            {
                if (blocked.Code == 0) { try { await blocked.Client.GetStream().WriteAsync("PING"u8.ToArray(), token); Check(await blocked.Client.GetStream().ReadAsync(new byte[1], token) == 0, "BLOCK closes stream"); } catch (IOException) { } }
                Check(!echo.Pending() && !outbound.Pending(), "BLOCK forwarded no connection");
            }
            async Task ServeProxyAsync()
            {
                using var accepted = await outbound.AcceptTcpClientAsync(token); var s = accepted.GetStream(); var greeting = new byte[3]; await s.ReadExactlyAsync(greeting, token); await s.WriteAsync(new byte[] { 5, 0 }, token); await s.ReadExactlyAsync(greeting, token); var target = await ReadAddressAsync(s, token);
                Check(target.Host == "proxy.test", "proxy core preserved restored domain"); await s.WriteAsync(new byte[] { 5, 0, 0 }.Concat(Address("127.0.0.1", 1)).ToArray(), token); var data = new byte[4]; await s.ReadExactlyAsync(data, token); await s.WriteAsync(data, token);
            }
            var proxyTask = ServeProxyAsync(); var proxied = await SocksAsync(gateway.Port, await Fake("proxy.test"), 443, 1, token);
            using (proxied.Client) { Check(proxied.Code == 0, "proxy request ready"); await proxied.Client.GetStream().WriteAsync("PING"u8.ToArray(), token); await proxied.Client.GetStream().ReadExactlyAsync(new byte[4], token); } await proxyTask;
        }
        finally
        {
            echo.Stop(); outbound.Stop(); if (process != null) { if (!process.HasExited) process.Kill(); await process.WaitForExitAsync(); await File.WriteAllTextAsync(Path.Combine(dir, "core.log"), await output! + await error!); process.Dispose(); }
            Global.Settings = saved; RuntimePort("CoreDnsPort", previousDns); RuntimePort("CoreProxyPort", previousProxy); RuntimePort("TransportPort", previousTransport);
        }
    }
}
