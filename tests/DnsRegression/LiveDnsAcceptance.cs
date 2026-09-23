using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using Netch.Services.Dns;

internal static class LiveDnsAcceptance
{
    private sealed record Result(string Test, string Outcome, long ElapsedMs, string Detail);
    public static async Task RunAsync(string root, bool connected = true, string fileName = "live-dns.json")
    {
        var results = new List<Result>();
        var nonce = "netch-acceptance-" + Guid.NewGuid().ToString("N");
        var started = DateTimeOffset.Now;
        foreach (var ip in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
        foreach (var tcp in new[] { false, true })
        {
            foreach (var (name, type, expected) in new (string, ushort, int)[]
            {
                ("example.com", 1, 0), ("example.com", 28, 0),
                (nonce + ".invalid", 1, 3), ("cloudflare.com", 65, 0)
            })
            {
                var watch = Stopwatch.StartNew();
                var label = $"loopback-{ip.AddressFamily}-{(tcp ? "TCP" : "UDP")}-type{type}-rcode{(connected ? expected : 2)}";
                try
                {
                    var query = DnsWire.Query(name, type, (ushort)Random.Shared.Next(65536));
                    var response = await ExchangeAsync(ip, tcp, query);
                    DnsWire.ValidateResponse(query, response);
                    var code = DnsWire.U16(response, 2) & 15;
                    var success = code == (connected ? expected : 2) && (!connected || type is not (1 or 28) || expected != 0 || DnsWire.Addresses(response).Length > 0);
                    results.Add(new(label, success ? "PASS" : "FAIL", watch.ElapsedMilliseconds, $"RCODE={code}, answers={DnsWire.U16(response, 6)}"));
                }
                catch (Exception ex) { results.Add(new(label, "FAIL", watch.ElapsedMilliseconds, ex.GetType().Name + ": " + ex.Message)); }
            }
        }

        var destinations = new List<IPAddress> { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("2606:4700:4700::1111") };
        destinations.AddRange(NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up)
            .SelectMany(n => n.GetIPProperties().GatewayAddresses).Select(g => g.Address)
            .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a)));
        foreach (var ip in destinations.Distinct())
        foreach (var port in new[] { 53, 853, 5353, 5355, 137 })
        foreach (var tcp in new[] { false, true })
        {
            var watch = Stopwatch.StartNew();
            var label = $"external-{(ip.ToString().StartsWith("192.168.") ? "LAN" : ip.AddressFamily)}-{(tcp ? "TCP" : "UDP")}-{port}";
            using var deadline = new CancellationTokenSource(1200);
            try
            {
                using var socket = new Socket(ip.AddressFamily, tcp ? SocketType.Stream : SocketType.Dgram, tcp ? ProtocolType.Tcp : ProtocolType.Udp);
                await socket.ConnectAsync(new IPEndPoint(ip, port), deadline.Token);
                if (tcp) results.Add(new(label, "FAIL", watch.ElapsedMilliseconds, "Direct TCP connection established; inspect capture for interception."));
                else
                {
                    await socket.SendAsync(DnsWire.Query(nonce + ".invalid", 1, 54123), SocketFlags.None, deadline.Token);
                    results.Add(new(label, "CAPTURE_REQUIRED", watch.ElapsedMilliseconds, "UDP send accepted by socket; NIC capture determines whether it left the host."));
                }
            }
            catch (SocketException ex)
            {
                results.Add(new(label, ex.SocketErrorCode == SocketError.AccessDenied ? "PASS" : "INCONCLUSIVE", watch.ElapsedMilliseconds, ex.SocketErrorCode.ToString()));
            }
            catch (OperationCanceledException) { results.Add(new(label, "INCONCLUSIVE", watch.ElapsedMilliseconds, "Timed out; this alone does not prove filtering.")); }
        }

        var directory = Path.Combine(root, ".build", "acceptance");
        Directory.CreateDirectory(directory);
        await File.WriteAllTextAsync(Path.Combine(directory, fileName), JsonSerializer.Serialize(new { Started = started, Completed = DateTimeOffset.Now, Connected = connected, Nonce = nonce, Results = results }, new JsonSerializerOptions { WriteIndented = true }));
        foreach (var item in results) Console.WriteLine($"{item.Outcome} {item.Test}: {item.Detail} ({item.ElapsedMs} ms)");
        Console.WriteLine($"Results: {results.Count(r => r.Outcome == "PASS")} PASS, {results.Count(r => r.Outcome == "FAIL")} FAIL, {results.Count(r => r.Outcome is "INCONCLUSIVE" or "CAPTURE_REQUIRED")} require capture/analysis.");
    }

    private static async Task<byte[]> ExchangeAsync(IPAddress ip, bool tcp, byte[] query)
    {
        using var deadline = new CancellationTokenSource(8000);
        if (!tcp)
        {
            using var udp = new UdpClient(ip.AddressFamily);
            udp.Connect(ip, 53);
            await udp.SendAsync(query, deadline.Token);
            return (await udp.ReceiveAsync(deadline.Token)).Buffer;
        }
        using var client = new TcpClient(ip.AddressFamily);
        await client.ConnectAsync(ip, 53, deadline.Token);
        var stream = client.GetStream();
        var prefix = new byte[2];
        DnsWire.Put16(prefix, 0, (ushort)query.Length);
        await stream.WriteAsync(prefix, deadline.Token);
        await stream.WriteAsync(query, deadline.Token);
        await stream.ReadExactlyAsync(prefix, deadline.Token);
        var answer = new byte[DnsWire.U16(prefix, 0)];
        await stream.ReadExactlyAsync(answer, deadline.Token);
        return answer;
    }
}
