using System.Diagnostics;
using Netch.Services.Dns;

// Explicit diagnostic: queries public example.com through a caller-provided
// loopback SOCKS port. No settings, DNS listeners, rules or routes are changed.
internal static class LiveRemotePathProbe
{
    public static async Task RunAsync(int port)
    {
        if (port is < 1024 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        using var transport = new RemoteDnsTransport(port);
        var endpoints = new[] { "https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query" };
        var failures = 0;
        var elapsed = Stopwatch.StartNew();
        // Span the production transport's two-minute connection lifetime.
        for (var round = 0; round < 8; round++)
        {
            foreach (var endpoint in endpoints)
            {
                using var budget = new CancellationTokenSource(5000);
                var query = DnsWire.Query("example.com", 1, (ushort)(1900 + round));
                var watch = Stopwatch.StartNew();
                try
                {
                    var response = await transport.QueryAsync(new Uri(endpoint), query, budget.Token);
                    DnsWire.ValidateResponse(query, response);
                    if ((DnsWire.U16(response, 2) & 15) != 0 || DnsWire.Addresses(response).Length == 0)
                        throw new InvalidDataException("No positive DNS answer");
                    Console.WriteLine($"PASS remote transport round={round + 1} endpoint={new Uri(endpoint).Host} elapsedMs={watch.ElapsedMilliseconds} windowSeconds={elapsed.Elapsed.TotalSeconds:F1}");
                }
                catch (Exception error)
                {
                    failures++;
                    Console.WriteLine($"FAIL remote transport round={round + 1} endpoint={new Uri(endpoint).Host} elapsedMs={watch.ElapsedMilliseconds} type={error.GetType().Name}");
                }
            }
            if (round < 7) await Task.Delay(TimeSpan.FromSeconds(20));
        }
        Console.WriteLine($"RESULT remote transport: {16 - failures}/16 positive answers; no system network changes");
        if (failures != 0) throw new Exception("Remote transport diagnostic had failures; inspect per-round results.");
    }
}
