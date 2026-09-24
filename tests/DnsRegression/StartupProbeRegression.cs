using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using Netch.Models;
using Netch.Services.Dns;

internal static class StartupProbeRegression
{
    private static void Check(bool value, string message)
    {
        if (!value) throw new Exception(message);
    }

    private static Exception Reset() => new HttpRequestException(HttpRequestError.SecureConnectionError,
        "TLS handshake interrupted", new IOException("Transport read failed", new SocketException(10054)));

    private static byte[] Answer(byte[] query)
    {
        var result = DnsWire.Error(query, 0).Concat(new byte[]
        {
            0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7
        }).ToArray();
        DnsWire.Put16(result, 6, 1);
        return result;
    }

    private static async Task<string> FailureAsync(RemoteDnsService service)
    {
        try { await service.ProbeAsync(); }
        catch (MessageException ex) { return ex.Message; }
        throw new Exception("Expected startup probe failure");
    }

    public static async Task RunAsync(Func<string, Func<Task>, Task> test)
    {
        await test("startup retries nested TLS connection resets through remote resolvers only", async () =>
        {
            var calls = 0; var local = 0;
            var states = new List<string>();
            // Reproduce the actual HttpRequestException -> IOException -> 10054 chain.
            await using var service = new RemoteDnsService(new()
            {
                AllowLocalResolution = true, AllowLocalFallback = true, LocalDomainRules = ["example.com"]
            }, (_, q, _) => ++calls <= 2 ? Task.FromException<byte[]>(Reset()) : Task.FromResult(Answer(q)),
                (q, _) => { local++; return Task.FromResult(Answer(q)); });
            service.StatusChanged += states.Add;
            await service.ProbeAsync();
            Check(calls == 3 && local == 0 && service.Available, "transient startup failure must recover remotely");
            Check(states.Any(s => s.Contains("重试") && s.Contains("10054")), "retry must report nested reset cause");
            Check(!states.Any(s => s.Contains("证书")), "transport reset is not evidence of a certificate error");
        });

        await test("startup retries are bounded and persistent failures remain fail closed", async () =>
        {
            var calls = 0; var local = 0;
            await using var service = new RemoteDnsService(new(), (_, _, _) => { calls++; throw Reset(); },
                (q, _) => { local++; return Task.FromResult(Answer(q)); });
            var watch = Stopwatch.StartNew();
            var message = await FailureAsync(service);
            Check(calls == 6 && local == 0 && !service.Available, "three rounds of two remote resolvers, no local fallback");
            Check(watch.ElapsedMilliseconds < 4000 && message.Contains("10054") && !message.Contains("证书"), "bounded accurate failure");
            Check((DnsWire.U16(await service.QueryAsync(DnsWire.Query("uncached.test", 1)), 2) & 15) == 2,
                "normal requests still fail closed after failed startup");
        });

        await test("startup never retries authentication or invalid remote replies as transient resets", async () =>
        {
            foreach (var error in new Exception[]
            {
                new HttpRequestException(HttpRequestError.SecureConnectionError, "TLS authentication failed",
                    new AuthenticationException("Untrusted certificate")),
                new AuthenticationException("Invalid TLS peer"),
                new InvalidDataException("Mismatched DNS answer"),
                new HttpRequestException("HTTP rejected", null, HttpStatusCode.Forbidden)
            })
            {
                var calls = 0;
                await using var service = new RemoteDnsService(new(), (_, _, _) => { calls++; throw error; });
                await FailureAsync(service);
                Check(calls == 2 && !service.Available, "permanent failure only tries configured alternatives once");
            }
            foreach (var code in new ushort[] { 0, 3 })
            foreach (var failedPrimary in new[] { false, true })
            {
                var calls = 0;
                await using var empty = new RemoteDnsService(new(), (_, q, _) =>
                {
                    if (++calls == 1 && failedPrimary) throw Reset();
                    return Task.FromResult(DnsWire.Error(q, code));
                });
                var message = await FailureAsync(empty);
                Check(calls == (failedPrimary ? 2 : 1) && !empty.Available && message.Contains("有效 IPv4") && !message.Contains("已连接"),
                    "NXDOMAIN or an empty probe response cannot report readiness");
            }
        });

        await test("startup retry cancellation and proxy suspension prevent further attempts", async () =>
        {
            var calls = 0;
            using var cancel = new CancellationTokenSource();
            await using var service = new RemoteDnsService(new(), (_, _, _) => { calls++; throw Reset(); });
            service.StatusChanged += status => { if (status.Contains("重试")) cancel.Cancel(); };
            try { await service.ProbeAsync(cancel.Token); throw new Exception("Cancellation ignored"); }
            catch (OperationCanceledException) when (cancel.IsCancellationRequested) { }
            Check(calls == 2, "cancellation ends retry backoff");

            calls = 0;
            await using var suspended = new RemoteDnsService(new(), (_, _, _) => { calls++; throw Reset(); });
            suspended.StatusChanged += status => { if (status.Contains("重试")) suspended.MarkUnavailable(); };
            await FailureAsync(suspended);
            Check(calls == 2 && !suspended.Available, "core exit must never resurrect DNS during retry");
        });

        await test("startup deadline bounds stalled remote attempts including retry delays", async () =>
        {
            var calls = 0; var local = 0;
            await using var service = new RemoteDnsService(new() { QueryTimeoutMs = 1000 }, async (_, q, token) =>
            {
                calls++; await Task.Delay(10000, token); return Answer(q);
            }, (q, _) => { local++; return Task.FromResult(Answer(q)); });
            var watch = Stopwatch.StartNew();
            var message = await FailureAsync(service);
            Check(calls is >= 3 and <= 6 && local == 0 && !service.Available, "only bounded remote attempts");
            Check(watch.ElapsedMilliseconds < 6000 && message.Contains("超时"), "overall startup deadline includes backoff");
        });
    }
}
