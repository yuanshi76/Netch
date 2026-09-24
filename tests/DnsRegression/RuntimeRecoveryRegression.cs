using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using Netch.Services;
using Netch.Services.Dns;
using Serilog;
using Serilog.Core;
using Serilog.Events;

internal static class RuntimeRecoveryRegression
{
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); }
    private static byte[] Answer(byte[] q) => DnsWire.AddressAnswer(q, IPAddress.Parse("192.0.2.7"), 60);
    private static int Code(byte[] q) => DnsWire.U16(q, 2) & 15;
    private static async Task UntilAsync(Func<bool> predicate)
    {
        var watch = Stopwatch.StartNew();
        while (!predicate()) { Check(watch.ElapsedMilliseconds < 2500, "Recovery timed out"); await Task.Delay(10); }
    }
    private sealed class Sink : ILogEventSink
    {
        public ConcurrentQueue<string> Entries { get; } = new();
        public void Emit(LogEvent logEvent) => Entries.Enqueue(logEvent.RenderMessage());
    }

    public static async Task RunAsync(string root, Func<string, Func<Task>, Task> test)
    {
        await test("NF loopback bypass includes dual-stack mappings and excludes external addresses", () =>
        {
            var rules = NfLoopbackPolicy.BuildRules();
            bool Matches(string text)
            {
                var address = IPAddress.Parse(text); var bytes = address.GetAddressBytes();
                return rules.Any(rule => rule.Length == 83 && BitConverter.ToUInt16(rule, 13) == (bytes.Length == 4 ? 2 : 23) &&
                    bytes.Select((value, index) => (value & rule[63 + index]) == rule[47 + index]).All(v => v));
            }
            foreach (var address in new[] { "127.0.0.1", "127.2.3.4", "::1", "::ffff:127.0.0.1", "::ffff:127.255.255.254" })
                Check(Matches(address), "all loopback representations bypass capture");
            foreach (var address in new[] { "126.255.255.255", "128.0.0.1", "192.168.1.1", "198.18.0.1", "::2", "::ffff:1.1.1.1", "fdfe:dcba:9876::1" })
                Check(!Matches(address), "external and Fake-IP traffic must remain filtered");
            return Task.CompletedTask;
        });
        await test("cancelled application query preserves shared DNS availability and cache", async () =>
        {
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var calls = 0;
            var warm = DnsWire.Query("warm.test", 1);
            await using var service = new RemoteDnsService(new(), async (_, q, token) =>
            {
                Interlocked.Increment(ref calls);
                if (DnsWire.ParseQuestion(q).Name == "cancel.test")
                { entered.SetResult(); await Task.Delay(10000, token); }
                return Answer(q);
            });
            Check(Code(await service.QueryAsync(warm)) == 0, "warm cache");
            using var cancel = new CancellationTokenSource();
            var pending = service.QueryAsync(DnsWire.Query("cancel.test", 1), cancel.Token);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(2)); cancel.Cancel();
            Check(Code(await pending) == 2 && service.Available, "one cancelled client must not mark all DNS unavailable");
            Check(Code(await service.QueryAsync(warm)) == 0 && calls == 2, "other applications keep their cache");
        });
        await test("remote-only background recovery restores DNS without another application query", async () =>
        {
            var healthy = 0; var local = 0; var calls = 0;
            var sink = new Sink(); var oldLog = Log.Logger;
            using var logger = new LoggerConfiguration().WriteTo.Sink(sink).CreateLogger();
            Log.Logger = logger;
            try
            {
                await using var service = new RemoteDnsService(new(), (_, q, _) =>
                {
                    Interlocked.Increment(ref calls);
                    if (Volatile.Read(ref healthy) == 0) throw new IOException("private-domain-secret.test payload-secret");
                    return Task.FromResult(Answer(q));
                }, (q, _) => { Interlocked.Increment(ref local); return Task.FromResult(Answer(q)); });
                Check(Code(await service.QueryAsync(DnsWire.Query("private-domain-secret.test", 1))) == 2 && !service.Available, "strict failure");
                service.StartRecoveryMonitor(TimeSpan.FromMilliseconds(30)); service.StartRecoveryMonitor();
                Volatile.Write(ref healthy, 1);
                await UntilAsync(() => service.Available);
                var recoveredCalls = Volatile.Read(ref calls); await Task.Delay(100);
                Check(local == 0 && calls == recoveredCalls, "no local fallback or periodic queries while healthy");
                Check(sink.Entries.Any(s => s.Contains("after all remote alternatives")) && sink.Entries.Any(s => s.Contains("transport recovered")), "failure and recovery retained");
                Check(!sink.Entries.Any(s => s.Contains("private-domain-secret") || s.Contains("payload-secret")), "runtime DNS log omits names, payloads and arbitrary exception messages");
            }
            finally { Log.Logger = oldLog; }
        });
        await test("background recovery remains fail closed on negative replies and core suspension", async () =>
        {
            var mode = 0; var calls = 0; var local = 0;
            await using var service = new RemoteDnsService(new(), (_, q, _) =>
            {
                Interlocked.Increment(ref calls);
                return Volatile.Read(ref mode) switch
                {
                    1 => Task.FromResult(DnsWire.Error(q, 3)),
                    2 => Task.FromResult(Answer(q)),
                    _ => throw new IOException("network down")
                };
            }, (q, _) => { local++; return Task.FromResult(Answer(q)); });
            await service.QueryAsync(DnsWire.Query("fail.test", 1));
            Volatile.Write(ref mode, 1); service.StartRecoveryMonitor(TimeSpan.FromMilliseconds(20));
            await UntilAsync(() => Volatile.Read(ref calls) >= 5);
            Check(!service.Available && local == 0, "NXDOMAIN probe is not recovery");
            service.MarkUnavailable();
            var stoppedCalls = Volatile.Read(ref calls); Volatile.Write(ref mode, 2);
            await Task.Delay(100);
            Check(!service.Available && calls == stoppedCalls, "explicit core suspension must not resurrect DNS");
            Check(Code(await service.QueryAsync(DnsWire.Query("fail.test", 1))) == 2, "suspended query stays closed");
            await service.DisposeAsync(); await service.DisposeAsync();
        });
        await test("core history survives reconnect with bounded archives and locked logs cannot block output", async () =>
        {
            var directory = Path.Combine(root, ".build", "regression", "log-history-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "Xray.log");
            await using (var first = new CoreLogWriter(path, 100, 2)) { await first.WriteLineAsync("before reconnect"); }
            await using (var second = new CoreLogWriter(path, 100, 2)) { await second.WriteLineAsync("after reconnect"); }
            Check(File.ReadAllText(path + ".1").Contains("before reconnect") && File.ReadAllText(path).Contains("after reconnect"), "both sessions remain");
            await using (var bounded = new CoreLogWriter(path, 8, 2))
                for (var i = 0; i < 8; i++) await bounded.WriteLineAsync("bounded line");
            Check(Directory.GetFiles(directory).Length == 3, "two archives and current only");
            using (var locked = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            await using (var unavailable = new CoreLogWriter(path, 8, 2))
                for (var i = 0; i < 1000; i++) await unavailable.WriteLineAsync("still draining");
            // Fail during rollover after a successful write, not just initialization.
            await using (var writer = new CoreLogWriter(path, 8, 2))
            {
                await writer.WriteLineAsync("rollover next");
                using var locked = new FileStream(path + ".1", FileMode.Open, FileAccess.Read, FileShare.None);
                await writer.WriteLineAsync("rollover failure");
                await writer.WriteLineAsync("draining continues");
            }
        });
    }
}
