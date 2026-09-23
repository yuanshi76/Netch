using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Netch.Models;

namespace Netch.Services.Dns;

public sealed class RemoteDnsService : IAsyncDisposable
{
    public const int ListenPort = 53;
    public const string TransportTag = "netch-dns-transport";
    private const int SioUdpConnectionReset = unchecked((int)0x9800000C);
    private readonly DnsPolicyConfig _policy;
    private readonly Func<Uri, byte[], CancellationToken, Task<byte[]>> _exchange;
    private readonly Func<byte[], CancellationToken, Task<byte[]>>? _localExchange;
    private volatile bool _suspended;
    private readonly CancellationTokenSource _stop = new();
    private readonly object _disposeGate = new();
    private Task? _disposeTask;
    private readonly SemaphoreSlim _capacity = new(128);
    private readonly List<UdpClient> _udp = [];
    private readonly List<TcpListener> _tcp = [];
    private readonly List<Task> _loops = [];
    private readonly ConcurrentDictionary<long, Task> _requests = new();
    private long _requestId;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();
    private sealed record CacheEntry(byte[] Response, DateTimeOffset Created, uint Lifetime);
    private volatile bool _available = true;
    public event Action<string>? StatusChanged;
    public event Action<string>? ListenerFailed;
    public bool Available => _available;
    public string Status { get; private set; } = "远程 DNS 等待连接";

    public RemoteDnsService(DnsPolicyConfig policy, Func<Uri, byte[], CancellationToken, Task<byte[]>> exchange,
        Func<byte[], CancellationToken, Task<byte[]>>? localExchange = null)
    {
        policy.Validate();
        _policy = policy;
        _exchange = exchange;
        _localExchange = localExchange;
    }

    public void Listen(int port = ListenPort)
    {
        var endpoint = "";
        try
        {
            foreach (var address in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
            {
                endpoint = $"UDP {new IPEndPoint(address, port)}";
                var udp = new UdpClient(address.AddressFamily);
                _udp.Add(udp);
                if (address.AddressFamily == AddressFamily.InterNetworkV6) udp.Client.DualMode = false;
                udp.Client.ExclusiveAddressUse = true;
                // Windows otherwise reports ICMP PORT_UNREACHABLE from a departed
                // query client as WSAECONNRESET on this shared server socket.
                // This changes only ICMP error reporting, not DNS routing/fallback.
                udp.Client.IOControl(SioUdpConnectionReset, new byte[4], null);
                udp.Client.Bind(new IPEndPoint(address, port));
                endpoint = $"TCP {new IPEndPoint(address, port)}";
                var tcp = new TcpListener(address, port);
                _tcp.Add(tcp);
                if (address.AddressFamily == AddressFamily.InterNetworkV6) tcp.Server.DualMode = false;
                tcp.Server.ExclusiveAddressUse = true;
                tcp.Start(128);
            }
            foreach (var udp in _udp) _loops.Add(ReadUdpAsync(udp));
            foreach (var tcp in _tcp) _loops.Add(ReadTcpAsync(tcp));
        }
        catch (Exception error)
        {
            foreach (var udp in _udp) udp.Dispose();
            foreach (var tcp in _tcp) tcp.Stop();
            _udp.Clear();
            _tcp.Clear();
            var reason = error is SocketException socket ? socket.SocketErrorCode switch
            {
                SocketError.AddressAlreadyInUse => $"端口已被占用（{socket.NativeErrorCode}）",
                SocketError.AccessDenied => $"系统拒绝绑定，请检查端口保留或安全软件（{socket.NativeErrorCode}）",
                SocketError.NotInitialized => $"进程网络接口未初始化，请完全退出程序后重启（{socket.NativeErrorCode}）",
                _ => $"{socket.Message}（{socket.SocketErrorCode} / {socket.NativeErrorCode}）"
            } : error.Message;
            throw new MessageException($"DNS 监听失败：{endpoint}。{reason}。未回退到本地 DNS。\n详细信息见 data/startup-error.log。", error);
        }
    }

    public Task<byte[]> QueryAsync(byte[] input, CancellationToken token = default) => QueryCoreAsync(input, token, false);

    private async Task<byte[]> QueryCoreAsync(byte[] input, CancellationToken token, bool remoteProbe)
    {
        byte[] query;
        try { query = DnsWire.NormalizeQuery(input); }
        catch (Exception e) when (e is InvalidDataException or ArgumentException) { return DnsWire.Error(input, 1); }
        if (_suspended || token.IsCancellationRequested) { return DnsWire.Error(query, 2); }
        if (!remoteProbe && _policy.IsLocalDomain(DnsWire.ParseQuestion(query).Name))
            return await QueryLocalAsync(query, token);
        var keyBytes = (byte[])query.Clone();
        keyBytes[0] = keyBytes[1] = 0;
        var key = Convert.ToBase64String(keyBytes);
        if (!remoteProbe && _available && _cache.TryGetValue(key, out var cached))
        {
            var elapsed = (uint)Math.Max(0, (DateTimeOffset.UtcNow - cached.Created).TotalSeconds);
            if (elapsed < cached.Lifetime)
            {
                var result = (byte[])cached.Response.Clone();
                foreach (var record in DnsWire.Records(result).Where(r => r.Type != 41))
                    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(record.TtlOffset, 4), record.Ttl > elapsed ? record.Ttl - elapsed : 0);
                DnsWire.Put16(result, 0, DnsWire.U16(query, 0));
                if (_suspended) { return DnsWire.Error(query, 2); }
                return result;
            }
            _cache.TryRemove(key, out _);
        }
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(token, _stop.Token);
        budget.CancelAfter(_policy.QueryTimeoutMs);
        var started = Stopwatch.GetTimestamp();
        var errors = new List<string>();
        for (var resolverIndex = 0; resolverIndex < _policy.RemoteResolvers.Count; resolverIndex++)
        {
            if (budget.IsCancellationRequested) break;
            var address = _policy.RemoteResolvers[resolverIndex];
            using var attempt = CancellationTokenSource.CreateLinkedTokenSource(budget.Token);
            // Reserve time for every configured remote alternative, even with a short
            // total budget. A stalled primary must not consume the backup's entire turn.
            var remaining = _policy.QueryTimeoutMs - (int)Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            attempt.CancelAfter(Math.Clamp(remaining / (_policy.RemoteResolvers.Count - resolverIndex), 1, 3000));
            try
            {
                var response = await _exchange(new Uri(address), query, attempt.Token);
                if (_suspended || budget.IsCancellationRequested) { return DnsWire.Error(query, 2); }
                DnsWire.ValidateResponse(query, response);
                var code = DnsWire.U16(response, 2) & 15;
                if (code is not (0 or 3)) throw new IOException($"DNS RCODE={code}");
                _available = true;

                SetStatus(_policy.AllowLocalFallback ? "远程 DNS 已连接（已允许本地回退）" : "远程 DNS 已连接（禁止本地回退）");
                var records = DnsWire.Records(response).Where(r => r.Type != 41).ToArray();
                // Cache positive answers only. Negative TTL requires SOA semantics.
                if (!remoteProbe && code == 0 && DnsWire.U16(response, 6) > 0 && records.Length > 0)
                {
                    var ttl = Math.Min(300u, records.Min(r => r.Ttl));
                    if (ttl > 0)
                    {
                        if (_cache.Count >= 2048) _cache.Clear();
                        _cache[key] = new((byte[])response.Clone(), DateTimeOffset.UtcNow, ttl);
                    }
                }
                return response;
            }
            catch (Exception e) when (e is IOException or InvalidDataException or HttpRequestException or OperationCanceledException or System.Security.Authentication.AuthenticationException or SocketException)
            {
                errors.Add(DescribeFailure(e));
                // Startup failures need their real cause; no browsing query or
                // proxy credentials are included in this log entry.
                if (remoteProbe) Log.Warning(e, "Remote DNS startup probe failed for resolver {ResolverIndex}", resolverIndex + 1);
            }
        }
        _available = false;

        _cache.Clear();
        if (!remoteProbe && _policy.AllowLocalResolution && _policy.AllowLocalFallback && !token.IsCancellationRequested)
            return await QueryLocalAsync(query, token);
        SetStatus("远程 DNS 不可用，未回退本地（" + string.Join(" / ", errors.Distinct()) + "）");
        return DnsWire.Error(query, 2);
    }

    private async Task<byte[]> QueryLocalAsync(byte[] query, CancellationToken token)
    {
        if (!_policy.AllowLocalResolution || _localExchange == null) return DnsWire.Error(query, 2);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token, _stop.Token);
        timeout.CancelAfter(_policy.QueryTimeoutMs);
        try
        {
            var answer = await _localExchange(query, timeout.Token);
            if (_suspended || timeout.IsCancellationRequested) { return DnsWire.Error(query, 2); }
            DnsWire.ValidateResponse(query, answer);
            SetStatus("已按你的设置使用本地 DNS 解析");
            return answer;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or SocketException or OperationCanceledException)
        {
            SetStatus("本地 DNS 解析失败");
            return DnsWire.Error(query, 2);
        }
    }

    public async Task ProbeAsync(CancellationToken token = default)
    {
        // Probe the real remote path without deleting useful application cache entries
        // or accepting an explicit local rule/fallback as proof of remote readiness.
        var answer = await QueryCoreAsync(DnsWire.Query("example.com", 1, 0x4e44), token, true);
        if ((DnsWire.U16(answer, 2) & 15) != 0 || DnsWire.Addresses(answer).Length == 0)
            throw new MessageException("远程 DNS 验证失败。" + Status + "。\n请检查节点和远程 DNS 设置；详细信息见 logging/application.log。");
    }

    private static string DescribeFailure(Exception error) => error switch
    {
        OperationCanceledException => "远程查询超时",
        System.Security.Authentication.AuthenticationException => "DNS 加密连接或证书校验失败",
        HttpRequestException { HttpRequestError: HttpRequestError.SecureConnectionError } => "DNS 加密连接或证书校验失败",
        HttpRequestException { StatusCode: { } status } => $"远程 DNS 返回 HTTP {(int)status}",
        SocketException socket => $"代理通道连接失败（{socket.SocketErrorCode}）",
        InvalidDataException => "远程 DNS 应答无效",
        _ => "远程 DNS 连接或应答失败"
    };

    public void ClearCache() => _cache.Clear();
    public void MarkUnavailable() { _suspended = true; _available = false; _cache.Clear(); SetStatus("代理已停止，DNS 保护保持；需要联网请恢复连接或解除保护。"); }
    private void SetStatus(string status)
    {
        if (Status == status) return;
        Status = status;
        try { StatusChanged?.Invoke(status); }
        catch (Exception ex) { Log.Warning(ex, "DNS status notification failed"); }
    }

    private void Dispatch(Func<Task> action)
    {
        var id = Interlocked.Increment(ref _requestId);
        var task = RunAsync();
        _requests[id] = task;
        _ = task.ContinueWith(completed => { _requests.TryRemove(id, out _); }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        async Task RunAsync()
        {
            try { await action(); }
            catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
            finally { _capacity.Release(); }
        }
    }

    private async Task ReadUdpAsync(UdpClient socket)
    {
        try
        {
            var interruptions = 0;
            while (!_stop.IsCancellationRequested)
            {
                UdpReceiveResult request;
                try { request = await socket.ReceiveAsync(_stop.Token); interruptions = 0; }
                catch (SocketException ex) when (!_stop.IsCancellationRequested && ex.SocketErrorCode == SocketError.ConnectionReset)
                {
                    // A client can close before its answer arrives. Such peer errors
                    // must never exhaust the shared listener's failure allowance.
                    // Also tolerate providers that still surface ICMP notifications.
                    await Task.Delay(10, _stop.Token);
                    continue;
                }
                catch (SocketException ex) when (!_stop.IsCancellationRequested && IsTransientReceiveError(ex) && ++interruptions <= 3)
                {
                    // Redirector teardown or a local UDP peer closing can abort a
                    // pending receive without a request to dispose this DNS service.
                    Log.Warning(ex, "DNS UDP receive interrupted; retry {Attempt}", interruptions);
                    await Task.Delay(50, _stop.Token);
                    continue;
                }
                if (!IPAddress.IsLoopback(request.RemoteEndPoint.Address)) continue;
                if (!_capacity.Wait(0))
                {
                    try { await socket.SendAsync(DnsWire.Error(request.Buffer, 2), request.RemoteEndPoint, _stop.Token); }
                    catch (SocketException ex) when (!_stop.IsCancellationRequested && ex.SocketErrorCode == SocketError.ConnectionReset) { }
                    continue;
                }
                Dispatch(async () =>
                {
                    var answer = await QueryAsync(request.Buffer, _stop.Token);
                    var maximum = request.Buffer.Length >= 12 && DnsWire.U16(request.Buffer, 10) > 0 ? 1232 : 512;
                    if (answer.Length > maximum)
                    {
                        answer = DnsWire.Error(request.Buffer, 0);
                        DnsWire.Put16(answer, 2, (ushort)(DnsWire.U16(answer, 2) | 0x0200));
                    }
                    await socket.SendAsync(answer, request.RemoteEndPoint, _stop.Token);
                });
            }
        }
        catch (Exception e) when (_stop.IsCancellationRequested && e is OperationCanceledException or SocketException or ObjectDisposedException) { }
        catch (Exception e) { ReportListenerFailure("UDP", e); }
    }

    private async Task ReadTcpAsync(TcpListener listener)
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(_stop.Token);
                if (!_capacity.Wait(0)) { client.Dispose(); continue; }
                Dispatch(async () =>
                {
                    using (client)
                    using (var idle = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token))
                    {
                        var stream = client.GetStream();
                        var prefix = new byte[2];
                        for (var count = 0; count < 100; count++)
                        {
                            idle.CancelAfter(TimeSpan.FromSeconds(15));
                            await stream.ReadExactlyAsync(prefix, idle.Token);
                            var length = DnsWire.U16(prefix, 0);
                            if (length < 12) return;
                            var query = new byte[length];
                            await stream.ReadExactlyAsync(query, idle.Token);
                            var answer = await QueryAsync(query, idle.Token);
                            DnsWire.Put16(prefix, 0, (ushort)answer.Length);
                            await stream.WriteAsync(prefix, idle.Token);
                            await stream.WriteAsync(answer, idle.Token);
                        }
                    }
                });
            }
        }
        catch (Exception e) when (_stop.IsCancellationRequested && e is OperationCanceledException or SocketException or ObjectDisposedException) { }
        catch (Exception e) { ReportListenerFailure("TCP", e); }
    }

    private static bool IsTransientReceiveError(SocketException error) => error.SocketErrorCode is
        SocketError.OperationAborted or SocketError.Interrupted;

    private void ReportListenerFailure(string protocol, Exception error)
    {
        Log.Error(error, "DNS {Protocol} listener failed", protocol);
        MarkUnavailable();
        var message = $"{protocol} DNS 监听异常，解析已停止且未回退本地。请查看日志并重新连接。";
        SetStatus(message);
        try { ListenerFailed?.Invoke(message); }
        catch (Exception notificationError) { Log.Warning(notificationError, "DNS listener failure notification failed"); }
    }

    public ValueTask DisposeAsync()
    {
        lock (_disposeGate) return new ValueTask(_disposeTask ??= DisposeCoreAsync());
    }

    private async Task DisposeCoreAsync()
    {
        _suspended = true;
        _available = false;
        _cache.Clear();
        try
        {
            try { await _stop.CancelAsync(); }
            catch (Exception ex) { Log.Warning(ex, "DNS cancellation callback failed during cleanup"); }
            foreach (var udp in _udp) udp.Dispose();
            foreach (var tcp in _tcp) tcp.Stop();
            // Observe every old task, including one that faulted BEFORE cancellation.
            // A stale receive failure must not prevent releasing the other resources.
            try { await Task.WhenAll(_loops); }
            catch (Exception ex) { Log.Warning(ex, "Observed prior DNS listener failure during cleanup"); }
            try { await Task.WhenAll(_requests.Values); }
            catch (Exception ex) { Log.Warning(ex, "Observed DNS request failure during cleanup"); }
        }
        finally
        {
            foreach (var udp in _udp) udp.Dispose();
            foreach (var tcp in _tcp) tcp.Stop();
            _stop.Dispose();
            _capacity.Dispose();
        }
    }
}
