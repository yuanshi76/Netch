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
    private readonly FakeIpPool? _fakeIp;
    private readonly bool _fakeIpv6;
    private readonly Func<bool> _fakeReady;
    private readonly Func<Uri, byte[], CancellationToken, Task<byte[]>> _exchange;
    private readonly Func<byte[], CancellationToken, Task<byte[]>>? _localExchange;
    private volatile bool _suspended;
    private readonly CancellationTokenSource _stop = new();
    private readonly object _disposeGate = new();
    private Task? _disposeTask;
    private Task _recoveryMonitor = Task.CompletedTask;
    private bool _monitorStarted;
    private long _failedQueries;
    private long _lastFailureLog = long.MinValue;
    private readonly SemaphoreSlim _capacity = new(128);
    private readonly List<UdpClient> _udp = [];
    private readonly List<TcpListener> _tcp = [];
    private readonly List<Task> _loops = [];
    private readonly ConcurrentDictionary<long, Task> _requests = new();
    private long _requestId;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();
    private sealed record CacheEntry(byte[] Response, DateTimeOffset Created, uint Lifetime);
    private sealed record QueryFailure(string Description, bool Retryable);
    private volatile bool _available = true;
    public event Action<string>? StatusChanged;
    public event Action<string>? ListenerFailed;
    public bool Available => _available;
    public string Status { get; private set; } = "远程 DNS 等待连接";

    public RemoteDnsService(DnsPolicyConfig policy, Func<Uri, byte[], CancellationToken, Task<byte[]>> exchange,
        Func<byte[], CancellationToken, Task<byte[]>>? localExchange = null, FakeIpPool? fakeIp = null, bool fakeIpv6 = true, Func<bool>? fakeReady = null)
    {
        policy.Validate();
        _policy = policy;
        _exchange = exchange;
        _localExchange = localExchange;
        _fakeIp = fakeIp; _fakeIpv6 = fakeIpv6;
        _fakeReady = fakeReady ?? (() => true);
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

    public Task<byte[]> QueryRealAsync(byte[] input, CancellationToken token = default) => QueryCoreAsync(input, token, false);

    public async Task<byte[]> QueryAsync(byte[] input, CancellationToken token = default)
    {
        var response = await QueryRealAsync(input, token);
        if (!_policy.FakeIpEnabled || _fakeIp == null || (DnsWire.U16(response, 2) & 15) != 0) return response;
        if (!_fakeReady()) return DnsWire.Error(input, 2);
        try
        {
            var question = DnsWire.ParseQuestion(input);
            if (DnsWire.Addresses(response).Any(FakeIpPool.IsFake)) throw new InvalidDataException("Remote DNS returned a reserved Fake-IP address");
            if (question.Type is not (1 or 28) || question.Type == 28 && !_fakeIpv6 || DnsWire.RequestsDnssec(input) ||
                FakeIpPool.MatchesDomain(question.Name, _policy.FakeIpBypassDomains)) return response;
            var records = DnsWire.Records(response).ToArray();
            foreach (var record in records.Where(r => r.Type == 5))
            {
                var offset = record.DataOffset;
                if (FakeIpPool.MatchesDomain(DnsWire.ReadName(response, ref offset), _policy.FakeIpBypassDomains)) return response;
            }
            var addresses = DnsWire.Addresses(response).Where(a => question.Type == 1
                ? a.AddressFamily == AddressFamily.InterNetwork : a.AddressFamily == AddressFamily.InterNetworkV6).ToArray();
            if (addresses.Length == 0) return response;
            if (addresses.Any(FakeIpPool.IsFake)) throw new InvalidDataException("Remote DNS returned a reserved Fake-IP address");
            var ttl = Math.Min((uint)_policy.FakeIpTtlSeconds, records.Where(r => r.IsAnswer).Min(r => r.Ttl));
            if (ttl == 0) return response;
            var address = _fakeIp.Allocate(question.Name, question.Type, ttl);
            if (_suspended || !_available || !_fakeReady() || token.IsCancellationRequested) return DnsWire.Error(input, 2);
            return DnsWire.AddressAnswer(input, address, ttl);
        }
        catch (Exception ex) when (ex is MessageException or IOException or InvalidDataException or ObjectDisposedException or ArgumentException)
        {
            SetStatus("Fake-IP 分配失败，未返回虚拟地址：" + ex.Message);
            return DnsWire.Error(input, 2);
        }
    }

    public void ListenRealOnly(int port)
    {
        var listener = new TcpListener(IPAddress.Loopback, port);
        listener.Server.ExclusiveAddressUse = true;
        try { listener.Start(128); _tcp.Add(listener); _loops.Add(ReadTcpAsync(listener, true)); }
        catch { listener.Stop(); throw; }
    }

    private async Task<byte[]> QueryCoreAsync(byte[] input, CancellationToken token, bool remoteProbe,
        List<QueryFailure>? probeFailures = null, bool logProbeFailures = true)
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
                // An empty/negative connectivity probe is not proof of recovery.
                // Normal browsing NXDOMAIN responses remain valid remote answers.
                if (remoteProbe && (code != 0 || DnsWire.Addresses(response).Length == 0)) return response;
                _available = true;
                var recoveredFailures = Interlocked.Exchange(ref _failedQueries, 0);
                if (recoveredFailures > 0) Log.Information("Remote DNS transport recovered after {FailedQueries} failed queries; local fallback unchanged", recoveredFailures);

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
                var failure = DescribeFailure(e);
                errors.Add(failure.Description);
                probeFailures?.Add(failure);
                // Startup failures need their real cause; no browsing query or
                // proxy credentials are included in this log entry.
                if (remoteProbe && logProbeFailures) Log.Warning(e, "Remote DNS startup probe failed for resolver {ResolverIndex}", resolverIndex + 1);
            }
        }
        // An application abandoning its request is not evidence that the shared
        // remote resolver is down. Do not invalidate other applications' cache.
        if (_suspended || token.IsCancellationRequested || _stop.IsCancellationRequested) return DnsWire.Error(query, 2);
        _available = false;
        var failed = Interlocked.Increment(ref _failedQueries);
        var now = Environment.TickCount64;
        var lastLog = Interlocked.Read(ref _lastFailureLog);
        if ((failed == 1 || lastLog == long.MinValue || now - lastLog >= 30000) && Interlocked.CompareExchange(ref _lastFailureLog, now, lastLog) == lastLog)
            Log.Warning("Remote DNS query failed after all remote alternatives: {Reasons}. Consecutive failures: {Count}. Query names and payloads omitted",
                string.Join(" / ", errors.Distinct()), failed);

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
        // A core listening on SOCKS does not imply its upstream tunnel is ready.
        // Retry transient transport failures only, with both round and time limits.
        const int maxRounds = 3;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token, _stop.Token);
        deadline.CancelAfter(Math.Min(15000, _policy.QueryTimeoutMs * maxRounds + 1500));
        for (var round = 1; round <= maxRounds; round++)
        {
            token.ThrowIfCancellationRequested();
            if (_suspended || deadline.IsCancellationRequested) break;
            var failures = new List<QueryFailure>();
            Log.Information("Remote DNS startup probe round {Round}/{MaxRounds}", round, maxRounds);
            var answer = await QueryCoreAsync(DnsWire.Query("example.com", 1), deadline.Token, true, failures);
            token.ThrowIfCancellationRequested();
            if (_suspended || deadline.IsCancellationRequested) break;
            var code = DnsWire.U16(answer, 2) & 15;
            if (code == 0 && DnsWire.Addresses(answer).Length > 0)
            {
                Log.Information("Remote DNS startup probe succeeded on round {Round}", round);
                return;
            }
            if (code is 0 or 3)
            {
                _available = false;
                _cache.Clear();
                SetStatus($"远程 DNS 验证未取得有效 IPv4 地址（RCODE={code}），未回退本地");
                break;
            }
            if (round == maxRounds || failures.Count == 0 || failures.Any(failure => !failure.Retryable)) break;
            SetStatus($"远程 DNS 连接暂不可用，正在重试（{round + 1}/{maxRounds}；{string.Join(" / ", failures.Select(f => f.Description).Distinct())}）；未回退本地");
            if (_suspended) break;
            try { await Task.Delay(round * 500, deadline.Token); }
            catch (OperationCanceledException) when (!token.IsCancellationRequested) { break; }
        }
        token.ThrowIfCancellationRequested();
        if (!_suspended && deadline.IsCancellationRequested)
        {
            _available = false;
            _cache.Clear();
            SetStatus("远程 DNS 启动验证超时，未回退本地");
        }
        throw new MessageException("远程 DNS 验证失败。" + Status + "。\n请检查节点和远程 DNS 设置；详细信息见 logging/application.log。");
    }

    private static T? FindCause<T>(Exception error) where T : Exception
    {
        for (Exception? cause = error; cause != null; cause = cause.InnerException)
            if (cause is T result) return result;
        return null;
    }

    private static QueryFailure DescribeFailure(Exception error)
    {
        // SecureConnectionError means any TLS handshake failure, not necessarily
        // a certificate error. Preserve the nested transport cause (e.g. 10054).
        if (FindCause<System.Security.Authentication.AuthenticationException>(error) != null)
            return new("DNS TLS 认证失败（证书或协议校验未通过）", false);
        if (FindCause<InvalidDataException>(error) != null)
            return new("远程 DNS 应答无效", false);
        if (FindCause<SocketException>(error) is { } socket)
        {
            var retryable = socket.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted
                or SocketError.ConnectionRefused or SocketError.TimedOut or SocketError.NetworkUnreachable
                or SocketError.HostUnreachable or SocketError.NetworkDown or SocketError.TryAgain;
            var reason = socket.SocketErrorCode == SocketError.ConnectionReset
                ? "远程 DNS 通道连接被重置" : $"远程 DNS 通道连接失败：{socket.SocketErrorCode}";
            return new($"{reason}（{socket.NativeErrorCode}）", retryable);
        }
        if (FindCause<OperationCanceledException>(error) != null) return new("远程查询超时", true);
        if (error is HttpRequestException { StatusCode: { } status })
            return new($"远程 DNS 返回 HTTP {(int)status}", (int)status is 429 or 500 or 502 or 503 or 504);
        if (error is HttpRequestException { HttpRequestError: HttpRequestError.SecureConnectionError })
            return new("远程 DNS TLS 握手中断", FindCause<IOException>(error) != null);
        return new("远程 DNS 连接或应答失败", error is IOException
            or HttpRequestException { HttpRequestError: HttpRequestError.ConnectionError or HttpRequestError.ResponseEnded });
    }

    public void ClearCache() => _cache.Clear();
    public void MarkUnavailable() { if (!_suspended) Log.Information("DNS service suspended; successful answers disabled until reconnect"); _suspended = true; _available = false; _cache.Clear(); SetStatus("代理已停止，DNS 保护保持；需要联网请恢复连接或解除保护。"); }

    public void StartRecoveryMonitor(TimeSpan? interval = null)
    {
        lock (_disposeGate)
        {
            if (_monitorStarted || _disposeTask != null || _suspended) return;
            var period = interval ?? TimeSpan.FromSeconds(5);
            if (period <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(interval));
            _monitorStarted = true; _recoveryMonitor = MonitorRecoveryAsync(period);
        }
    }

    private async Task MonitorRecoveryAsync(TimeSpan interval)
    {
        using var timer = new PeriodicTimer(interval);
        try
        {
            while (!_suspended && await timer.WaitForNextTickAsync(_stop.Token))
            {
                if (_suspended) break;
                if (_available) continue;
                // Only check the already-running proxy. Never restart a core, change
                // routes/adapters, or enable local resolution to recover connectivity.
                var answer = await QueryCoreAsync(DnsWire.Query("example.com", 1), _stop.Token, true, logProbeFailures: false);
                if (_suspended) break;
                if ((DnsWire.U16(answer, 2) & 15) != 0 || DnsWire.Addresses(answer).Length == 0)
                {
                    _available = false; _cache.Clear();
                    SetStatus("远程 DNS 恢复检查未通过，仍按当前 DNS 策略处理");
                }
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (Exception error) { Log.Warning(error, "Remote DNS recovery monitor stopped; query handling remains active"); }
    }
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

    private async Task ReadTcpAsync(TcpListener listener, bool realOnly = false)
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
                            var answer = realOnly ? await QueryRealAsync(query, idle.Token) : await QueryAsync(query, idle.Token);
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
            await _recoveryMonitor;
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
