using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Netch.Models;

namespace Netch.Services.Dns;

/// <summary>Restores verified leases before either proxy core applies its ordinary domain rules.</summary>
public sealed class FakeIpProxy : IAsyncDisposable
{
    private readonly FakeIpPool _pool;
    private readonly int _corePort;
    private readonly Func<bool> _ready;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<long, Task> _workers = new();
    private readonly SemaphoreSlim _capacity = new(256);
    private Task _accept = Task.CompletedTask;
    private long _id;
    private readonly object _disposeGate = new();
    private Task? _dispose;
    public event Action<string>? Failed;
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public FakeIpProxy(FakeIpPool pool, int corePort, IPAddress listenAddress, int port, Func<bool> ready)
    {
        _pool = pool; _corePort = corePort; _ready = ready; _listener = new(listenAddress, port);
        _listener.Server.ExclusiveAddressUse = true;
        if (listenAddress.Equals(IPAddress.IPv6Any)) _listener.Server.DualMode = true;
    }

    public void Start() { _listener.Start(128); _accept = AcceptAsync(); }
    public void Suspend() { _stop.Cancel(); _listener.Stop(); }

    private string Restore(string host)
    {
        if (!_ready() || _stop.IsCancellationRequested) throw new IOException("远程 DNS 尚未就绪，连接已阻止。");
        return _pool.Restore(host);
    }

    private async Task AcceptAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                if (!_capacity.Wait(0)) { client.Dispose(); continue; }
                var id = Interlocked.Increment(ref _id);
                async Task RunClientAsync()
                {
                    try { await HandleAsync(client); }
                    finally { _capacity.Release(); }
                }
                var work = RunClientAsync();
                _workers[id] = work;
                _ = work.ContinueWith(completed => { _workers.TryRemove(id, out var ignored); if (completed.IsFaulted) Log.Error(completed.Exception, "Fake-IP client handler failed"); },
                    CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        catch (Exception ex) when (_stop.IsCancellationRequested && ex is OperationCanceledException or SocketException or ObjectDisposedException) { }
        catch (Exception ex) { Log.Error(ex, "Fake-IP proxy listener failed"); Failed?.Invoke("Fake-IP 连接监听失败，解析已停止。"); }
    }

    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        using (var setup = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token))
        {
            setup.CancelAfter(TimeSpan.FromSeconds(10));
            var stream = client.GetStream();
            byte protocol = 0;
            var established = false;
            try
            {
                protocol = await ReadByteAsync(stream, setup.Token);
                if (protocol != 5)
                {
                    await HandleHttpAsync(client, protocol, setup.Token, () => established = true);
                    return;
                }
                var methodCount = await ReadByteAsync(stream, setup.Token);
                var methods = new byte[methodCount];
                await stream.ReadExactlyAsync(methods, setup.Token);
                if (!methods.Contains((byte)0)) { await stream.WriteAsync(new byte[] { 5, 255 }, setup.Token); return; }
                await stream.WriteAsync(new byte[] { 5, 0 }, setup.Token);
                var header = new byte[3]; await stream.ReadExactlyAsync(header, setup.Token);
                if (header[0] != 5 || header[2] != 0) throw new IOException("Invalid SOCKS request");
                var target = await ReadAddressAsync(stream, setup.Token);
                if (header[1] == 3)
                {
                    _ = Restore("127.0.0.1");
                    established = true;
                    await HandleUdpAsync(client, target, _stop.Token);
                }
                else if (header[1] == 1 && target.Port != 0)
                {
                    using var upstream = await OpenCoreAsync(1, Restore(target.Host), target.Port, setup.Token);
                    await ReplyAsync(stream, 0, (IPEndPoint)upstream.Client.LocalEndPoint!, setup.Token);
                    established = true;
                    await RelayAsync(client, upstream, _stop.Token);
                }
                else await ReplyAsync(stream, 7, new(IPAddress.Loopback, 0), setup.Token);
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException or MessageException or ArgumentException)
            {
                if (!established && !_stop.IsCancellationRequested)
                {
                    try
                    {
                        using var reply = new CancellationTokenSource(1000);
                        if (protocol == 5) await ReplyAsync(stream, 4, new(IPAddress.Loopback, 0), reply.Token);
                        else await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"), reply.Token);
                    }
                    catch (Exception) { }
                }
                // Do not record destination history or HTTP authentication headers.
                Log.Debug("Fake-IP connection closed: {ErrorType}", ex.GetType().Name);
            }
        }
    }

    private async Task HandleHttpAsync(TcpClient client, byte first, CancellationToken setup, Action established)
    {
        using var bytes = new MemoryStream(); bytes.WriteByte(first);
        var stream = client.GetStream(); var tail = (uint)first;
        while (tail != 0x0d0a0d0a)
        {
            if (bytes.Length >= 32768) throw new IOException("HTTP proxy header too large");
            var value = await ReadByteAsync(stream, setup); bytes.WriteByte(value); tail = (tail << 8) | value;
        }
        var lines = Encoding.Latin1.GetString(bytes.ToArray()).Split("\r\n");
        var request = lines[0].Split(' ', 3);
        if (request.Length != 3 || !request[2].StartsWith("HTTP/1.")) throw new IOException("Invalid HTTP proxy request");
        if (request[0].Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate("https://" + request[1], UriKind.Absolute, out var target) || target.UserInfo.Length != 0 || target.AbsolutePath != "/")
                throw new IOException("Invalid CONNECT authority");
            using var upstream = await OpenCoreAsync(1, Restore(target.Host.Trim('[', ']')), target.Port, setup);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), setup);
            established();
            await RelayAsync(client, upstream, _stop.Token);
            return;
        }
        if (!Uri.TryCreate(request[1], UriKind.Absolute, out var uri) || uri.Scheme != "http" || uri.UserInfo.Length != 0)
            throw new IOException("HTTP proxy requires an absolute HTTP URL");
        var host = Restore(uri.Host.Trim('[', ']'));
        var rewritten = new UriBuilder(uri) { Host = host }.Uri;
        var headers = new List<string> { request[0] + " " + rewritten.AbsoluteUri + " " + request[2] };
        foreach (var line in lines.Skip(1).Where(l => l.Length > 0))
        {
            var colon = line.IndexOf(':'); if (colon <= 0) throw new IOException("Invalid HTTP header");
            var name = line[..colon];
            if (name.Equals("Connection", StringComparison.OrdinalIgnoreCase) || name.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase)) continue;
            headers.Add(name.Equals("Host", StringComparison.OrdinalIgnoreCase) ? "Host: " + rewritten.Authority : line);
        }
        // A single request per connection avoids forwarding later pipelined Fake-IP targets unrestored.
        headers.Add("Connection: close"); headers.Add("Proxy-Connection: close");
        using var core = new TcpClient(); await core.ConnectAsync(IPAddress.Loopback, _corePort, setup);
        await core.GetStream().WriteAsync(Encoding.Latin1.GetBytes(string.Join("\r\n", headers) + "\r\n\r\n"), setup);
        established();
        await RelayAsync(client, core, _stop.Token);
    }

    private async Task<TcpClient> OpenCoreAsync(byte command, string host, int port, CancellationToken token)
    {
        var client = new TcpClient();
        try
        {
            await client.ConnectAsync(IPAddress.Loopback, _corePort, token);
            var stream = client.GetStream();
            await stream.WriteAsync(new byte[] { 5, 1, 0 }, token);
            var reply = new byte[2]; await stream.ReadExactlyAsync(reply, token);
            if (reply[0] != 5 || reply[1] != 0) throw new IOException("Core SOCKS greeting failed");
            await stream.WriteAsync(new byte[] { 5, command, 0 }.Concat(EncodeAddress(host, port)).ToArray(), token);
            var header = new byte[3]; await stream.ReadExactlyAsync(header, token);
            if (header[0] != 5 || header[1] != 0 || header[2] != 0) throw new IOException("Core SOCKS request failed");
            // UDP needs the returned endpoint; CONNECT callers only need the stream.
            if (command == 1) _ = await ReadAddressAsync(stream, token);
            return client;
        }
        catch { client.Dispose(); throw; }
    }

    private async Task HandleUdpAsync(TcpClient control, (string Host, int Port) requested, CancellationToken token)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(token);
        var peer = ((IPEndPoint)control.Client.RemoteEndPoint!).Address;
        var local = ((IPEndPoint)control.Client.LocalEndPoint!).Address;
        using var socket = new UdpClient(local.AddressFamily);
        socket.Client.Bind(new IPEndPoint(local, 0));
        socket.Client.IOControl(unchecked((int)0x9800000C), new byte[4], null);
        await ReplyAsync(control.GetStream(), 0, (IPEndPoint)socket.Client.LocalEndPoint!, lifetime.Token);
        var watch = WatchAsync(control.GetStream(), lifetime);
        var flows = new Dictionary<string, UdpFlow>();
        IPEndPoint? sender = requested.Port == 0 ? null : new(peer, requested.Port);
        try
        {
            while (!lifetime.IsCancellationRequested)
            {
                var packet = await socket.ReceiveAsync(lifetime.Token);
                if (!packet.RemoteEndPoint.Address.Equals(peer) || sender != null && !packet.RemoteEndPoint.Equals(sender)) continue;
                var data = packet.Buffer;
                if (data.Length < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0) continue; // No fragmented datagrams.
                try
                {
                    var target = DecodeAddress(data, 3); if (target.Port == 0) continue;
                    var restored = Restore(target.Host);
                    sender ??= packet.RemoteEndPoint;
                    var key = target.Host + ":" + target.Port;
                    if (flows.TryGetValue(key, out var expired) && expired.Expired)
                    { await expired.DisposeAsync(); flows.Remove(key); }
                    if (!flows.TryGetValue(key, out var flow))
                    {
                        foreach (var stale in flows.Where(p => p.Value.Expired).ToArray())
                        { await stale.Value.DisposeAsync(); flows.Remove(stale.Key); }
                        if (flows.Count >= 32) continue;
                        using var setup = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token); setup.CancelAfter(5000);
                        var upstream = await OpenCoreAsync(3, "0.0.0.0", 0, setup.Token);
                        try
                        {
                            var relay = await ReadAddressAsync(upstream.GetStream(), setup.Token);
                            if (!IPAddress.TryParse(relay.Host, out var address) || relay.Port == 0 ||
                                !IPAddress.IsLoopback(address) && !address.Equals(IPAddress.Any)) throw new IOException("Core UDP relay is not loopback");
                            var responseAddress = restored == target.Host ? null : data[3..target.End];
                            flow = new UdpFlow(upstream, new(IPAddress.Loopback, relay.Port), socket, sender, responseAddress, lifetime.Token);
                            flows[key] = flow;
                        }
                        catch { upstream.Dispose(); throw; }
                    }
                    await flow.SendAsync(EncodeAddress(restored, target.Port), data.AsMemory(target.End), lifetime.Token);
                }
                catch (Exception ex) when (ex is IOException or SocketException or MessageException or ArgumentException or OperationCanceledException) { }
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
        finally
        {
            await lifetime.CancelAsync();
            foreach (var flow in flows.Values) await flow.DisposeAsync();
            await watch;
        }
    }

    private sealed class UdpFlow : IAsyncDisposable
    {
        private readonly TcpClient _control;
        private readonly UdpClient _socket = new(AddressFamily.InterNetwork);
        private readonly CancellationTokenSource _stop;
        private readonly Task _read, _watch;
        private long _last = Environment.TickCount64;
        public bool Expired => _stop.IsCancellationRequested || Environment.TickCount64 - _last > 60000;
        public UdpFlow(TcpClient control, IPEndPoint upstream, UdpClient replySocket, IPEndPoint client, byte[]? responseAddress, CancellationToken token)
        {
            _control = control; _stop = CancellationTokenSource.CreateLinkedTokenSource(token); _socket.Connect(upstream);
            _watch = WatchAsync(control.GetStream(), _stop);
            _read = ReadAsync(replySocket, client, responseAddress);
        }
        public async Task SendAsync(byte[] address, ReadOnlyMemory<byte> payload, CancellationToken token)
        {
            _last = Environment.TickCount64;
            var buffer = new byte[3 + address.Length + payload.Length]; address.CopyTo(buffer, 3); payload.CopyTo(buffer.AsMemory(3 + address.Length));
            await _socket.SendAsync(buffer, token);
        }
        private async Task ReadAsync(UdpClient reply, IPEndPoint client, byte[]? responseAddress)
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var packet = (await _socket.ReceiveAsync(_stop.Token)).Buffer;
                    if (packet.Length < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0) continue;
                    var target = DecodeAddress(packet, 3);
                    if (responseAddress != null) packet = new byte[3].Concat(responseAddress).Concat(packet[target.End..]).ToArray();
                    await reply.SendAsync(packet, client, _stop.Token);
                }
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException or ArgumentException) { }
        }
        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync(); _control.Dispose(); _socket.Dispose();
            await Task.WhenAll(_read, _watch); _stop.Dispose();
        }
    }

    private static async Task WatchAsync(Stream stream, CancellationTokenSource stop)
    {
        try { await stream.ReadAsync(new byte[1], stop.Token); }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
        finally { await stop.CancelAsync(); }
    }

    private static async Task RelayAsync(TcpClient first, TcpClient second, CancellationToken stop)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stop);
        async Task CopyAsync(TcpClient source, TcpClient destination)
        {
            try { await source.GetStream().CopyToAsync(destination.GetStream(), lifetime.Token); destination.Client.Shutdown(SocketShutdown.Send); }
            catch { await lifetime.CancelAsync(); throw; }
        }
        await Task.WhenAll(CopyAsync(first, second), CopyAsync(second, first));
    }

    private static async Task<byte> ReadByteAsync(Stream stream, CancellationToken token)
    { var value = new byte[1]; await stream.ReadExactlyAsync(value, token); return value[0]; }

    private static async Task<(string Host, int Port)> ReadAddressAsync(Stream stream, CancellationToken token)
    {
        var type = await ReadByteAsync(stream, token);
        var size = type switch { 1 => 4, 4 => 16, 3 => await ReadByteAsync(stream, token), _ => throw new IOException("Invalid SOCKS address type") };
        if (size == 0) throw new IOException("Empty SOCKS address");
        var bytes = new byte[size + 2]; await stream.ReadExactlyAsync(bytes, token);
        return (type == 3 ? Encoding.ASCII.GetString(bytes, 0, size) : new IPAddress(bytes.AsSpan(0, size)).ToString(), (bytes[size] << 8) | bytes[size + 1]);
    }

    internal static (string Host, int Port, int End) DecodeAddress(byte[] packet, int offset)
    {
        if (offset >= packet.Length) throw new IOException("Truncated SOCKS address");
        var type = packet[offset++];
        var size = type switch { 1 => 4, 4 => 16, 3 when offset < packet.Length => packet[offset++], _ => throw new IOException("Invalid SOCKS address") };
        if (size == 0 || offset + size + 2 > packet.Length) throw new IOException("Truncated SOCKS address");
        var host = type == 3 ? Encoding.ASCII.GetString(packet, offset, size) : new IPAddress(packet.AsSpan(offset, size)).ToString();
        offset += size; return (host, (packet[offset] << 8) | packet[offset + 1], offset + 2);
    }

    internal static byte[] EncodeAddress(string host, int port)
    {
        if (IPAddress.TryParse(host, out var ip))
            return new[] { ip.AddressFamily == AddressFamily.InterNetwork ? (byte)1 : (byte)4 }.Concat(ip.GetAddressBytes()).Concat(new[] { (byte)(port >> 8), (byte)port }).ToArray();
        var name = Encoding.ASCII.GetBytes(new System.Globalization.IdnMapping().GetAscii(host));
        if (name.Length is 0 or > 255) throw new IOException("Invalid SOCKS hostname");
        return new byte[] { 3, (byte)name.Length }.Concat(name).Concat(new[] { (byte)(port >> 8), (byte)port }).ToArray();
    }

    private static Task ReplyAsync(Stream stream, byte code, IPEndPoint endpoint, CancellationToken token) =>
        stream.WriteAsync(new byte[] { 5, code, 0 }.Concat(EncodeAddress(endpoint.Address.ToString(), endpoint.Port)).ToArray(), token).AsTask();

    public ValueTask DisposeAsync()
    {
        lock (_disposeGate) return new ValueTask(_dispose ??= DisposeCoreAsync());
    }

    private async Task DisposeCoreAsync()
    {
        Suspend(); await _accept; await Task.WhenAll(_workers.Values); _capacity.Dispose(); _stop.Dispose();
    }
}
