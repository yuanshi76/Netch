using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Netch.Services.Dns;

// Capture upstreams before redirecting adapters, so compatibility mode cannot recurse.
public sealed class LocalDnsTransport
{
    private readonly IPAddress[] _servers = NetworkInterface.GetAllNetworkInterfaces()
        .Where(n => n.OperationalStatus == OperationalStatus.Up)
        .SelectMany(n => n.GetIPProperties().DnsAddresses)
        .Where(a => !IPAddress.IsLoopback(a)).Distinct().ToArray();

    public async Task<byte[]> QueryAsync(byte[] query, CancellationToken token)
    {
        foreach (var address in _servers)
        {
            using var attempt = CancellationTokenSource.CreateLinkedTokenSource(token);
            attempt.CancelAfter(1500);
            try
            {
                using var udp = new UdpClient(address.AddressFamily);
                udp.Connect(address, 53);
                await udp.SendAsync(query, attempt.Token);
                var response = (await udp.ReceiveAsync(attempt.Token)).Buffer;
                if (response.Length >= 12 && (DnsWire.U16(response, 2) & 0x200) != 0)
                {
                    using var tcp = new TcpClient(address.AddressFamily);
                    await tcp.ConnectAsync(address, 53, attempt.Token);
                    var stream = tcp.GetStream();
                    var prefix = new byte[2];
                    DnsWire.Put16(prefix, 0, (ushort)query.Length);
                    await stream.WriteAsync(prefix, attempt.Token);
                    await stream.WriteAsync(query, attempt.Token);
                    await stream.ReadExactlyAsync(prefix, attempt.Token);
                    response = new byte[DnsWire.U16(prefix, 0)];
                    await stream.ReadExactlyAsync(response, attempt.Token);
                }
                DnsWire.ValidateResponse(query, response);
                if ((DnsWire.U16(response, 2) & 15) is 0 or 3) return response;
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or SocketException or OperationCanceledException) { }
        }
        throw new IOException("本地 DNS 不可用。");
    }
}
