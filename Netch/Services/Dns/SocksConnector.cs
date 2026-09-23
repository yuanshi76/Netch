using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Netch.Services.Dns;

public static class SocksConnector
{
    // Only the local SOCKS endpoint is dialled by this process; destination names stay on the wire.
    public static async Task<Stream> ConnectAsync(int socksPort, string host, int port, CancellationToken token)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        NetworkStream? stream = null;
        try
        {
            await socket.ConnectAsync(IPAddress.Loopback, socksPort, token);
            stream = new NetworkStream(socket, true);
            await stream.WriteAsync(new byte[] { 5, 1, 0 }, token);
            var greeting = new byte[2];
            await stream.ReadExactlyAsync(greeting, token);
            if (greeting[0] != 5 || greeting[1] != 0) throw new IOException("DNS proxy authentication failed.");
            using var request = new MemoryStream();
            request.Write([5, 1, 0]);
            if (IPAddress.TryParse(host.Trim('[', ']'), out var ip))
            {
                request.WriteByte(ip.AddressFamily == AddressFamily.InterNetwork ? (byte)1 : (byte)4);
                request.Write(ip.GetAddressBytes());
            }
            else
            {
                var name = Encoding.ASCII.GetBytes(new System.Globalization.IdnMapping().GetAscii(host));
                if (name.Length is 0 or > 255) throw new IOException("Invalid remote DNS hostname.");
                request.WriteByte(3);
                request.WriteByte((byte)name.Length);
                request.Write(name);
            }
            request.Write([(byte)(port >> 8), (byte)port]);
            await stream.WriteAsync(request.ToArray(), token);
            var reply = new byte[4];
            await stream.ReadExactlyAsync(reply, token);
            if (reply[0] != 5 || reply[1] != 0 || reply[2] != 0) throw new IOException("DNS proxy connection failed.");
            var size = reply[3] switch { 1 => 4, 4 => 16, 3 => -1, _ => throw new IOException("Invalid SOCKS reply.") };
            if (size < 0) { var length = new byte[1]; await stream.ReadExactlyAsync(length, token); size = length[0]; }
            await stream.ReadExactlyAsync(new byte[size + 2], token);
            return stream;
        }
        catch { if (stream != null) await stream.DisposeAsync(); else socket.Dispose(); throw; }
    }
}
