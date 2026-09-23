using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;

namespace Netch.Services.Dns;

public sealed class RemoteDnsTransport : IDisposable
{
    private readonly int _socksPort;
    private readonly HttpClient _http;

    public RemoteDnsTransport(int socksPort)
    {
        _socksPort = socksPort;
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            UseCookies = false,
            SslOptions = new SslClientAuthenticationOptions { CertificateChainPolicy = OfflineCertificatePolicy() },
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectCallback = async (context, token) => await SocksConnector.ConnectAsync(socksPort, context.DnsEndPoint.Host, context.DnsEndPoint.Port, token)
        };
        _http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
    }

    public async Task<byte[]> QueryAsync(Uri endpoint, byte[] query, CancellationToken token)
    {
        if (endpoint.Scheme == "tls")
        {
            await using var stream = await SocksConnector.ConnectAsync(_socksPort, endpoint.IdnHost, endpoint.Port < 0 ? 853 : endpoint.Port, token);
            await using var tls = new SslStream(stream, false);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = endpoint.IdnHost,
                CertificateChainPolicy = OfflineCertificatePolicy(),
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
            }, token);
            var prefix = new byte[2];
            DnsWire.Put16(prefix, 0, (ushort)query.Length);
            await tls.WriteAsync(prefix, token);
            await tls.WriteAsync(query, token);
            await tls.ReadExactlyAsync(prefix, token);
            var result = new byte[DnsWire.U16(prefix, 0)];
            await tls.ReadExactlyAsync(result, token);
            return result;
        }
        if (endpoint.Scheme != "https") throw new InvalidOperationException("Encrypted remote DNS is required.");
        var target = new UriBuilder(endpoint);
        if (target.Path is "" or "/") target.Path = "/dns-query";
        using var request = new HttpRequestMessage(HttpMethod.Post, target.Uri)
        {
            Content = new ByteArrayContent(query),
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentType?.MediaType != "application/dns-message" || response.Content.Headers.ContentLength > 65535)
            throw new InvalidDataException("Invalid DoH response type or length.");
        await using var body = await response.Content.ReadAsStreamAsync(token);
        using var output = new MemoryStream();
        var buffer = new byte[4096];
        int count;
        while ((count = await body.ReadAsync(buffer, token)) != 0)
        {
            if (output.Length + count > 65535) throw new InvalidDataException("Oversized DoH response.");
            output.Write(buffer, 0, count);
        }
        return output.ToArray();
    }

    public void Dispose() => _http.Dispose();

    public static System.Security.Cryptography.X509Certificates.X509ChainPolicy OfflineCertificatePolicy() => new()
    {
        DisableCertificateDownloads = true,
        RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
    };
}
