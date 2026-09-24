using System.Text;

namespace Netch.Services;

/// <summary>Bounded core history across reconnects, without blocking core output on log failure.</summary>
public sealed class CoreLogWriter : IAsyncDisposable
{
    private readonly string _path;
    private readonly long _limit;
    private readonly int _archives;
    private StreamWriter? _writer;
    private long _bytes;

    public CoreLogWriter(string path, long limit = 8 * 1024 * 1024, int archives = 4)
    {
        if (limit < 1 || archives < 1) throw new ArgumentOutOfRangeException(nameof(limit));
        _path = path; _limit = limit; _archives = archives;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            Rotate(); Open();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { Log.Warning(error, "Core log initialization failed; output will still be drained"); }
    }

    private void Rotate()
    {
        for (var index = _archives - 1; index >= 1; index--)
        {
            var source = _path + "." + index;
            if (File.Exists(source)) File.Move(source, _path + "." + (index + 1), true);
        }
        if (File.Exists(_path)) File.Move(_path, _path + ".1", true);
    }

    private void Open()
    {
        _writer = new StreamWriter(new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, true), new UTF8Encoding(false)) { AutoFlush = true };
        _bytes = new FileInfo(_path).Length;
    }

    // Guard serializes both stdout and stderr through its existing log semaphore.
    public async Task WriteLineAsync(string line)
    {
        if (_writer == null) return;
        try
        {
            if (_bytes >= _limit)
            {
                await _writer.DisposeAsync(); _writer = null;
                Rotate(); Open();
            }
            await _writer!.WriteLineAsync(line);
            _bytes += Encoding.UTF8.GetByteCount(line) + Environment.NewLine.Length;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // Still drain stdout/stderr: a full pipe can otherwise stall the proxy.
            Log.Warning(error, "Core log write failed; draining output without recording until reconnect");
            await DisposeAsync();
        }
    }

    public async ValueTask DisposeAsync()
    {
        var writer = _writer;
        _writer = null;
        if (writer == null) return;
        try { await writer.DisposeAsync(); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { Log.Warning(error, "Core log cleanup failed"); }
    }
}
