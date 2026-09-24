using System.Diagnostics;
using System.Text;
using Microsoft.VisualStudio.Threading;
using Netch.Enums;
using Netch.Models;
using Netch.Services;
using Netch.Utils;

namespace Netch.Controllers;

public abstract class Guard
{
    private CoreLogWriter? _logStreamWriter;
    private readonly SemaphoreSlim _logLock = new(1);
    private Task _outputTask = Task.CompletedTask;
    private bool _started;
    private bool _disposed;

    /// <param name="mainFile">application path relative of Netch\bin</param>
    /// <param name="redirectOutput"></param>
    /// <param name="encoding">application output encode</param>
    protected Guard(string mainFile, bool redirectOutput = true, Encoding? encoding = null)
    {
        RedirectOutput = redirectOutput;

        var fileName = BundledCoreManager.ResolveExecutable(mainFile, Global.NetchDir);

        if (!File.Exists(fileName))
            throw new MessageException(i18N.Translate($"bin\\{mainFile} file not found!"));

        Instance = new Process
        {
            StartInfo =
            {
                FileName = fileName,
                WorkingDirectory = Path.Combine(Global.NetchDir, "bin"),
                CreateNoWindow = true,
                UseShellExecute = !RedirectOutput,
                RedirectStandardOutput = RedirectOutput,
                StandardOutputEncoding = RedirectOutput ? encoding : null,
                RedirectStandardError = RedirectOutput,
                StandardErrorEncoding = RedirectOutput ? encoding : null,
                WindowStyle = ProcessWindowStyle.Hidden
            }
        };
        if (mainFile.Equals("xray.exe", StringComparison.OrdinalIgnoreCase))
            Instance.StartInfo.Environment["XRAY_LOCATION_ASSET"] = Path.Combine(Global.NetchDir, "bin");
    }

    protected string LogPath => Path.Combine(Global.NetchDir, $"logging\\{Name}.log");

    protected virtual IEnumerable<string> StartedKeywords { get; } = new List<string>();

    protected virtual IEnumerable<string> FailedKeywords { get; } = new List<string>();

    public abstract string Name { get; }

    private State State { get; set; } = State.Waiting;

    private bool RedirectOutput { get; }

    public Process Instance { get; }

    protected async Task StartGuardAsync(string argument, ProcessPriorityClass priority = ProcessPriorityClass.Normal)
    {
        State = State.Starting;

        _logStreamWriter = new CoreLogWriter(LogPath);

        Instance.StartInfo.Arguments = argument;
        Instance.Start();
        _started = true;
        Global.Job.AddProcess(Instance);
        Log.Information("Core started: {Core}, PID {Pid}", Name, Instance.Id);
        await _logStreamWriter.WriteLineAsync($"=== {DateTimeOffset.Now:O} {Name} PID={Instance.Id} ===");

        if (priority != ProcessPriorityClass.Normal)
            Instance.PriorityClass = priority;

        if (RedirectOutput)
        {
            _outputTask = Task.WhenAll(ReadOutputAsync(Instance.StandardOutput), ReadOutputAsync(Instance.StandardError));

            if (!StartedKeywords.Any())
            {
                // Skip, No started keyword
                State = State.Started;
                return;
            }

            // wait ReadOutput change State
            for (var i = 0; i < 1000; i++)
            {
                await Task.Delay(50);
                if (Instance.HasExited) State = State.Stopped;
                switch (State)
                {
                    case State.Started:
                        OnStarted();
                        return;
                    case State.Stopped:
                        OnStartFailed();
                        throw new MessageException($"{Name} 控制器启动失败");
                }
            }

            throw new MessageException($"{Name} 控制器启动超时");
        }
    }

    private async Task ReadOutputAsync(TextReader reader)
    {
        string? line;
        while ((line = await reader.ReadLineAsync()) != null)
        {
            await _logLock.WaitAsync();
            try { if (_logStreamWriter != null) await _logStreamWriter.WriteLineAsync(line); }
            finally { _logLock.Release(); }
            OnReadNewLine(line);

            if (State == State.Starting)
            {
                if (StartedKeywords.Any(s => line.Contains(s)))
                    State = State.Started;
                else if (FailedKeywords.Any(s => line.Contains(s)))
                {
                    OnStartFailed();
                    State = State.Stopped;
                }
            }
        }
    }

    public virtual Task StopAsync()
    {
        return StopGuardAsync();
    }

    protected async Task StopGuardAsync()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            if (_started && !Instance.HasExited)
            {
                Instance.Kill();
                await Instance.WaitForExitAsync();
            }
        }
        catch (Exception e)
        {
            Log.Error(e, "Stop {Name} failed", Name);
            _disposed = false;
            throw new MessageException($"无法停止 {Name}：{e.Message}");
        }
        finally
        {
            if (_disposed)
            {
                try { await _outputTask.WaitAsync(TimeSpan.FromSeconds(5)); } catch (Exception ex) { Log.Warning(ex, "Core output cleanup failed"); }
                if (_logStreamWriter != null)
                    await _logStreamWriter.DisposeAsync();

                Instance.Dispose();

                State = State.Stopped;
            }
        }
    }

    protected virtual void OnStarted()
    {
    }

    protected virtual void OnReadNewLine(string line)
    {
    }

    protected virtual void OnStartFailed()
    {
        Utils.Utils.Open(LogPath);
    }
}
