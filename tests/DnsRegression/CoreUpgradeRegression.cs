using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Netch;
using Netch.Models;
using Netch.Services;
using Netch.Servers;

internal static class CoreUpgradeRegression
{
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); }

    public static async Task RunAsync(string root, bool allowProcesses, Func<string, Func<Task>, Task> test)
    {
        Check(BundledCoreManager.IsBundled, "Build regression tests with BundleProxyCores=true");
        var installation = Path.Combine(root, ".build", "core-upgrade", "deployment-" + Guid.NewGuid().ToString("N"));
        var bin = Path.Combine(installation, "bin");
        Directory.CreateDirectory(bin);
        using var manifest = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "Storage", "cores.lock.json")));
        var cores = manifest.RootElement.GetProperty("cores").EnumerateArray().ToArray();
        await test("bundled cores install offline and preserve existing executables and geodata", async () =>
        {
            foreach (var file in new[] { "xray.exe", "sing-box.exe", "geoip.dat", "geosite.dat" })
                await File.WriteAllTextAsync(Path.Combine(bin, file), "legacy sentinel");
            BundledCoreManager.Prepare(installation);
            foreach (var file in new[] { "xray.exe", "sing-box.exe", "geoip.dat", "geosite.dat" })
                Check(await File.ReadAllTextAsync(Path.Combine(bin, file)) == "legacy sentinel", "existing file overwritten: " + file);
            foreach (var core in cores)
            {
                var directory = Path.GetDirectoryName(BundledCoreManager.ResolveExecutable(core.GetProperty("executable").GetString()!, installation))!;
                foreach (var file in core.GetProperty("files").EnumerateArray())
                {
                    using var stream = File.OpenRead(Path.Combine(directory, file.GetProperty("name").GetString()!));
                    Check(Convert.ToHexString(SHA256.HashData(stream)).Equals(file.GetProperty("sha256").GetString(), StringComparison.OrdinalIgnoreCase), "extracted hash mismatch");
                }
            }
        });
        await test("bundled cores reuse valid files and repair damaged files without network", async () =>
        {
            var path = BundledCoreManager.ResolveExecutable("sing-box.exe", installation);
            var timestamp = File.GetLastWriteTimeUtc(path);
            BundledCoreManager.Prepare(installation);
            Check(File.GetLastWriteTimeUtc(path) == timestamp, "unchanged executable was rewritten");
            var dll = Path.Combine(Path.GetDirectoryName(path)!, "libcronet.dll");
            await File.WriteAllTextAsync(dll, "interrupted deployment");
            await File.WriteAllTextAsync(path, "corrupt executable");
            BundledCoreManager.ResolveExecutable("sing-box.exe", installation);
            Check(new FileInfo(dll).Length > 1000000 && new FileInfo(path).Length > 1000000, "damaged files were not repaired");
            File.Delete(dll);
            BundledCoreManager.Prepare(installation);
            Check(File.Exists(dll), "missing dependency was not repaired");
        });
        await test("locked damaged core fails clearly without falling back or leaving pending files", async () =>
        {
            var path = BundledCoreManager.ResolveExecutable("xray.exe", installation);
            await File.WriteAllTextAsync(path, "damaged and locked");
            using (var locked = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                var rejected = false;
                try { BundledCoreManager.ResolveExecutable("xray.exe", installation); }
                catch (MessageException) { rejected = true; }
                Check(rejected, "locked corrupt core accepted or legacy fallback used");
            }
            Check(!Directory.GetFiles(installation, "*.pending", SearchOption.AllDirectories).Any(), "pending extraction left behind");
            BundledCoreManager.ResolveExecutable("xray.exe", installation);
        });
        await test("controllers select bundled versions and retain bin as asset and working directory", async () =>
        {
            var xray = new V2rayController();
            var singbox = new SingboxController();
            try
            {
                Check(xray.Instance.StartInfo.FileName == BundledCoreManager.ResolveExecutable("xray.exe", Global.NetchDir), "controller selected legacy Xray");
                Check(singbox.Instance.StartInfo.FileName == BundledCoreManager.ResolveExecutable("sing-box.exe", Global.NetchDir), "controller selected legacy sing-box");
                Check(xray.Instance.StartInfo.WorkingDirectory == Path.Combine(Global.NetchDir, "bin"), "relative config path changed");
                Check(xray.Instance.StartInfo.Environment["XRAY_LOCATION_ASSET"] == Path.Combine(Global.NetchDir, "bin"), "existing geodata not preserved");
            }
            finally { await xray.StopAsync(); await singbox.StopAsync(); }
        });
        if (allowProcesses) await test("embedded executables report the pinned versions", async () =>
        {
            var reports = new List<string>();
            foreach (var core in cores)
            {
                var executable = core.GetProperty("executable").GetString()!;
                var info = new ProcessStartInfo(BundledCoreManager.ResolveExecutable(executable, installation), "version")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                using var process = Process.Start(info)!;
                var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
                try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)); }
                catch { if (!process.HasExited) process.Kill(); throw; }
                var output = await stdout + await stderr;
                Check(process.ExitCode == 0 && output.Contains(core.GetProperty("version").GetString()!), "embedded executable version mismatch");
                reports.Add(output);
            }
            await File.WriteAllTextAsync(Path.Combine(root, ".build", "core-upgrade", "embedded-versions.log"), string.Join("\n", reports));
        });
    }
}
