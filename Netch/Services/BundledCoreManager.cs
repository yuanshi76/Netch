using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Netch.Models;

namespace Netch.Services;

/// <summary>Offline deployment of pinned cores. Never replaces legacy bin executables.</summary>
public static class BundledCoreManager
{
    private const string ResourcePrefix = "Netch.BundledCores.";
    private static readonly object Sync = new();
    private static readonly Lazy<CoreManifest> Manifest = new(ReadManifest);

    public static bool IsBundled
    {
        get
        {
#if BUNDLED_PROXY_CORES
            return true;
#else
            return false;
#endif
        }
    }

    public static void Prepare(string installationDirectory)
    {
        if (!IsBundled) return;
        lock (Sync)
            foreach (var core in Manifest.Value.Cores) EnsureCore(core, installationDirectory);
    }

    public static string ResolveExecutable(string fileName, string installationDirectory)
    {
        if (IsBundled)
        {
            var core = Manifest.Value.Cores.SingleOrDefault(c => c.Executable.Equals(fileName, StringComparison.OrdinalIgnoreCase));
            if (core != null)
            {
                lock (Sync) return EnsureCore(core, installationDirectory);
            }
        }
        return Path.GetFullPath(Path.Combine(installationDirectory, "bin", fileName));
    }

    private static CoreManifest ReadManifest()
    {
        using var stream = OpenResource("manifest.json");
        var manifest = JsonSerializer.Deserialize<CoreManifest>(stream, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (manifest == null || manifest.SchemaVersion != 1 || manifest.Cores.Count != 2)
            throw new InvalidDataException("Invalid bundled core manifest");
        foreach (var core in manifest.Cores)
        {
            ValidateName(core.Id); ValidateName(core.Version); ValidateName(core.Executable);
            if (core.Files.Count == 0 || core.Files.Count(f => f.Name == core.Executable) != 1)
                throw new InvalidDataException("Missing bundled executable");
            foreach (var file in core.Files) ValidateName(file.Name);
        }
        return manifest;
    }

    private static Stream OpenResource(string name) => typeof(BundledCoreManager).Assembly.GetManifestResourceStream(ResourcePrefix + name)
        ?? throw new InvalidDataException("Missing bundled core resource: " + name);

    private static void ValidateName(string name)
    {
        if (string.IsNullOrEmpty(name) || name is "." or ".." || name.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '.' and not '-' and not '_'))
            throw new InvalidDataException("Invalid bundled core filename");
    }

    private static string EnsureCore(CoreDefinition core, string installationDirectory)
    {
        try
        {
            var directory = Path.GetFullPath(installationDirectory);
            // Refuse junctions under the installation when writing with administrator rights.
            foreach (var part in new[] { "bin", "cores", core.Id, core.Version })
            {
                directory = Path.Combine(directory, part);
                RejectReparsePoint(directory);
                Directory.CreateDirectory(directory);
            }
            var missing = core.Files.Where(f => !MatchesFile(Path.Combine(directory, f.Name), f.Sha256)).ToList();
            if (missing.Count > 0)
            {
                using var payload = OpenResource(core.Id + ".zip");
                if (!Convert.ToHexString(SHA256.HashData(payload)).Equals(core.ArchiveSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Bundled archive checksum mismatch");
                payload.Position = 0;
                using var archive = new ZipArchive(payload, ZipArchiveMode.Read);
                // Dependencies and licenses precede the executable in the pinned manifest.
                foreach (var file in missing)
                {
                    var entry = archive.GetEntry(file.Entry) ?? throw new InvalidDataException("Missing archive entry: " + file.Entry);
                    var destination = Path.Combine(directory, file.Name);
                    var pending = destination + "." + Guid.NewGuid().ToString("N") + ".pending";
                    try
                    {
                        using (var input = entry.Open())
                        using (var output = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                            input.CopyTo(output);
                        if (!MatchesFile(pending, file.Sha256)) throw new InvalidDataException("Extracted core checksum mismatch");
                        RejectReparsePoint(destination);
                        File.Move(pending, destination, true);
                    }
                    finally { if (File.Exists(pending)) File.Delete(pending); }
                }
            }
            var executable = Path.Combine(directory, core.Executable);
            Log.Information("Verified bundled core {Core} {Version}: {Path}", core.Id, core.Version, executable);
            return executable;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            throw new MessageException($"无法准备 {core.Id} {core.Version}：{ex.Message}。请检查 bin/cores 的写入权限或安全软件隔离记录。", ex);
        }
    }

    private static bool MatchesFile(string path, string expected)
    {
        RejectReparsePoint(path);
        if (!File.Exists(path)) return false;
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).Equals(expected, StringComparison.OrdinalIgnoreCase);
    }

    private static void RejectReparsePoint(string path)
    {
        if ((File.Exists(path) || Directory.Exists(path)) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Core path is a symbolic link or junction: " + path);
    }

    private sealed class CoreManifest
    {
        public int SchemaVersion { get; set; }
        public List<CoreDefinition> Cores { get; set; } = [];
    }

    private sealed class CoreDefinition
    {
        public string Id { get; set; } = "";
        public string Version { get; set; } = "";
        public string Executable { get; set; } = "";
        public string ArchiveSha256 { get; set; } = "";
        public List<CoreFile> Files { get; set; } = [];
    }

    private sealed class CoreFile
    {
        public string Entry { get; set; } = "";
        public string Name { get; set; } = "";
        public string Sha256 { get; set; } = "";
    }
}
