using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.VisualStudio.Threading;
using Netch.JsonConverter;
using Netch.Models;

namespace Netch.Utils;

public static class Configuration
{
    /// <summary>
    ///     数据目录
    /// </summary>
    public static string DataDirectoryFullName => Path.Combine(Global.NetchDir, "data");

    public static string FileFullName => Path.Combine(DataDirectoryFullName, FileName);

    private static string BackupFileFullName => Path.Combine(DataDirectoryFullName, BackupFileName);

    private const string FileName = "settings.json";

    private const string BackupFileName = "settings.json.bak";

    private static readonly AsyncReaderWriterLock _lock = new(null);

    private static readonly JsonSerializerOptions JsonSerializerOptions = Global.NewCustomJsonSerializerOptions();

    static Configuration()
    {
        JsonSerializerOptions.PropertyNameCaseInsensitive = true;
        JsonSerializerOptions.Converters.Add(new ServerConverterWithTypeDiscriminator());
        JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    }

    public static async Task LoadAsync()
    {
        try
        {
            if (!File.Exists(FileFullName))
            {
                await SaveAsync();
                return;
            }

            await using var _ = await _lock.ReadLockAsync();

            if (await LoadCoreAsync(FileFullName))
            {
                return;
            }

            Log.Information("Load backup configuration \"{FileName}\"", BackupFileFullName);
            if (await LoadCoreAsync(BackupFileFullName))
                return;

            throw new InvalidDataException($"Failed to load configuration file \"{FileFullName}\" and backup \"{BackupFileFullName}\".");
        }
        catch (Exception e)
        {
            Log.Error(e, "Load configuration failed");
            MessageBox.Show(
                $"Load configuration failed:\n{e.Message}",
                "Netch",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            Environment.Exit(-1);
        }
    }

    private static async ValueTask<bool> LoadCoreAsync(string filename)
    {
        try
        {
            var settings = await TryLoadSettingsAsync(filename);
            if (settings == null)
                return false;

            CheckSetting(settings);
            Global.Settings = settings;
            Log.Information(
                "Configuration loaded from \"{FileName}\": {ServerCount} server(s), {ProfileCount} profile(s), {RoutingProfileCount} routing profile(s)",
                filename,
                settings.Server.Count,
                settings.Profiles.Count,
                settings.RoutingProfiles.Count);
            return true;
        }
        catch (Exception e)
        {
            Log.Error(e, "Load configuration file \"{FileName}\" error ", filename);
            return false;
        }
    }

    private static async Task<Setting?> TryLoadSettingsAsync(string filename)
    {
        await using var fs = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true);
        return await JsonSerializer.DeserializeAsync<Setting>(fs, JsonSerializerOptions);
    }

    private static void CheckSetting(Setting settings)
    {
        settings.Server ??= new();
        settings.RoutingProfiles ??= new();
        settings.Profiles ??= new();
        settings.DnsPolicy ??= new();
        settings.DnsPolicy.LocalDomainRules ??= [];
        settings.DnsPolicy.BootstrapMappings ??= new(StringComparer.OrdinalIgnoreCase);

        foreach (var server in settings.Server.Where(server => server.Id.IsNullOrWhiteSpace()))
        {
            server.Id = Guid.NewGuid().ToString("N");
        }

        if (settings.RoutingProfiles.Count == 0)
        {
            var routingProfile = new RoutingProfile();
            settings.RoutingProfiles.Add(routingProfile);
            settings.ActiveRoutingProfileId = routingProfile.Id;
        }

        if (settings.ActiveRoutingProfileId.IsNullOrWhiteSpace() ||
            settings.RoutingProfiles.All(p => p.Id != settings.ActiveRoutingProfileId))
        {
            settings.ActiveRoutingProfileId = settings.RoutingProfiles.First().Id;
        }

        if (settings.V2RayConfig.CoreBasicItem.DestOverride.Count == 0)
        {
            settings.V2RayConfig.CoreBasicItem.DestOverride = ["http", "tls", "quic"];
        }

        settings.Profiles.RemoveAll(p => p.ServerRemark == string.Empty || p.ModeRemark == string.Empty);

        if (settings.Profiles.Any(p => settings.Profiles.Any(p1 => p1 != p && p1.Index == p.Index)))
            for (var i = 0; i < settings.Profiles.Count; i++)
                settings.Profiles[i].Index = i;

        settings.AioDNS.ChinaDNS = DnsUtils.AppendPort(settings.AioDNS.ChinaDNS);
        settings.AioDNS.OtherDNS = DnsUtils.AppendPort(settings.AioDNS.OtherDNS);
    }

    /// <summary>
    ///     保存配置
    /// </summary>
    public static async Task SaveAsync()
    {
        if (_lock.IsWriteLockHeld)
            return;

        try
        {
            await using var _ = await _lock.WriteLockAsync();
            Log.Verbose("Save Configuration");

            if (!Directory.Exists(DataDirectoryFullName))
                Directory.CreateDirectory(DataDirectoryFullName);

            var tempFile = Path.Combine(DataDirectoryFullName, FileFullName + ".tmp");
            await using (var fileStream = new FileStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true))
            {
                await JsonSerializer.SerializeAsync(fileStream, Global.Settings, JsonSerializerOptions);
            }

            await EnsureConfigFileExistsAsync();

            File.Replace(tempFile, FileFullName, BackupFileFullName);
        }
        catch (Exception e)
        {
            Log.Error(e, "Save Configuration error");
        }
    }

    private static async Task<bool> ExistingConfigurationHasServersAsync()
    {
        foreach (var filename in new[] { FileFullName, BackupFileFullName })
        {
            if (!File.Exists(filename))
                continue;

            try
            {
                var settings = await TryLoadSettingsAsync(filename);
                if (settings?.Server.Count > 0)
                    return true;
            }
            catch (Exception e)
            {
                Log.Warning(e, "Check existing configuration \"{FileName}\" failed", filename);
            }
        }

        return false;
    }

    private static async ValueTask EnsureConfigFileExistsAsync()
    {
        if (!File.Exists(FileFullName))
        {
            await using var fs = new FileStream(FileFullName, FileMode.Create, FileAccess.ReadWrite, FileShare.None, 4096, true);
        }
    }
}
