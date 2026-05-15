using Netch.Models;

namespace Netch.Utils;

public static class GeoDataUpdateUtil
{
    public const string GeoSiteFileName = "geosite.dat";
    public const string GeoIpFileName = "geoip.dat";

    private const int DownloadTimeout = 120_000;
    private static readonly string[] GeoSiteUrls =
    [
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
    ];

    private static readonly string[] GeoIpUrls =
    [
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"
    ];

    private static readonly TimeSpan UpdateInterval = TimeSpan.FromDays(7);
    private static readonly SemaphoreSlim UpdateLock = new(1, 1);

    public static string GeoSitePath => Path.Combine(Global.NetchDir, "bin", GeoSiteFileName);

    public static string GeoIpPath => Path.Combine(Global.NetchDir, "bin", GeoIpFileName);

    public static bool HasGeoSite => File.Exists(GeoSitePath);

    public static bool HasGeoIp => File.Exists(GeoIpPath);

    public static async Task UpdateIfStaleAsync()
    {
        try
        {
            if (!NeedsUpdate(GeoSitePath) && !NeedsUpdate(GeoIpPath))
            {
                return;
            }

            await UpdateAsync();
        }
        catch (Exception e)
        {
            Log.Warning(e, "Update GeoSite/GeoIP data failed");
        }
    }

    public static async Task UpdateAsync(IProgress<int>? progress = null, string? proxyServer = null)
    {
        await UpdateLock.WaitAsync();
        try
        {
            Directory.CreateDirectory(Path.Combine(Global.NetchDir, "bin"));
            progress?.Report(0);
            await DownloadAtomicAsync(GeoSiteUrls, GeoSitePath, proxyServer);
            progress?.Report(50);
            await DownloadAtomicAsync(GeoIpUrls, GeoIpPath, proxyServer);
            progress?.Report(100);
            Log.Information("GeoSite/GeoIP data updated");
        }
        finally
        {
            UpdateLock.Release();
        }
    }

    private static bool NeedsUpdate(string path)
    {
        if (!File.Exists(path))
        {
            return true;
        }

        return DateTime.UtcNow - File.GetLastWriteTimeUtc(path) > UpdateInterval;
    }

    private static async Task DownloadAtomicAsync(IEnumerable<string> urls, string targetPath, string? proxyServer)
    {
        var tempPath = $"{targetPath}.download";
        var errors = new List<string>();
        try
        {
            foreach (var url in urls)
            {
                try
                {
                    await WebUtil.DownloadFileAsync(url, tempPath, null, DownloadTimeout, proxyServer);
                    if (new FileInfo(tempPath).Length == 0)
                    {
                        throw new MessageException($"Downloaded geo data file is empty: {Path.GetFileName(targetPath)}");
                    }

                    File.Move(tempPath, targetPath, true);
                    return;
                }
                catch (Exception e)
                {
                    errors.Add($"{url}: {e.Message}");
                    Log.Warning(e, "Download geo data failed from {Url}", url);
                    SafeDelete(tempPath);
                }
            }

            throw new MessageException($"下载 {Path.GetFileName(targetPath)} 失败：{string.Join("; ", errors)}");
        }
        finally
        {
            SafeDelete(tempPath);
        }
    }

    private static void SafeDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException e)
        {
            Log.Warning(e, "Delete temporary geo data file failed: {Path}", path);
        }
        catch (UnauthorizedAccessException e)
        {
            Log.Warning(e, "Delete temporary geo data file failed: {Path}", path);
        }
    }
}
