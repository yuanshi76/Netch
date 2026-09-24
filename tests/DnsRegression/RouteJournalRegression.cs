using System.Text.Json;
using Netch.Models;
using Netch.Services;

internal static class RouteJournalRegression
{
    private static void Check(bool ok, string message) { if (!ok) throw new Exception(message); }
    public static async Task RunAsync(string root, Func<string, Func<Task>, Task> test)
    {
        var entry = new OwnedRouteJournal.Entry(Guid.NewGuid().ToString(), "198.18.0.0/15", "10.0.236.1", 1);
        string PathForTest() => Path.Combine(root, ".build", "regression", "routes-" + Guid.NewGuid().ToString("N"), "owned.json");
        await test("TUN route ownership is durable before creation and survives a host crash", () =>
        {
            var path = PathForTest(); var actual = new HashSet<OwnedRouteJournal.Entry>();
            bool Exists(OwnedRouteJournal.Entry e, bool exact) => actual.Any(a => a.InterfaceId == e.InterfaceId && a.DestinationPrefix == e.DestinationPrefix && a.NextHop == e.NextHop && (!exact || a.Metric == e.Metric));
            var journal = new OwnedRouteJournal(path, Exists, e =>
            {
                Check(JsonSerializer.Deserialize<List<OwnedRouteJournal.Entry>>(File.ReadAllText(path))!.Contains(e), "ownership precedes route mutation");
                return actual.Add(e);
            }, actual.Remove);
            journal.Add(entry); journal.Add(entry);
            Check(actual.Count == 1, "duplicate add is idempotent");
            new OwnedRouteJournal(path, Exists, actual.Add, actual.Remove).Restore();
            Check(actual.Count == 0 && JsonSerializer.Deserialize<List<OwnedRouteJournal.Entry>>(File.ReadAllText(path))!.Count == 0, "new owner restores after simulated crash");
            return Task.CompletedTask;
        });
        await test("TUN never takes ownership of preexisting routes or deletes changed routes", () =>
        {
            var path = PathForTest(); var actual = new HashSet<OwnedRouteJournal.Entry> { entry with { Metric = 2 } };
            bool Exists(OwnedRouteJournal.Entry e, bool exact) => actual.Any(a => a.InterfaceId == e.InterfaceId && a.DestinationPrefix == e.DestinationPrefix && a.NextHop == e.NextHop && (!exact || a.Metric == e.Metric));
            var journal = new OwnedRouteJournal(path, Exists, actual.Add, actual.Remove);
            try { journal.Add(entry); throw new Exception("Preexisting route accepted"); } catch (MessageException) { }
            Check(!File.Exists(path) && actual.Count == 1, "preexisting route remains untouched");
            actual.Clear(); journal.Add(entry);
            actual.Remove(entry); actual.Add(entry with { Metric = 3 });
            journal.Restore();
            Check(actual.Single().Metric == 3, "externally changed route preserved");
            return Task.CompletedTask;
        });
        await test("TUN cleanup failure retains retryable ownership and failed create is not claimed", () =>
        {
            var path = PathForTest(); var actual = new HashSet<OwnedRouteJournal.Entry>();
            bool Exists(OwnedRouteJournal.Entry e, bool _) => actual.Contains(e);
            var journal = new OwnedRouteJournal(path, Exists, actual.Add, _ => false); journal.Add(entry);
            try { journal.Restore(); throw new Exception("Failure hidden"); } catch (MessageException) { }
            Check(actual.Count == 1 && JsonSerializer.Deserialize<List<OwnedRouteJournal.Entry>>(File.ReadAllText(path))!.Count == 1, "failed removal keeps record");
            new OwnedRouteJournal(path, Exists, actual.Add, actual.Remove).Restore();
            Check(actual.Count == 0, "fresh controller retries cleanup");
            var failed = new OwnedRouteJournal(path, Exists, _ => false, actual.Remove);
            try { failed.Add(entry); throw new Exception("Failed creation hidden"); } catch (MessageException) { }
            Check(JsonSerializer.Deserialize<List<OwnedRouteJournal.Entry>>(File.ReadAllText(path))!.Count == 0, "failed create removed from journal");
            return Task.CompletedTask;
        });
        await test("TUN rejects invalid recovery records and refuses mutation without a writable journal", () =>
        {
            var path = PathForTest(); Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(new[] { entry with { InterfaceId = "wrong-interface" } }));
            try { _ = new OwnedRouteJournal(path); throw new Exception("Invalid journal accepted"); } catch (MessageException) { }
            var blocked = Path.Combine(Path.GetDirectoryName(path)!, "blocked"); File.WriteAllText(blocked, "file instead of directory");
            var calls = 0;
            var journal = new OwnedRouteJournal(Path.Combine(blocked, "owned.json"), (_, _) => false, _ => { calls++; return true; }, _ => true);
            try { journal.Add(entry); throw new Exception("Unwritable journal accepted"); } catch (IOException) { }
            Check(calls == 0, "no route operation if ownership cannot be saved");
            return Task.CompletedTask;
        });
    }
}
