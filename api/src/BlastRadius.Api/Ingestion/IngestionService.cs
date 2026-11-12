using BlastRadius.Api.Data;
using BlastRadius.Api.Exposure;
using BlastRadius.Api.Matching;
using BlastRadius.Api.Notifications;
using Microsoft.EntityFrameworkCore;

namespace BlastRadius.Api.Ingestion;

public sealed record IngestionSummary(Guid BatchId, DateTimeOffset StartedAt, DateTimeOffset FinishedAt, int Fetched,
                                      int Created, int Updated, int Linked, int Merged, int KevMarked, int EpssScored,
                                      int Notifications, List<string> Errors);

/// <summary>
/// One ingestion batch: fetch every watched product from NVD and GitHub, deduplicate into canonical records,
/// enrich with KEV and EPSS, recompute exposure, and notify subscribers about what changed.
/// Watched products are the catalog plus whatever identities users entered by hand.
/// </summary>
public sealed class IngestionService(AppDb db, Catalog catalog, NvdClient nvd, GhsaClient ghsa, KevClient kev,
                                     EpssClient epss, ExposureService exposure, Notifier notifier, TimeProvider time,
                                     ILogger<IngestionService> log)
{
    private Dictionary<string, Vulnerability> _byAlias = [];
    private Dictionary<string, string> _remap = [];
    private int _created, _updated, _linked, _merged;

    public async Task<IngestionSummary> RunAsync(string trigger, CancellationToken ct)
    {
        var batch = Guid.NewGuid();
        var started = time.GetUtcNow();
        var errors = new List<string>();
        int fetched = 0;
        _created = _updated = _linked = _merged = 0;
        _remap = [];

        var before = await SnapshotAsync(ct);
        var all = await db.Vulnerabilities.ToListAsync(ct);
        _byAlias = new Dictionary<string, Vulnerability>(StringComparer.Ordinal);
        foreach (var v in all) foreach (var a in v.Aliases) _byAlias[a] = v;

        var (cpes, packages) = await WatchedAsync(ct);

        foreach (var (vendor, product) in cpes)
        {
            var key = "nvd:" + Identity.CpeKey(vendor, product);
            var run = await StartRunAsync(batch, "nvd", $"{vendor}:{product}", trigger);
            try
            {
                var state = await db.SyncStates.FindAsync([key], ct);
                var now = time.GetUtcNow();
                await foreach (var cve in nvd.FetchAsync(vendor, product, state?.LastSuccess, now, ct))
                {
                    run.Fetched++;
                    Count(run, Upsert(Normalize.FromNvd(cve)));
                }
                if (state == null) db.SyncStates.Add(new SyncState { Key = key, LastSuccess = now });
                else state.LastSuccess = now;
            }
            catch (Exception ex) when (ex is HttpRequestException or System.Text.Json.JsonException or TaskCanceledException)
            {
                run.Error = ex.Message;
                errors.Add($"NVD {vendor}:{product}: {ex.Message}");
            }
            fetched += run.Fetched;
            await FinishRunAsync(run, ct);
        }

        foreach (var (ecosystem, package) in packages)
        {
            var key = "ghsa:" + Identity.PackageKey(ecosystem, package);
            var run = await StartRunAsync(batch, "ghsa", $"{ecosystem}/{package}", trigger);
            try
            {
                var state = await db.SyncStates.FindAsync([key], ct);
                var now = time.GetUtcNow();
                await foreach (var a in ghsa.FetchAsync(ecosystem, package, state?.LastSuccess, ct))
                {
                    run.Fetched++;
                    Count(run, Upsert(Normalize.FromGhsa(a)));
                }
                if (state == null) db.SyncStates.Add(new SyncState { Key = key, LastSuccess = now });
                else state.LastSuccess = now;
            }
            catch (Exception ex) when (ex is HttpRequestException or System.Text.Json.JsonException or TaskCanceledException)
            {
                run.Error = ex.Message;
                errors.Add($"GitHub {ecosystem}/{package}: {ex.Message}");
            }
            fetched += run.Fetched;
            await FinishRunAsync(run, ct);
        }

        int kevMarked = await EnrichKevAsync(batch, trigger, errors, ct);
        int epssScored = await EnrichEpssAsync(batch, trigger, errors, ct);
        await SyncAliasesAsync(ct);
        await RepointAsync(ct);
        await db.SaveChangesAsync(ct);

        await exposure.RecomputeAsync(null, ct);
        var events = await DiffAsync(before, ct);
        int notified = await notifier.NotifyAsync(events, ct);

        var finished = time.GetUtcNow();
        log.LogInformation("Ingestion {Batch}: {Fetched} fetched, {Created} new, {Updated} updated, {Linked} linked, {Merged} merged, {Notified} notifications",
            batch, fetched, _created, _updated, _linked, _merged, notified);
        return new IngestionSummary(batch, started, finished, fetched, _created, _updated, _linked, _merged, kevMarked, epssScored, notified, errors);
    }

    private async Task<(List<(string, string)> Cpes, List<(string, string)> Packages)> WatchedAsync(CancellationToken ct)
    {
        var cpes = new HashSet<(string, string)>();
        var packages = new HashSet<(string, string)>();
        foreach (var p in catalog.Data.Products)
        {
            if (p.Cpe != null) cpes.Add((p.Cpe.Vendor, p.Cpe.Product));
            if (p.Ghsa != null) packages.Add((p.Ghsa.Ecosystem, p.Ghsa.Package));
        }
        foreach (var a in await db.Assets.Where(a => a.ProductKey == null).ToListAsync(ct))
        {
            if (a.CpeVendor != null && a.CpeProduct != null) cpes.Add((a.CpeVendor.ToLowerInvariant(), a.CpeProduct.ToLowerInvariant()));
            if (a.Ecosystem != null && a.Package != null) packages.Add((a.Ecosystem.ToLowerInvariant(), a.Package));
        }
        return (cpes.Order().ToList(), packages.Order().ToList());
    }

    private enum Outcome { Created, Updated, Linked, Merged, Unchanged }

    private static void Count(IngestionRun run, Outcome o)
    {
        switch (o)
        {
            case Outcome.Created: run.Created++; break;
            case Outcome.Updated: run.Updated++; break;
            case Outcome.Linked: run.Linked++; break;
            case Outcome.Merged: run.Merged++; break;
            default: run.Unchanged++; break;
        }
    }

    /// <summary>
    /// Finds every canonical record any of the advisory's identifiers already points to. None: new record.
    /// Several: they were duplicates all along (e.g. a GitHub-only record and an NVD record that this advisory
    /// links by CVE), so they collapse into one. Finally the record is re-keyed if a CVE has appeared.
    /// </summary>
    private Outcome Upsert(Advisory a)
    {
        var now = time.GetUtcNow();
        var hits = a.Aliases.Select(x => _byAlias.GetValueOrDefault(x)).OfType<Vulnerability>().Distinct().ToList();
        Vulnerability v;
        var outcome = Outcome.Unchanged;
        if (hits.Count == 0)
        {
            v = new Vulnerability { Id = Merge.PreferredId(a.Aliases), IngestedAt = now, UpdatedAt = now };
            db.Vulnerabilities.Add(v);
            outcome = Outcome.Created;
            _created++;
        }
        else
        {
            v = hits.OrderBy(h => h.Id.StartsWith("CVE-", StringComparison.Ordinal) ? 0 : 1).ThenBy(h => h.Id, StringComparer.Ordinal).First();
            foreach (var other in hits.Where(h => h != v))
            {
                Merge.Absorb(v, other);
                Retire(other, v);
                outcome = Outcome.Merged;
                _merged++;
            }
        }

        bool linked = outcome == Outcome.Unchanged && !v.Sources.Contains(a.Source);
        bool changed = Merge.Apply(v, a, now);
        var preferred = Merge.PreferredId(v.Aliases);
        if (preferred != v.Id)
        {
            var rekeyed = Merge.Rekey(v, preferred);
            db.Vulnerabilities.Add(rekeyed);
            Retire(v, rekeyed);
            v = rekeyed;
            if (outcome != Outcome.Created) { outcome = Outcome.Merged; _merged++; }
        }
        foreach (var alias in v.Aliases) _byAlias[alias] = v;

        if (outcome == Outcome.Unchanged && linked) { outcome = Outcome.Linked; _linked++; }
        else if (outcome == Outcome.Unchanged && changed) { outcome = Outcome.Updated; _updated++; }
        return outcome;
    }

    private void Retire(Vulnerability old, Vulnerability into)
    {
        _remap[old.Id] = into.Id;
        foreach (var alias in old.Aliases) _byAlias[alias] = into;
        var entry = db.Entry(old);
        if (entry.State == EntityState.Added) entry.State = EntityState.Detached;
        else db.Vulnerabilities.Remove(old);
    }

    private string Resolve(string id)
    {
        while (_remap.TryGetValue(id, out var next)) id = next;
        return id;
    }

    private async Task<int> EnrichKevAsync(Guid batch, string trigger, List<string> errors, CancellationToken ct)
    {
        var run = await StartRunAsync(batch, "kev", "catalog", trigger);
        int marked = 0;
        try
        {
            var entries = await kev.FetchAsync(ct);
            run.Fetched = entries.Count;
            var listed = new HashSet<string>(StringComparer.Ordinal);
            foreach (var e in entries)
            {
                if (!_byAlias.TryGetValue(e.Cve, out var v)) continue;
                listed.Add(v.Id);
                bool changed = !v.Kev || v.KevAdded != e.Added || v.KevDue != e.Due || v.KevRansomware != e.Ransomware;
                v.Kev = true; v.KevAdded = e.Added; v.KevDue = e.Due; v.KevRansomware = e.Ransomware; v.KevAction = e.Action;
                if (changed) { run.Updated++; marked++; } else run.Unchanged++;
            }
            foreach (var v in _byAlias.Values.Distinct().Where(v => v.Kev && !listed.Contains(v.Id)))
            {
                v.Kev = false; v.KevAdded = null; v.KevDue = null; v.KevRansomware = false; v.KevAction = null;
                run.Updated++;
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or System.Text.Json.JsonException or TaskCanceledException)
        {
            run.Error = ex.Message;
            errors.Add($"KEV: {ex.Message}");
        }
        await FinishRunAsync(run, ct);
        return marked;
    }

    private async Task<int> EnrichEpssAsync(Guid batch, string trigger, List<string> errors, CancellationToken ct)
    {
        var run = await StartRunAsync(batch, "epss", "scored CVEs", trigger);
        int scored = 0;
        try
        {
            var byCve = _byAlias.Values.Distinct().Where(v => v.Id.StartsWith("CVE-", StringComparison.Ordinal)).ToDictionary(v => v.Id);
            var scores = await epss.FetchAsync(byCve.Keys.Order().ToList(), ct);
            run.Fetched = scores.Count;
            foreach (var (cve, s) in scores)
            {
                var v = byCve[cve];
                if (v.Epss == s.Epss && v.EpssPercentile == s.Percentile) { run.Unchanged++; continue; }
                v.Epss = s.Epss; v.EpssPercentile = s.Percentile;
                run.Updated++; scored++;
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or System.Text.Json.JsonException or TaskCanceledException)
        {
            run.Error = ex.Message;
            errors.Add($"EPSS: {ex.Message}");
        }
        await FinishRunAsync(run, ct);
        return scored;
    }

    /// <summary>Makes the alias table mirror the in-memory index (the unique key guarantees one owner per identifier).</summary>
    private async Task SyncAliasesAsync(CancellationToken ct)
    {
        var rows = await db.Aliases.ToDictionaryAsync(a => a.Alias, ct);
        foreach (var (alias, v) in _byAlias)
        {
            if (rows.Remove(alias, out var row))
            {
                if (row.VulnerabilityId != v.Id) row.VulnerabilityId = v.Id;
            }
            else db.Aliases.Add(new VulnerabilityAlias { Alias = alias, VulnerabilityId = v.Id });
        }
        db.Aliases.RemoveRange(rows.Values);
    }

    /// <summary>Notifications that pointed at a record merged or re-keyed this run now point at its successor.</summary>
    private async Task RepointAsync(CancellationToken ct)
    {
        if (_remap.Count == 0) return;
        var oldIds = _remap.Keys.ToList();
        var stale = await db.Notifications.Where(n => oldIds.Contains(n.VulnerabilityId)).ToListAsync(ct);
        var targets = stale.Select(n => Resolve(n.VulnerabilityId)).Distinct().ToList();
        var existing = (await db.Notifications.Where(n => targets.Contains(n.VulnerabilityId))
                .Select(n => new { n.SubscriptionId, n.VulnerabilityId, n.Reason }).ToListAsync(ct))
            .Select(x => (x.SubscriptionId, x.VulnerabilityId, x.Reason)).ToHashSet();
        foreach (var n in stale)
        {
            var to = Resolve(n.VulnerabilityId);
            if (!existing.Add((n.SubscriptionId, to, n.Reason))) db.Notifications.Remove(n);
            else n.VulnerabilityId = to;
        }
        // matches are rebuilt by the exposure pass; drop the ones keyed by retired ids
        db.Matches.RemoveRange(await db.Matches.Where(m => oldIds.Contains(m.VulnerabilityId)).ToListAsync(ct));
    }

    private sealed record Snapshot(HashSet<(Guid Asset, string Vuln)> Pairs, Dictionary<string, (bool Kev, string Severity)> State);

    private async Task<Snapshot> SnapshotAsync(CancellationToken ct)
    {
        var matches = await db.Matches.Select(m => new { m.AssetId, m.VulnerabilityId }).ToListAsync(ct);
        var ids = matches.Select(m => m.VulnerabilityId).Distinct().ToList();
        var state = await db.Vulnerabilities.Where(v => ids.Contains(v.Id))
            .Select(v => new { v.Id, v.Kev, v.Severity }).ToDictionaryAsync(v => v.Id, v => (v.Kev, v.Severity), ct);
        return new Snapshot(matches.Select(m => (m.AssetId, m.VulnerabilityId)).ToHashSet(), state);
    }

    /// <summary>Compares exposure before and after the batch; ids from before are resolved through merges.</summary>
    private async Task<List<ExposureEvent>> DiffAsync(Snapshot before, CancellationToken ct)
    {
        var pairsBefore = before.Pairs.Select(p => (p.Asset, Resolve(p.Vuln))).ToHashSet();
        var stateBefore = new Dictionary<string, (bool Kev, string Severity)>();
        foreach (var (id, s) in before.State)
        {
            var to = Resolve(id);
            stateBefore[to] = stateBefore.TryGetValue(to, out var prev)
                ? (prev.Kev || s.Kev, Danger.SeverityRank(prev.Severity) >= Danger.SeverityRank(s.Severity) ? prev.Severity : s.Severity)
                : s;
        }

        var matches = await db.Matches.ToListAsync(ct);
        var assets = await db.Assets.ToDictionaryAsync(a => a.Id, ct);
        var sites = await db.Sites.ToDictionaryAsync(s => s.Id, ct);
        var vulnIds = matches.Select(m => m.VulnerabilityId).Distinct().ToList();
        var vulns = await db.Vulnerabilities.Where(v => vulnIds.Contains(v.Id)).ToDictionaryAsync(v => v.Id, ct);

        var events = new List<ExposureEvent>();
        foreach (var m in matches.OrderBy(m => m.VulnerabilityId, StringComparer.Ordinal))
        {
            if (!assets.TryGetValue(m.AssetId, out var asset) || !sites.TryGetValue(asset.SiteId, out var site)) continue;
            var v = vulns[m.VulnerabilityId];
            if (!pairsBefore.Contains((m.AssetId, m.VulnerabilityId)))
            {
                events.Add(new ExposureEvent("new_exposure", m.UserId, asset, site, v, m.Basis));
                continue;
            }
            if (!stateBefore.TryGetValue(v.Id, out var was)) continue;
            if (v.Kev && !was.Kev) events.Add(new ExposureEvent("kev_added", m.UserId, asset, site, v, m.Basis));
            if (Danger.SeverityRank(v.Severity) > Danger.SeverityRank(was.Severity))
                events.Add(new ExposureEvent("severity_raised", m.UserId, asset, site, v, m.Basis));
        }
        return events;
    }

    private async Task<IngestionRun> StartRunAsync(Guid batch, string source, string target, string trigger)
    {
        var run = new IngestionRun { BatchId = batch, Source = source, Target = target, Trigger = trigger, StartedAt = time.GetUtcNow() };
        db.IngestionRuns.Add(run);
        await Task.CompletedTask;
        return run;
    }

    private async Task FinishRunAsync(IngestionRun run, CancellationToken ct)
    {
        run.FinishedAt = time.GetUtcNow();
        await db.SaveChangesAsync(ct);
    }
}
