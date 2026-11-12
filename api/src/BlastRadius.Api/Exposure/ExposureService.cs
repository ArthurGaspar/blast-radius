using BlastRadius.Api.Data;
using BlastRadius.Api.Matching;
using Microsoft.EntityFrameworkCore;

namespace BlastRadius.Api.Exposure;

/// <summary>Which assets each vulnerability reaches, and why. Results are stored as <see cref="Match"/> rows.</summary>
public sealed class ExposureService(AppDb db, TimeProvider time)
{
    public sealed record Found(MatchStatus Status, AffectedRange Range, string Explanation, string Basis);

    public static string BasisOf(Asset asset, AffectedRange r, MatchStatus status) =>
        status == MatchStatus.Affected ? "range"
        : r.Exact == null && !r.HasBounds ? "no-bounds"
        : string.IsNullOrWhiteSpace(asset.Version) ? "no-version"
        : "incomparable";

    /// <summary>Best statement across sources: "affected" beats "possible"; NVD and GitHub are otherwise equal.</summary>
    public static Found? Evaluate(Asset asset, Vulnerability v)
    {
        if (v.Withdrawn) return null;
        var keys = asset.IdentityKeys().ToHashSet();
        var (status, range) = AffectedRange.Best(v.Ranges.Where(r => keys.Contains(r.IdentityKey)), asset.Version);
        return status == MatchStatus.None ? null : new Found(status, range!, Explain(asset, range!, status), BasisOf(asset, range!, status));
    }

    public static string Explain(Asset asset, AffectedRange r, MatchStatus status)
    {
        string who = r.Source == "nvd" ? $"NVD cpe {r.CpeVendor}:{r.CpeProduct}" : $"GitHub {r.Ecosystem}/{r.Package}";
        if (!r.HasBounds && r.Exact == null) return $"{who} names the product without version bounds";
        if (status == MatchStatus.Possible && string.IsNullOrWhiteSpace(asset.Version)) return $"Version unknown; {who} lists {r.Describe()}";
        if (status == MatchStatus.Possible) return $"{asset.Version} can't be compared with {r.Describe()} ({who})";
        return $"{asset.Version} is in {r.Describe()} ({who})";
    }

    /// <summary>
    /// Recomputes matches for one user, or everyone when <paramref name="userId"/> is null.
    /// Existing rows keep their FirstSeen; stale ones are removed.
    /// </summary>
    public async Task RecomputeAsync(Guid? userId, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var assets = await db.Assets.Where(a => userId == null || a.UserId == userId).ToListAsync(ct);
        var keys = assets.SelectMany(a => a.IdentityKeys()).Distinct().ToList();

        var candidates = new List<Vulnerability>();
        foreach (var key in keys)
        {
            var pattern = "%|" + key + "|%";
            candidates.AddRange(await db.Vulnerabilities.Where(v => !v.Withdrawn && EF.Functions.Like(v.IdentityIndex, pattern)).ToListAsync(ct));
        }
        var byKey = candidates.DistinctBy(v => v.Id)
            .SelectMany(v => v.Ranges.Select(r => (r.IdentityKey, v)))
            .GroupBy(x => x.IdentityKey)
            .ToDictionary(g => g.Key, g => g.Select(x => x.v).DistinctBy(v => v.Id).ToList());

        var existing = await db.Matches.Where(m => userId == null || m.UserId == userId).ToListAsync(ct);
        var byPair = existing.ToDictionary(m => (m.AssetId, m.VulnerabilityId));
        var keep = new HashSet<(Guid, string)>();

        foreach (var asset in assets)
        {
            var vulns = asset.IdentityKeys().SelectMany(k => byKey.GetValueOrDefault(k) ?? []).DistinctBy(v => v.Id);
            foreach (var v in vulns)
            {
                var found = Evaluate(asset, v);
                if (found == null) continue;
                var pair = (asset.Id, v.Id);
                keep.Add(pair);
                double score = Danger.Score(v.CvssScore, v.Severity, v.Kev, v.Epss, found.Status);
                string status = found.Status == MatchStatus.Affected ? "affected" : "possible";
                if (byPair.TryGetValue(pair, out var m))
                {
                    m.Status = status; m.Basis = found.Basis; m.Explanation = found.Explanation; m.FixedIn = found.Range.Fixed; m.Score = score;
                }
                else
                {
                    db.Matches.Add(new Match
                    {
                        UserId = asset.UserId, AssetId = asset.Id, VulnerabilityId = v.Id, Status = status, Basis = found.Basis,
                        Explanation = found.Explanation, FixedIn = found.Range.Fixed, Score = score, FirstSeen = now,
                    });
                }
            }
        }
        db.Matches.RemoveRange(existing.Where(m => !keep.Contains((m.AssetId, m.VulnerabilityId))));
        await db.SaveChangesAsync(ct);
    }
}
