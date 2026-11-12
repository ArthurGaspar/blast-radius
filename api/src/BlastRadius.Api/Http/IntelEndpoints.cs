using System.Security.Claims;
using BlastRadius.Api.Data;
using BlastRadius.Api.Matching;
using Microsoft.EntityFrameworkCore;

namespace BlastRadius.Api.Http;

/// <summary>Exposure (what the map draws) and the vulnerability catalog.</summary>
public static class IntelEndpoints
{
    /// <summary>CVE ids are upper case ("CVE-2024-37032"); GHSA ids keep a lower-case body ("GHSA-8hqg-whrw-pv92").</summary>
    public static string NormalizeId(string raw)
    {
        var t = raw.Trim();
        if (t.StartsWith("ghsa-", StringComparison.OrdinalIgnoreCase)) return "GHSA-" + t[5..].ToLowerInvariant();
        return t.ToUpperInvariant();
    }

    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api").RequireAuthorization();
        app.MapGet("/api/catalog", (Catalog c) => c.Data);

        // ?site= scopes the threat list to one site, ranked by the scores there
        g.MapGet("/exposure", async (ClaimsPrincipal p, AppDb db, TimeProvider time, Guid? site, CancellationToken ct) =>
        {
            var uid = p.UserId();
            var sites = await db.Sites.Where(s => s.UserId == uid).ToListAsync(ct);
            var assets = await db.Assets.Where(a => a.UserId == uid).ToListAsync(ct);
            var matches = await db.Matches.Where(m => m.UserId == uid).ToListAsync(ct);
            var ids = matches.Select(m => m.VulnerabilityId).Distinct().ToList();
            var vulns = await db.Vulnerabilities.Where(v => ids.Contains(v.Id)).ToDictionaryAsync(v => v.Id, ct);
            var assetById = assets.ToDictionary(a => a.Id);
            var siteById = sites.ToDictionary(s => s.Id);

            var threatMatches = site is { } only ? matches.Where(m => assetById[m.AssetId].SiteId == only).ToList() : matches;
            var threats = threatMatches.GroupBy(m => m.VulnerabilityId)
                .Select(grp =>
                {
                    var v = vulns[grp.Key];
                    double score = grp.Max(m => m.Score);
                    return new
                    {
                        id = v.Id, title = v.Title, severity = v.Severity, cvss = v.CvssScore, kev = v.Kev, kevAdded = v.KevAdded,
                        epss = v.Epss, score, level = Danger.Level(score),
                        assets = grp.OrderByDescending(m => m.Score).Select(m => new
                        {
                            assetId = m.AssetId, label = assetById[m.AssetId].Label, version = assetById[m.AssetId].Version,
                            siteId = assetById[m.AssetId].SiteId, site = siteById[assetById[m.AssetId].SiteId].Name,
                            status = m.Status, basis = m.Basis, explanation = m.Explanation, fixedIn = m.FixedIn, score = m.Score,
                        }).ToList(),
                    };
                })
                .OrderByDescending(t => t.score).ThenByDescending(t => t.epss ?? 0).ThenBy(t => t.id, StringComparer.Ordinal)
                .ToList();

            var siteViews = sites.OrderBy(s => s.CreatedAt).Select(s =>
            {
                var here = matches.Where(m => assetById[m.AssetId].SiteId == s.Id).ToList();
                double score = here.Count == 0 ? 0 : here.Max(m => m.Score);
                var top = here.OrderByDescending(m => m.Score).FirstOrDefault();
                return new
                {
                    s.Id, s.Name, s.Kind, s.Lat, s.Lon, score, level = Danger.Level(score),
                    assets = assets.Count(a => a.SiteId == s.Id),
                    affected = here.Where(m => m.Status == "affected").Select(m => m.VulnerabilityId).Distinct().Count(),
                    possible = here.Where(m => m.Status == "possible").Select(m => m.VulnerabilityId).Distinct().Count(),
                    kev = here.Where(m => vulns[m.VulnerabilityId].Kev).Select(m => m.VulnerabilityId).Distinct().Count(),
                    // strongest exploit signal here; the map's simulated probe traffic scales with it
                    exploitPressure = here.Count == 0 ? 0 : here.Max(m => (vulns[m.VulnerabilityId].Kev ? 1.0 : 0) + (vulns[m.VulnerabilityId].Epss ?? 0)),
                    top = top == null ? null : new { id = top.VulnerabilityId, title = vulns[top.VulnerabilityId].Title, score = top.Score },
                };
            }).ToList();

            double overall = siteViews.Count == 0 ? 0 : siteViews.Max(s => s.score);
            return new
            {
                generatedAt = time.GetUtcNow(),
                score = overall,
                level = Danger.Level(overall),
                totals = new
                {
                    sites = sites.Count, assets = assets.Count, vulnerabilities = threats.Count,
                    affected = threats.Count(t => t.assets.Any(a => a.status == "affected")),
                    kev = threats.Count(t => t.kev),
                    severe = threats.Count(t => t.level == "severe"),
                },
                sites = siteViews,
                threats = threats.Take(100),
            };
        });

        g.MapGet("/vulnerabilities", async (ClaimsPrincipal p, AppDb db, string? q, string? severity, bool? kev, double? minEpss,
                                            string? product, bool? matched, string? sort, int? page, int? size, Catalog catalog,
                                            CancellationToken ct) =>
        {
            var uid = p.UserId();
            int pg = Math.Max(page ?? 0, 0), sz = Math.Clamp(size ?? 50, 1, 200);
            var query = db.Vulnerabilities.Where(v => !v.Withdrawn);
            if (!string.IsNullOrWhiteSpace(q))
            {
                var term = q.Trim();
                var like = "%" + term.ToLowerInvariant() + "%";
                var alias = NormalizeId(term);
                var aliasHit = db.Aliases.Where(a => a.Alias == alias).Select(a => a.VulnerabilityId);
                query = query.Where(v => aliasHit.Contains(v.Id) || EF.Functions.Like(v.Title.ToLower(), like) || EF.Functions.Like(v.Description.ToLower(), like));
            }
            if (!string.IsNullOrEmpty(severity))
            {
                var allowed = severity.Split(',');
                query = query.Where(v => allowed.Contains(v.Severity));
            }
            if (kev == true) query = query.Where(v => v.Kev);
            if (minEpss is { } e) query = query.Where(v => v.Epss >= e);
            if (!string.IsNullOrEmpty(product))
            {
                var prod = catalog.Product(product) ?? throw ApiError.Invalid($"Unknown product {product}");
                var keys = catalog.IdentityKeys(prod).Select(k => "%|" + k + "|%").ToList();
                query = keys.Count switch
                {
                    1 => query.Where(v => EF.Functions.Like(v.IdentityIndex, keys[0])),
                    _ => query.Where(v => EF.Functions.Like(v.IdentityIndex, keys[0]) || EF.Functions.Like(v.IdentityIndex, keys[1])),
                };
            }
            var myMatches = db.Matches.Where(m => m.UserId == uid);
            if (matched == true) query = query.Where(v => myMatches.Any(m => m.VulnerabilityId == v.Id));

            int total = await query.CountAsync(ct);
            // nulls last explicitly: PostgreSQL and SQLite disagree on where NULL sorts in DESC order
            query = sort switch
            {
                "cvss" => query.OrderBy(v => v.CvssScore == null).ThenByDescending(v => v.CvssScore).ThenByDescending(v => v.Id),
                "epss" => query.OrderBy(v => v.Epss == null).ThenByDescending(v => v.Epss).ThenByDescending(v => v.Id),
                _ => query.OrderBy(v => v.Published == null).ThenByDescending(v => v.Published).ThenByDescending(v => v.Id),
            };
            var rows = await query.Skip(pg * sz).Take(sz).ToListAsync(ct);
            var rowIds = rows.Select(r => r.Id).ToList();
            var counts = await myMatches.Where(m => rowIds.Contains(m.VulnerabilityId)).GroupBy(m => m.VulnerabilityId)
                .Select(x => new { x.Key, Count = x.Count() }).ToDictionaryAsync(x => x.Key, x => x.Count, ct);
            return new
            {
                items = rows.Select(v => new
                {
                    v.Id, v.Title, v.Severity, cvss = v.CvssScore, v.Kev, v.Epss, v.Published, v.Modified, v.Sources, v.Aliases,
                    matched = counts.GetValueOrDefault(v.Id),
                }),
                page = pg, size = sz, total,
            };
        });

        g.MapGet("/vulnerabilities/{id}", async (string id, ClaimsPrincipal p, AppDb db, CancellationToken ct) =>
        {
            var uid = p.UserId();
            var key = NormalizeId(id);
            var canonical = await db.Aliases.Where(a => a.Alias == key).Select(a => a.VulnerabilityId).FirstOrDefaultAsync(ct) ?? key;
            var v = await db.Vulnerabilities.FindAsync([canonical], ct) ?? throw ApiError.NotFound("Vulnerability");
            var matches = await db.Matches.Where(m => m.UserId == uid && m.VulnerabilityId == v.Id).ToListAsync(ct);
            var assetIds = matches.Select(m => m.AssetId).ToList();
            var assets = await db.Assets.Where(a => assetIds.Contains(a.Id)).ToDictionaryAsync(a => a.Id, ct);
            var siteIds = assets.Values.Select(a => a.SiteId).Distinct().ToList();
            var sites = await db.Sites.Where(s => siteIds.Contains(s.Id)).ToDictionaryAsync(s => s.Id, ct);
            return new
            {
                v.Id, requested = key, redirected = key != v.Id, v.Title, v.Description, v.Severity, cvss = v.CvssScore,
                cvssVector = v.CvssVector, cvssSource = v.CvssSource, v.Published, v.Modified, v.Withdrawn, v.Sources, v.Aliases, v.Cwes,
                kev = v.Kev ? new { added = v.KevAdded, due = v.KevDue, ransomware = v.KevRansomware, action = v.KevAction } : null,
                epss = v.Epss, epssPercentile = v.EpssPercentile,
                ranges = v.Ranges.Select(r => new
                {
                    r.Source, identity = r.CpeVendor != null ? $"{r.CpeVendor}:{r.CpeProduct}" : $"{r.Ecosystem}/{r.Package}",
                    versions = r.Describe(), r.Fixed,
                }),
                references = v.References.Take(40),
                matches = matches.OrderByDescending(m => m.Score).Select(m => new
                {
                    assetId = m.AssetId, label = assets[m.AssetId].Label, version = assets[m.AssetId].Version,
                    siteId = assets[m.AssetId].SiteId, site = sites[assets[m.AssetId].SiteId].Name, m.Status, m.Basis, m.Explanation, m.FixedIn, m.Score,
                    level = Danger.Level(m.Score), m.FirstSeen,
                }),
            };
        });
    }
}
