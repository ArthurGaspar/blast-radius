using System.Security.Claims;
using BlastRadius.Api.Data;
using BlastRadius.Api.Exposure;
using Microsoft.EntityFrameworkCore;

namespace BlastRadius.Api.Http;

/// <summary>Sites and the software running at them. Edits recompute exposure but never notify.</summary>
public static class InventoryEndpoints
{
    public sealed record SiteRequest(string? Name, string? Kind, string? PresetKey, double? Lat, double? Lon);
    public sealed record AssetRequest(Guid? SiteId, string? ProductKey, string? Label, string? Version,
                                      string? Ecosystem, string? Package, string? CpeVendor, string? CpeProduct);

    private static readonly string[] Kinds = ["office", "datacenter", "cloud"];
    public const int MaxSites = 200;
    public const int MaxAssets = 500;

    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api").RequireAuthorization();

        g.MapGet("/sites", async (ClaimsPrincipal p, AppDb db, CancellationToken ct) =>
            (await db.Sites.Where(s => s.UserId == p.UserId()).ToListAsync(ct)).OrderBy(s => s.CreatedAt).Select(SiteView));

        g.MapPost("/sites", async (SiteRequest req, ClaimsPrincipal p, AppDb db, Catalog catalog, TimeProvider time, CancellationToken ct) =>
        {
            var uid = p.UserId();
            if (await db.Sites.CountAsync(s => s.UserId == uid, ct) >= MaxSites)
                throw ApiError.Conflict("site.limit", $"Up to {MaxSites} sites per account");
            var site = new Site { UserId = uid, Name = "", Kind = "office", CreatedAt = time.GetUtcNow() };
            ApplySite(site, req, catalog);
            db.Sites.Add(site);
            await db.SaveChangesAsync(ct);
            return Results.Created($"/api/sites/{site.Id}", SiteView(site));
        });

        g.MapPut("/sites/{id:guid}", async (Guid id, SiteRequest req, ClaimsPrincipal p, AppDb db, Catalog catalog, CancellationToken ct) =>
        {
            var site = await db.Sites.FirstOrDefaultAsync(s => s.Id == id && s.UserId == p.UserId(), ct) ?? throw ApiError.NotFound("Site");
            ApplySite(site, req, catalog);
            await db.SaveChangesAsync(ct);
            return SiteView(site);
        });

        g.MapDelete("/sites/{id:guid}", async (Guid id, ClaimsPrincipal p, AppDb db, ExposureService exposure, CancellationToken ct) =>
        {
            var uid = p.UserId();
            var site = await db.Sites.FirstOrDefaultAsync(s => s.Id == id && s.UserId == uid, ct) ?? throw ApiError.NotFound("Site");
            if (await db.Subscriptions.AnyAsync(s => s.UserId == uid && s.ScopeSiteId == id, ct))
                throw ApiError.Conflict("site.has-subscriptions", "Subscriptions are scoped to this site; change or delete them first");
            db.Assets.RemoveRange(await db.Assets.Where(a => a.SiteId == id).ToListAsync(ct));
            db.Sites.Remove(site);
            await db.SaveChangesAsync(ct);
            await exposure.RecomputeAsync(uid, ct);
            return Results.NoContent();
        });

        g.MapGet("/assets", async (Guid? siteId, ClaimsPrincipal p, AppDb db, CancellationToken ct) =>
        {
            var uid = p.UserId();
            var assets = await db.Assets.Where(a => a.UserId == uid && (siteId == null || a.SiteId == siteId)).ToListAsync(ct);
            var counts = await MatchCountsAsync(db, uid, ct);
            return assets.OrderBy(a => a.CreatedAt).Select(a => AssetView(a, counts.GetValueOrDefault(a.Id)));
        });

        g.MapPost("/assets", async (AssetRequest req, ClaimsPrincipal p, AppDb db, Catalog catalog, ExposureService exposure,
                                    TimeProvider time, CancellationToken ct) =>
        {
            var uid = p.UserId();
            if (await db.Assets.CountAsync(a => a.UserId == uid, ct) >= MaxAssets)
                throw ApiError.Conflict("asset.limit", $"Up to {MaxAssets} assets per account");
            var asset = new Asset { UserId = uid, Label = "", CreatedAt = time.GetUtcNow() };
            await ApplyAssetAsync(asset, req, uid, db, catalog, ct);
            db.Assets.Add(asset);
            await db.SaveChangesAsync(ct);
            await exposure.RecomputeAsync(uid, ct);
            var counts = await MatchCountsAsync(db, uid, ct);
            return Results.Created($"/api/assets/{asset.Id}", AssetView(asset, counts.GetValueOrDefault(asset.Id)));
        });

        g.MapPut("/assets/{id:guid}", async (Guid id, AssetRequest req, ClaimsPrincipal p, AppDb db, Catalog catalog,
                                             ExposureService exposure, CancellationToken ct) =>
        {
            var uid = p.UserId();
            var asset = await db.Assets.FirstOrDefaultAsync(a => a.Id == id && a.UserId == uid, ct) ?? throw ApiError.NotFound("Asset");
            await ApplyAssetAsync(asset, req, uid, db, catalog, ct);
            await db.SaveChangesAsync(ct);
            await exposure.RecomputeAsync(uid, ct);
            var counts = await MatchCountsAsync(db, uid, ct);
            return AssetView(asset, counts.GetValueOrDefault(asset.Id));
        });

        g.MapDelete("/assets/{id:guid}", async (Guid id, ClaimsPrincipal p, AppDb db, ExposureService exposure, CancellationToken ct) =>
        {
            var uid = p.UserId();
            var asset = await db.Assets.FirstOrDefaultAsync(a => a.Id == id && a.UserId == uid, ct) ?? throw ApiError.NotFound("Asset");
            db.Assets.Remove(asset);
            await db.SaveChangesAsync(ct);
            await exposure.RecomputeAsync(uid, ct);
            return Results.NoContent();
        });
    }

    private static void ApplySite(Site site, SiteRequest req, Catalog catalog)
    {
        var name = req.Name?.Trim();
        if (string.IsNullOrEmpty(name) || name.Length > 80) throw ApiError.Invalid("name must be 1-80 characters");
        if (req.Kind == null || !Kinds.Contains(req.Kind)) throw ApiError.Invalid("kind must be office, datacenter or cloud");
        site.Name = name;
        site.Kind = req.Kind;
        if (req.PresetKey != null)
        {
            var preset = catalog.Data.SitePresets.FirstOrDefault(x => x.Key == req.PresetKey)
                         ?? throw ApiError.Invalid($"Unknown location preset {req.PresetKey}");
            site.PresetKey = preset.Key; site.Lat = preset.Lat; site.Lon = preset.Lon;
        }
        else
        {
            if (req.Lat is not { } lat || req.Lon is not { } lon || lat < -90 || lat > 90 || lon < -180 || lon > 180)
                throw ApiError.Invalid("Pick a location preset or give lat (-90..90) and lon (-180..180)");
            site.PresetKey = null; site.Lat = lat; site.Lon = lon;
        }
    }

    private static async Task ApplyAssetAsync(Asset asset, AssetRequest req, Guid uid, AppDb db, Catalog catalog, CancellationToken ct)
    {
        if (req.SiteId is not { } siteId || !await db.Sites.AnyAsync(s => s.Id == siteId && s.UserId == uid, ct))
            throw ApiError.Invalid("siteId must be one of your sites");
        var version = (req.Version ?? "").Trim();
        if (version.Length > 40) throw ApiError.Invalid("version must be at most 40 characters");

        if (req.ProductKey != null)
        {
            var product = catalog.Product(req.ProductKey) ?? throw ApiError.Invalid($"Unknown product {req.ProductKey}");
            asset.ProductKey = product.Key;
            asset.Ecosystem = product.Ghsa?.Ecosystem; asset.Package = product.Ghsa?.Package;
            asset.CpeVendor = product.Cpe?.Vendor; asset.CpeProduct = product.Cpe?.Product;
            asset.Label = string.IsNullOrWhiteSpace(req.Label) ? product.Name : req.Label.Trim();
        }
        else
        {
            bool hasPkg = !string.IsNullOrWhiteSpace(req.Ecosystem) && !string.IsNullOrWhiteSpace(req.Package);
            bool hasCpe = !string.IsNullOrWhiteSpace(req.CpeVendor) && !string.IsNullOrWhiteSpace(req.CpeProduct);
            if (!hasPkg && !hasCpe) throw ApiError.Invalid("Pick a catalog product, or give ecosystem + package and/or CPE vendor + product");
            asset.ProductKey = null;
            asset.Ecosystem = hasPkg ? req.Ecosystem!.Trim().ToLowerInvariant() : null;
            asset.Package = hasPkg ? req.Package!.Trim() : null;
            asset.CpeVendor = hasCpe ? req.CpeVendor!.Trim().ToLowerInvariant() : null;
            asset.CpeProduct = hasCpe ? req.CpeProduct!.Trim().ToLowerInvariant() : null;
            asset.Label = string.IsNullOrWhiteSpace(req.Label) ? (asset.Package ?? asset.CpeProduct!) : req.Label.Trim();
        }
        if (asset.Label.Length > 80) throw ApiError.Invalid("label must be at most 80 characters");
        asset.SiteId = siteId;
        asset.Version = version;
    }

    private static async Task<Dictionary<Guid, (int Affected, int Possible, double Max)>> MatchCountsAsync(AppDb db, Guid uid, CancellationToken ct) =>
        (await db.Matches.Where(m => m.UserId == uid).Select(m => new { m.AssetId, m.Status, m.Score }).ToListAsync(ct))
        .GroupBy(m => m.AssetId)
        .ToDictionary(g => g.Key, g => (g.Count(m => m.Status == "affected"), g.Count(m => m.Status == "possible"), g.Max(m => m.Score)));

    public static object SiteView(Site s) => new { s.Id, s.Name, s.Kind, s.PresetKey, s.Lat, s.Lon, s.CreatedAt };

    public static object AssetView(Asset a, (int Affected, int Possible, double Max) c) => new
    {
        a.Id, a.SiteId, a.ProductKey, a.Label, a.Version, a.Ecosystem, a.Package, a.CpeVendor, a.CpeProduct, a.CreatedAt,
        affected = c.Affected, possible = c.Possible, maxScore = c.Max,
        level = Matching.Danger.Level(c.Max),
    };
}
