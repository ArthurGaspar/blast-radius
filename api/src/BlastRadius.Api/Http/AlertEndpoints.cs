using System.Security.Claims;
using BlastRadius.Api.Data;
using BlastRadius.Api.Matching;
using BlastRadius.Api.Notifications;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace BlastRadius.Api.Http;

/// <summary>Subscriptions, the notification inbox and webhook delivery logs.</summary>
public static class AlertEndpoints
{
    public sealed record SubscriptionRequest(string? Name, string? Scope, Guid? ScopeSiteId, string? ScopeProductKey,
                                             string? MinSeverity, bool? KevOnly, double? MinEpss, string? Keyword,
                                             string? WebhookUrl, bool? Active);

    private static readonly string[] Severities = ["none", "low", "medium", "high", "critical"];

    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api").RequireAuthorization();

        g.MapGet("/subscriptions", async (ClaimsPrincipal p, AppDb db, CancellationToken ct) =>
            (await db.Subscriptions.Where(s => s.UserId == p.UserId()).ToListAsync(ct)).OrderBy(s => s.CreatedAt));

        g.MapPost("/subscriptions", async (SubscriptionRequest req, ClaimsPrincipal p, AppDb db, Catalog catalog,
                                           IOptions<WebhookOptions> hooks, TimeProvider time, CancellationToken ct) =>
        {
            var uid = p.UserId();
            if (await db.Subscriptions.CountAsync(s => s.UserId == uid, ct) >= 50)
                throw ApiError.Conflict("subscription.limit", "Up to 50 subscriptions per account");
            var s = new Subscription { UserId = uid, Name = "", CreatedAt = time.GetUtcNow() };
            await ApplyAsync(s, req, uid, db, catalog, hooks.Value, ct);
            db.Subscriptions.Add(s);
            await db.SaveChangesAsync(ct);
            return Results.Created($"/api/subscriptions/{s.Id}", s);
        });

        g.MapPut("/subscriptions/{id:guid}", async (Guid id, SubscriptionRequest req, ClaimsPrincipal p, AppDb db, Catalog catalog,
                                                    IOptions<WebhookOptions> hooks, CancellationToken ct) =>
        {
            var uid = p.UserId();
            var s = await db.Subscriptions.FirstOrDefaultAsync(x => x.Id == id && x.UserId == uid, ct) ?? throw ApiError.NotFound("Subscription");
            await ApplyAsync(s, req, uid, db, catalog, hooks.Value, ct);
            await db.SaveChangesAsync(ct);
            return s;
        });

        g.MapDelete("/subscriptions/{id:guid}", async (Guid id, ClaimsPrincipal p, AppDb db, CancellationToken ct) =>
        {
            var uid = p.UserId();
            var s = await db.Subscriptions.FirstOrDefaultAsync(x => x.Id == id && x.UserId == uid, ct) ?? throw ApiError.NotFound("Subscription");
            db.Subscriptions.Remove(s);
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        });

        // What this subscription would have caught among current exposure.
        g.MapGet("/subscriptions/{id:guid}/preview", async (Guid id, ClaimsPrincipal p, AppDb db, CancellationToken ct) =>
        {
            var uid = p.UserId();
            var s = await db.Subscriptions.FirstOrDefaultAsync(x => x.Id == id && x.UserId == uid, ct) ?? throw ApiError.NotFound("Subscription");
            var matches = await db.Matches.Where(m => m.UserId == uid).ToListAsync(ct);
            var assets = await db.Assets.Where(a => a.UserId == uid).ToDictionaryAsync(a => a.Id, ct);
            var sites = await db.Sites.Where(x => x.UserId == uid).ToDictionaryAsync(x => x.Id, ct);
            var ids = matches.Select(m => m.VulnerabilityId).Distinct().ToList();
            var vulns = await db.Vulnerabilities.Where(v => ids.Contains(v.Id)).ToDictionaryAsync(v => v.Id, ct);
            var hits = matches
                .Select(m => new ExposureEvent("preview", uid, assets[m.AssetId], sites[assets[m.AssetId].SiteId], vulns[m.VulnerabilityId], m.Basis))
                .Where(e => Notifier.Passes(WithActive(s), e))
                .ToList();
            return new
            {
                matches = hits.Count,
                vulnerabilities = hits.Select(h => h.Vulnerability.Id).Distinct().Count(),
                sample = hits.OrderByDescending(h => Danger.SeverityRank(h.Vulnerability.Severity)).ThenBy(h => h.Vulnerability.Id)
                    .Select(h => new { id = h.Vulnerability.Id, title = h.Vulnerability.Title, asset = h.Asset.Label, site = h.Site.Name })
                    .DistinctBy(x => x.id).Take(5),
            };
        });

        g.MapPost("/subscriptions/{id:guid}/test", async (Guid id, ClaimsPrincipal p, AppDb db, Notifier notifier, TimeProvider time, CancellationToken ct) =>
        {
            var uid = p.UserId();
            var s = await db.Subscriptions.FirstOrDefaultAsync(x => x.Id == id && x.UserId == uid, ct) ?? throw ApiError.NotFound("Subscription");
            if (s.WebhookUrl == null) throw ApiError.Invalid("This subscription has no webhook");
            var d = await notifier.DeliverAsync(s, null, new { @event = "blast-radius.test", subscription = s.Name, sentAt = time.GetUtcNow() }, ct);
            return DeliveryView(d);
        });

        g.MapGet("/notifications", async (ClaimsPrincipal p, AppDb db, bool? unread, int? page, int? size, CancellationToken ct) =>
        {
            var uid = p.UserId();
            int pg = Math.Max(page ?? 0, 0), sz = Math.Clamp(size ?? 50, 1, 200);
            var q = db.Notifications.Where(n => n.UserId == uid && (unread != true || n.ReadAt == null));
            int total = await q.CountAsync(ct);
            var rows = await q.OrderByDescending(n => n.CreatedAt).ThenBy(n => n.VulnerabilityId).Skip(pg * sz).Take(sz).ToListAsync(ct);
            var subIds = rows.Select(r => r.SubscriptionId).Distinct().ToList();
            var subs = await db.Subscriptions.Where(s => subIds.Contains(s.Id)).ToDictionaryAsync(s => s.Id, s => s.Name, ct);
            var vulnIds = rows.Select(r => r.VulnerabilityId).Distinct().ToList();
            var vulns = await db.Vulnerabilities.Where(v => vulnIds.Contains(v.Id))
                .Select(v => new { v.Id, v.Severity, v.Kev, v.Epss }).ToDictionaryAsync(v => v.Id, ct);
            return new
            {
                unread = await db.Notifications.CountAsync(n => n.UserId == uid && n.ReadAt == null, ct),
                total, page = pg, size = sz,
                items = rows.Select(n => new
                {
                    n.Id, n.Reason, n.Title, n.Detail, n.VulnerabilityId, n.AssetId, n.CreatedAt, n.ReadAt,
                    subscription = subs.GetValueOrDefault(n.SubscriptionId, "(deleted)"),
                    severity = vulns.GetValueOrDefault(n.VulnerabilityId)?.Severity,
                    kev = vulns.GetValueOrDefault(n.VulnerabilityId)?.Kev ?? false,
                }),
            };
        });

        g.MapPost("/notifications/{id:guid}/read", async (Guid id, ClaimsPrincipal p, AppDb db, TimeProvider time, CancellationToken ct) =>
        {
            var n = await db.Notifications.FirstOrDefaultAsync(x => x.Id == id && x.UserId == p.UserId(), ct) ?? throw ApiError.NotFound("Notification");
            n.ReadAt ??= time.GetUtcNow();
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        });

        g.MapPost("/notifications/read-all", async (ClaimsPrincipal p, AppDb db, TimeProvider time, CancellationToken ct) =>
        {
            var uid = p.UserId();
            var now = time.GetUtcNow();
            var rows = await db.Notifications.Where(n => n.UserId == uid && n.ReadAt == null).ToListAsync(ct);
            foreach (var n in rows) n.ReadAt = now;
            await db.SaveChangesAsync(ct);
            return new { marked = rows.Count };
        });

        g.MapGet("/deliveries", async (ClaimsPrincipal p, AppDb db, CancellationToken ct) =>
            (await db.Deliveries.Where(d => d.UserId == p.UserId()).OrderByDescending(d => d.CreatedAt).Take(100).ToListAsync(ct))
            .Select(DeliveryView));
    }

    // previews ignore the Active flag: paused subscriptions can still be inspected
    private static Subscription WithActive(Subscription s) => new()
    {
        Id = s.Id, UserId = s.UserId, Name = s.Name, Scope = s.Scope, ScopeSiteId = s.ScopeSiteId, ScopeProductKey = s.ScopeProductKey,
        MinSeverity = s.MinSeverity, KevOnly = s.KevOnly, MinEpss = s.MinEpss, Keyword = s.Keyword, WebhookUrl = s.WebhookUrl,
        Active = true, CreatedAt = s.CreatedAt,
    };

    private static object DeliveryView(WebhookDelivery d) =>
        new { d.Id, d.SubscriptionId, d.NotificationId, d.Url, d.Outcome, d.HttpStatus, d.Error, d.DurationMs, d.CreatedAt };

    private static async Task ApplyAsync(Subscription s, SubscriptionRequest req, Guid uid, AppDb db, Catalog catalog,
                                         WebhookOptions hooks, CancellationToken ct)
    {
        var name = req.Name?.Trim();
        if (string.IsNullOrEmpty(name) || name.Length > 80) throw ApiError.Invalid("name must be 1-80 characters");
        var scope = req.Scope ?? "all";
        if (scope is not ("all" or "site" or "product")) throw ApiError.Invalid("scope must be all, site or product");
        s.ScopeSiteId = null;
        s.ScopeProductKey = null;
        if (scope == "site")
        {
            if (req.ScopeSiteId is not { } sid || !await db.Sites.AnyAsync(x => x.Id == sid && x.UserId == uid, ct))
                throw ApiError.Invalid("scopeSiteId must be one of your sites");
            s.ScopeSiteId = sid;
        }
        if (scope == "product")
        {
            if (req.ScopeProductKey == null || catalog.Product(req.ScopeProductKey) == null)
                throw ApiError.Invalid("scopeProductKey must be a catalog product");
            s.ScopeProductKey = req.ScopeProductKey;
        }
        var min = req.MinSeverity ?? "high";
        if (!Severities.Contains(min)) throw ApiError.Invalid("minSeverity must be none, low, medium, high or critical");
        var epss = req.MinEpss ?? 0;
        if (epss < 0 || epss > 1) throw ApiError.Invalid("minEpss must be between 0 and 1");
        var keyword = string.IsNullOrWhiteSpace(req.Keyword) ? null : req.Keyword.Trim();
        if (keyword?.Length > 60) throw ApiError.Invalid("keyword must be at most 60 characters");
        var hook = string.IsNullOrWhiteSpace(req.WebhookUrl) ? null : req.WebhookUrl.Trim();
        if (hook != null && WebhookGuard.CheckSyntax(hook, hooks.AllowPrivateTargets) is { } problem)
            throw new ApiError(422, "webhook.rejected", problem);

        s.Name = name;
        s.Scope = scope;
        s.MinSeverity = min;
        s.KevOnly = req.KevOnly ?? false;
        s.MinEpss = epss;
        s.Keyword = keyword;
        s.WebhookUrl = hook;
        s.Active = req.Active ?? true;
    }
}
