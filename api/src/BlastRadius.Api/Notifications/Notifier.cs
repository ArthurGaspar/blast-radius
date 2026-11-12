using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using BlastRadius.Api.Data;
using BlastRadius.Api.Matching;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace BlastRadius.Api.Notifications;

public sealed class WebhookOptions
{
    /// <summary>Lets webhooks reach localhost and private networks. For local development only.</summary>
    public bool AllowPrivateTargets { get; set; }
    public int TimeoutSeconds { get; set; } = 5;
}

/// <summary>A change ingestion found for one of a user's matches.</summary>
public sealed record ExposureEvent(string Reason, Guid UserId, Asset Asset, Site Site, Vulnerability Vulnerability, string Basis = "range");

public sealed class Notifier(AppDb db, IHttpClientFactory http, IOptions<WebhookOptions> options, TimeProvider time,
                             ILogger<Notifier> log)
{
    public static bool Passes(Subscription s, ExposureEvent e)
    {
        if (!s.Active) return false;
        // a source that lists no versions, or versions in another scheme, says nothing about this install
        if (e.Basis is "no-bounds" or "incomparable") return false;
        var v = e.Vulnerability;
        if (s.Scope == "site" && s.ScopeSiteId != e.Asset.SiteId) return false;
        if (s.Scope == "product" && s.ScopeProductKey != e.Asset.ProductKey) return false;
        if (Danger.SeverityRank(v.Severity) < Danger.SeverityRank(s.MinSeverity)) return false;
        if (s.KevOnly && !v.Kev) return false;
        if ((v.Epss ?? 0) < s.MinEpss) return false;
        if (!string.IsNullOrWhiteSpace(s.Keyword)
            && !(v.Title.Contains(s.Keyword, StringComparison.OrdinalIgnoreCase)
                 || v.Description.Contains(s.Keyword, StringComparison.OrdinalIgnoreCase)
                 || v.Id.Contains(s.Keyword, StringComparison.OrdinalIgnoreCase)))
            return false;
        return true;
    }

    public static (string Title, string Detail) Describe(ExposureEvent e)
    {
        var v = e.Vulnerability;
        string where = $"{e.Asset.Label} at {e.Site.Name}";
        return e.Reason switch
        {
            "kev_added" => ($"{v.Id} is being exploited in the wild",
                $"CISA added it to KEV{(v.KevAdded is { } d ? $" on {d:yyyy-MM-dd}" : "")}. It reaches {where}.{(v.KevDue is { } due ? $" Federal due date {due:yyyy-MM-dd}." : "")}"),
            "severity_raised" => ($"{v.Id} is now {v.Severity}", $"{v.Title} · reaches {where}"),
            _ => ($"{v.Id} reaches {where}", v.Title),
        };
    }

    /// <summary>Creates at most one notification per subscription, vulnerability and reason, then fires webhooks.</summary>
    public async Task<int> NotifyAsync(IReadOnlyList<ExposureEvent> events, CancellationToken ct)
    {
        if (events.Count == 0) return 0;
        var now = time.GetUtcNow();
        var userIds = events.Select(e => e.UserId).Distinct().ToList();
        var subs = await db.Subscriptions.Where(s => userIds.Contains(s.UserId) && s.Active).ToListAsync(ct);
        var subIds = subs.Select(s => s.Id).ToList();
        var seen = (await db.Notifications.Where(n => subIds.Contains(n.SubscriptionId))
                .Select(n => new { n.SubscriptionId, n.VulnerabilityId, n.Reason }).ToListAsync(ct))
            .Select(x => (x.SubscriptionId, x.VulnerabilityId, x.Reason)).ToHashSet();

        var created = new List<(Subscription Sub, Notification N, ExposureEvent E)>();
        foreach (var e in events)
            foreach (var s in subs.Where(s => s.UserId == e.UserId && Passes(s, e)))
            {
                if (!seen.Add((s.Id, e.Vulnerability.Id, e.Reason))) continue;
                var (title, detail) = Describe(e);
                var n = new Notification
                {
                    UserId = e.UserId, SubscriptionId = s.Id, VulnerabilityId = e.Vulnerability.Id, AssetId = e.Asset.Id,
                    Reason = e.Reason, Title = title, Detail = detail, CreatedAt = now,
                };
                db.Notifications.Add(n);
                created.Add((s, n, e));
            }
        await db.SaveChangesAsync(ct);

        foreach (var group in created.Where(c => c.Sub.WebhookUrl != null).GroupBy(c => c.Sub.Id))
        {
            var sub = group.First().Sub;
            var payload = new
            {
                @event = "blast-radius.notifications",
                subscription = sub.Name,
                sentAt = now,
                notifications = group.Select(c => new
                {
                    id = c.N.Id, reason = c.N.Reason, title = c.N.Title, detail = c.N.Detail,
                    vulnerability = new
                    {
                        id = c.E.Vulnerability.Id, severity = c.E.Vulnerability.Severity, cvss = c.E.Vulnerability.CvssScore,
                        kev = c.E.Vulnerability.Kev, epss = c.E.Vulnerability.Epss,
                    },
                    asset = new { label = c.E.Asset.Label, version = c.E.Asset.Version, site = c.E.Site.Name },
                }),
            };
            await DeliverAsync(sub, group.First().N.Id, payload, ct);
        }
        return created.Count;
    }

    public async Task<WebhookDelivery> DeliverAsync(Subscription sub, Guid? notificationId, object payload, CancellationToken ct)
    {
        var d = new WebhookDelivery
        {
            UserId = sub.UserId, SubscriptionId = sub.Id, NotificationId = notificationId, Url = sub.WebhookUrl!,
            Outcome = "failed", CreatedAt = time.GetUtcNow(),
        };
        var sw = Stopwatch.StartNew();
        try
        {
            var problem = await WebhookGuard.CheckAsync(sub.WebhookUrl!, options.Value.AllowPrivateTargets, ct);
            if (problem != null)
            {
                d.Outcome = "blocked";
                d.Error = problem;
            }
            else
            {
                var client = http.CreateClient("webhooks");
                client.Timeout = TimeSpan.FromSeconds(options.Value.TimeoutSeconds);
                using var res = await client.PostAsJsonAsync(sub.WebhookUrl, payload, ct);
                d.HttpStatus = (int)res.StatusCode;
                d.Outcome = res.IsSuccessStatusCode ? "delivered" : "failed";
                if (!res.IsSuccessStatusCode) d.Error = $"HTTP {(int)res.StatusCode}";
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or SocketException)
        {
            d.Error = ex is TaskCanceledException ? "Timed out" : ex.Message;
            log.LogInformation("Webhook to {Url} failed: {Error}", sub.WebhookUrl, d.Error);
        }
        d.DurationMs = (int)sw.ElapsedMilliseconds;
        db.Deliveries.Add(d);
        await db.SaveChangesAsync(ct);
        return d;
    }
}

/// <summary>
/// Keeps webhooks from being aimed at the server's own network (SSRF): only http(s), and the resolved addresses
/// must be public. Checked when a subscription is saved and again, after DNS resolution, at send time.
/// </summary>
public static class WebhookGuard
{
    public static string? CheckSyntax(string url, bool allowPrivate)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != "https" && u.Scheme != "http"))
            return "Webhook URL must be an absolute http(s) URL";
        if (u.Scheme == "http" && !allowPrivate) return "Webhook URL must use https";
        if (!allowPrivate && (u.IsLoopback || u.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)))
            return "Webhook URL can't point at this server";
        if (!allowPrivate && IPAddress.TryParse(u.Host, out var ip) && IsPrivate(ip))
            return "Webhook URL can't point at a private or reserved address";
        return null;
    }

    public static async Task<string?> CheckAsync(string url, bool allowPrivate, CancellationToken ct)
    {
        var syntax = CheckSyntax(url, allowPrivate);
        if (syntax != null || allowPrivate) return syntax;
        var host = new Uri(url).Host;
        IPAddress[] addresses = IPAddress.TryParse(host, out var literal) ? [literal] : await Dns.GetHostAddressesAsync(host, ct);
        return addresses.Any(IsPrivate) ? "Webhook host resolves to a private or reserved address" : null;
    }

    public static bool IsPrivate(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return true;
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal || ip.IsIPv6Multicast;
        var b = ip.GetAddressBytes();
        return b[0] switch
        {
            0 or 10 or 127 => true,
            100 => b[1] >= 64 && b[1] <= 127,          // carrier-grade NAT
            169 => b[1] == 254,                          // link-local, cloud metadata (169.254.169.254)
            172 => b[1] >= 16 && b[1] <= 31,
            192 => b[1] == 168 || (b[1] == 0 && b[2] == 0),
            198 => b[1] == 18 || b[1] == 19,             // benchmarking
            >= 224 => true,                              // multicast and reserved
            _ => false,
        };
    }
}
