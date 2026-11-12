using BlastRadius.Api.Matching;

namespace BlastRadius.Api.Data;

public sealed class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Username { get; set; }
    public required string DisplayName { get; set; }
    public string PasswordHash { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>A place where software runs: an office, a data center, a cloud region. Drawn on the map.</summary>
public sealed class Site
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public required string Name { get; set; }
    public required string Kind { get; set; } // office | datacenter | cloud
    public string? PresetKey { get; set; }
    public double Lat { get; set; }
    public double Lon { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>A piece of software at a site. Identity comes from the catalog or is entered by hand.</summary>
public sealed class Asset
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public Guid SiteId { get; set; }
    public string? ProductKey { get; set; }
    public required string Label { get; set; }
    public string? Ecosystem { get; set; }
    public string? Package { get; set; }
    public string? CpeVendor { get; set; }
    public string? CpeProduct { get; set; }
    public string Version { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }

    public IEnumerable<string> IdentityKeys()
    {
        if (Ecosystem != null && Package != null) yield return Identity.PackageKey(Ecosystem, Package);
        if (CpeVendor != null && CpeProduct != null) yield return Identity.CpeKey(CpeVendor, CpeProduct);
    }
}

public sealed class Reference
{
    public required string Url { get; set; }
    public string? Source { get; set; }
}

/// <summary>
/// One vulnerability after deduplication. <see cref="Id"/> is the CVE when one is known, otherwise the GHSA id;
/// every identifier ever seen for it is in <see cref="Aliases"/> (and the alias table, which enforces uniqueness).
/// </summary>
public sealed class Vulnerability
{
    public required string Id { get; set; }
    public string Title { get; set; } = "";
    public string TitleSource { get; set; } = "derived"; // ghsa | derived
    public string Description { get; set; } = "";
    public string Severity { get; set; } = "none";
    public double? CvssScore { get; set; }
    public string? CvssVector { get; set; }
    public string? CvssSource { get; set; }
    public DateTimeOffset? Published { get; set; }
    public DateTimeOffset? Modified { get; set; }
    public bool Withdrawn { get; set; }
    public bool Kev { get; set; }
    public DateOnly? KevAdded { get; set; }
    public DateOnly? KevDue { get; set; }
    public bool KevRansomware { get; set; }
    public string? KevAction { get; set; }
    public double? Epss { get; set; }
    public double? EpssPercentile { get; set; }
    public List<string> Sources { get; set; } = [];
    public List<string> Aliases { get; set; } = [];
    public List<string> Cwes { get; set; } = [];
    public List<AffectedRange> Ranges { get; set; } = [];
    public List<Reference> References { get; set; } = [];
    /// <summary>"|key|key|" of every identity in <see cref="Ranges"/>, for LIKE filtering.</summary>
    public string IdentityIndex { get; set; } = "|";
    public DateTimeOffset IngestedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class VulnerabilityAlias
{
    public required string Alias { get; set; }
    public required string VulnerabilityId { get; set; }
}

/// <summary>Materialized exposure: this asset is (possibly) affected by this vulnerability.</summary>
public sealed class Match
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public Guid AssetId { get; set; }
    public required string VulnerabilityId { get; set; }
    public required string Status { get; set; } // affected | possible
    /// <summary>
    /// What the verdict rests on: "range" (the version is inside a published range), "no-version" (the asset's version
    /// is unknown), "no-bounds" (the source names the product without versions) or "incomparable" (different schemes).
    /// Only the first two raise alerts.
    /// </summary>
    public string Basis { get; set; } = "range";
    public required string Explanation { get; set; }
    public string? FixedIn { get; set; }
    public double Score { get; set; }
    public DateTimeOffset FirstSeen { get; set; }
}

public sealed class Subscription
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public required string Name { get; set; }
    public string Scope { get; set; } = "all"; // all | site | product
    public Guid? ScopeSiteId { get; set; }
    public string? ScopeProductKey { get; set; }
    public string MinSeverity { get; set; } = "high";
    public bool KevOnly { get; set; }
    public double MinEpss { get; set; }
    public string? Keyword { get; set; }
    public string? WebhookUrl { get; set; }
    public bool Active { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class Notification
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public Guid SubscriptionId { get; set; }
    public required string VulnerabilityId { get; set; }
    public Guid? AssetId { get; set; }
    public required string Reason { get; set; } // new_exposure | kev_added | severity_raised
    public required string Title { get; set; }
    public required string Detail { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ReadAt { get; set; }
}

public sealed class WebhookDelivery
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public Guid SubscriptionId { get; set; }
    public Guid? NotificationId { get; set; }
    public required string Url { get; set; }
    public required string Outcome { get; set; } // delivered | failed | blocked
    public int? HttpStatus { get; set; }
    public string? Error { get; set; }
    public int DurationMs { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class IngestionRun
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid BatchId { get; set; }
    public required string Source { get; set; } // nvd | ghsa | kev | epss
    public required string Target { get; set; }
    public required string Trigger { get; set; } // schedule | manual
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }
    public int Fetched { get; set; }
    public int Created { get; set; }
    public int Updated { get; set; }
    public int Merged { get; set; }
    /// <summary>Advisories that joined a record first created by the other source (cross-source duplicates).</summary>
    public int Linked { get; set; }
    public int Unchanged { get; set; }
    public string? Error { get; set; }
}

/// <summary>High-water marks for incremental fetches, keyed like "nvd:cpe:ollama:ollama".</summary>
public sealed class SyncState
{
    public required string Key { get; set; }
    public DateTimeOffset LastSuccess { get; set; }
}
