using System.Text.Json;
using BlastRadius.Api.Matching;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace BlastRadius.Api.Data;

public sealed class AppDb(DbContextOptions<AppDb> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Site> Sites => Set<Site>();
    public DbSet<Asset> Assets => Set<Asset>();
    public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();
    public DbSet<VulnerabilityAlias> Aliases => Set<VulnerabilityAlias>();
    public DbSet<Match> Matches => Set<Match>();
    public DbSet<Subscription> Subscriptions => Set<Subscription>();
    public DbSet<Notification> Notifications => Set<Notification>();
    public DbSet<WebhookDelivery> Deliveries => Set<WebhookDelivery>();
    public DbSet<IngestionRun> IngestionRuns => Set<IngestionRun>();
    public DbSet<SyncState> SyncStates => Set<SyncState>();

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    // Lists are stored as JSON text so the same model runs on PostgreSQL and SQLite.
    private static ValueConverter<List<T>, string> JsonList<T>() => new(
        v => JsonSerializer.Serialize(v, Json),
        v => JsonSerializer.Deserialize<List<T>>(v, Json) ?? new List<T>());

    private static ValueComparer<List<T>> ListComparer<T>() => new(
        (a, b) => JsonSerializer.Serialize(a, Json) == JsonSerializer.Serialize(b, Json),
        v => JsonSerializer.Serialize(v, Json).GetHashCode(),
        v => JsonSerializer.Deserialize<List<T>>(JsonSerializer.Serialize(v, Json), Json)!);

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>(e =>
        {
            e.HasIndex(x => x.Username).IsUnique();
            e.Property(x => x.Username).HasMaxLength(32);
            e.Property(x => x.DisplayName).HasMaxLength(60);
        });
        b.Entity<Site>(e =>
        {
            e.HasIndex(x => x.UserId);
            e.Property(x => x.Name).HasMaxLength(80);
        });
        b.Entity<Asset>(e =>
        {
            e.HasIndex(x => x.UserId);
            e.HasIndex(x => x.SiteId);
            e.Property(x => x.Label).HasMaxLength(80);
        });
        b.Entity<Vulnerability>(e =>
        {
            e.Property(x => x.Id).HasMaxLength(40);
            e.Property(x => x.Title).HasMaxLength(300);
            e.Property(x => x.Sources).HasConversion(JsonList<string>(), ListComparer<string>());
            e.Property(x => x.Aliases).HasConversion(JsonList<string>(), ListComparer<string>());
            e.Property(x => x.Cwes).HasConversion(JsonList<string>(), ListComparer<string>());
            e.Property(x => x.Ranges).HasConversion(JsonList<AffectedRange>(), ListComparer<AffectedRange>());
            e.Property(x => x.References).HasConversion(JsonList<Reference>(), ListComparer<Reference>());
            e.HasIndex(x => x.Modified);
        });
        b.Entity<VulnerabilityAlias>(e =>
        {
            e.HasKey(x => x.Alias);
            e.Property(x => x.Alias).HasMaxLength(40);
            e.HasIndex(x => x.VulnerabilityId);
        });
        b.Entity<Match>(e =>
        {
            e.HasIndex(x => new { x.AssetId, x.VulnerabilityId }).IsUnique();
            e.HasIndex(x => x.UserId);
        });
        b.Entity<Subscription>(e => e.HasIndex(x => x.UserId));
        b.Entity<Notification>(e =>
        {
            // one notification per subscription, vulnerability and reason
            e.HasIndex(x => new { x.SubscriptionId, x.VulnerabilityId, x.Reason }).IsUnique();
            e.HasIndex(x => new { x.UserId, x.CreatedAt });
        });
        b.Entity<WebhookDelivery>(e => e.HasIndex(x => new { x.UserId, x.CreatedAt }));
        b.Entity<IngestionRun>(e => e.HasIndex(x => x.StartedAt));
        b.Entity<SyncState>(e => e.HasKey(x => x.Key));

        // SQLite has no timestamp type and EF can't ORDER BY DateTimeOffset there; store UTC ticks instead.
        if (Database.IsSqlite())
        {
            foreach (var entity in b.Model.GetEntityTypes())
                foreach (var prop in entity.GetProperties().Where(p => p.ClrType == typeof(DateTimeOffset) || p.ClrType == typeof(DateTimeOffset?)))
                    prop.SetValueConverter(new DateTimeOffsetToBinaryConverter());
        }
    }
}
