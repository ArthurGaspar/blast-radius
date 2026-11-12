using System.Text.Json;
using BlastRadius.Api.Matching;

namespace BlastRadius.Api;

public sealed record GhsaIdentity(string Ecosystem, string Package);
public sealed record CpeIdentity(string Vendor, string Product);
public sealed record Product(string Key, string Name, string Category, string Description, GhsaIdentity? Ghsa, CpeIdentity? Cpe);
public sealed record SitePreset(string Key, string Label, string Country, double Lat, double Lon);
public sealed record DangerLevel(string Code, string Label, double Min);
public sealed record CatalogData(int Version, List<string> Severities, List<DangerLevel> DangerLevels, List<Product> Products, List<SitePreset> SitePresets);

/// <summary>shared/catalog.json: the products Blast Radius knows how to watch, and map presets for sites.</summary>
public sealed class Catalog
{
    public CatalogData Data { get; }
    private readonly Dictionary<string, Product> _products;

    public Catalog()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "shared", "catalog.json");
        Data = JsonSerializer.Deserialize<CatalogData>(File.ReadAllText(path), new JsonSerializerOptions(JsonSerializerDefaults.Web))
               ?? throw new InvalidOperationException("catalog.json is empty");
        _products = Data.Products.ToDictionary(p => p.Key);
    }

    public Product? Product(string key) => _products.GetValueOrDefault(key);

    public IEnumerable<string> IdentityKeys(Product p)
    {
        if (p.Ghsa != null) yield return Identity.PackageKey(p.Ghsa.Ecosystem, p.Ghsa.Package);
        if (p.Cpe != null) yield return Identity.CpeKey(p.Cpe.Vendor, p.Cpe.Product);
    }
}
