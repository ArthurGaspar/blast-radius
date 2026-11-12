using System.Text.Json;
using System.Text.Json.Serialization;
using BlastRadius.Api.Data;
using Microsoft.EntityFrameworkCore;

namespace BlastRadius.Api.Ingestion;

/// <summary>
/// <c>dotnet run -- snapshot &lt;file&gt;</c>: runs one ingestion against the live sources and writes the deduplicated
/// catalog as JSON. The GitHub Pages build starts from this file and refreshes it from the browser.
/// </summary>
public static class SnapshotCommand
{
    public static async Task<int> RunAsync(IServiceProvider services, string output, CancellationToken ct)
    {
        var coordinator = services.GetRequiredService<IngestionCoordinator>();
        var summary = await coordinator.RunAsync("manual", ct);
        if (summary == null) return 1;
        Console.WriteLine($"fetched {summary.Fetched}, created {summary.Created}, updated {summary.Updated}, linked {summary.Linked}, merged {summary.Merged}, " +
                          $"KEV {summary.KevMarked}, EPSS {summary.EpssScored}, errors {summary.Errors.Count}");
        foreach (var e in summary.Errors) Console.Error.WriteLine("  " + e);

        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDb>();
        var vulns = await db.Vulnerabilities.OrderBy(v => v.Id).ToListAsync(ct);
        // NVD also lists products that bundle a library (Log4Shell names hundreds); the browser only needs watched ones
        var catalog = services.GetRequiredService<Catalog>();
        var watched = catalog.Data.Products.SelectMany(catalog.IdentityKeys).ToHashSet();
        var runs = await db.IngestionRuns.Where(r => r.BatchId == summary.BatchId).OrderBy(r => r.Source).ThenBy(r => r.Target).ToListAsync(ct);
        var doc = new
        {
            generatedAt = summary.FinishedAt,
            summary,
            runs = runs.Select(r => new { r.Source, r.Target, r.Fetched, r.Created, r.Updated, r.Linked, r.Merged, r.Error }),
            vulnerabilities = vulns.Select(v => new
            {
                v.Id, v.Title, v.TitleSource,
                description = v.Description.Length > 900 ? v.Description[..899] + "…" : v.Description,
                v.Severity, cvss = v.CvssScore, v.CvssVector, v.CvssSource, v.Published, v.Modified, v.Withdrawn,
                v.Kev, v.KevAdded, v.KevDue, v.KevRansomware, v.KevAction, v.Epss, v.EpssPercentile,
                v.Sources, v.Aliases, v.Cwes, ranges = v.Ranges.Where(r => watched.Contains(r.IdentityKey)),
                references = v.References.Take(8),
            }),
        };
        var json = JsonSerializer.Serialize(doc, new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        });
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
        await File.WriteAllTextAsync(output, json, ct);
        Console.WriteLine($"wrote {vulns.Count} vulnerabilities to {output} ({json.Length / 1024} KB)");
        return summary.Errors.Count == 0 ? 0 : 2;
    }
}
