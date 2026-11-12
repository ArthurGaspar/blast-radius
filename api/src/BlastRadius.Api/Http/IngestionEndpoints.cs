using BlastRadius.Api.Data;
using BlastRadius.Api.Ingestion;
using Microsoft.EntityFrameworkCore;

namespace BlastRadius.Api.Http;

public static class IngestionEndpoints
{
    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/api/ingestion").RequireAuthorization();

        g.MapGet("/status", async (AppDb db, IngestionCoordinator coordinator, CancellationToken ct) =>
        {
            var sources = await db.Vulnerabilities.Where(v => !v.Withdrawn).Select(v => v.Sources).ToListAsync(ct);
            var latest = await db.IngestionRuns.OrderByDescending(r => r.StartedAt).Take(400).ToListAsync(ct);
            var lastBatch = latest.FirstOrDefault()?.BatchId;
            return new
            {
                running = coordinator.Running,
                nextScheduled = coordinator.NextScheduled,
                last = coordinator.Last,
                totals = new
                {
                    vulnerabilities = sources.Count,
                    nvdOnly = sources.Count(s => s.SequenceEqual(["nvd"])),
                    ghsaOnly = sources.Count(s => s.SequenceEqual(["ghsa"])),
                    both = sources.Count(s => s.Count == 2),
                    kev = await db.Vulnerabilities.CountAsync(v => v.Kev, ct),
                    withEpss = await db.Vulnerabilities.CountAsync(v => v.Epss != null, ct),
                    aliases = await db.Aliases.CountAsync(ct),
                    withdrawn = await db.Vulnerabilities.CountAsync(v => v.Withdrawn, ct),
                },
                // the most recent run for each source and target
                targets = latest.GroupBy(r => (r.Source, r.Target)).Select(grp => grp.First())
                    .OrderBy(r => r.Source).ThenBy(r => r.Target)
                    .Select(r => new
                    {
                        r.Source, r.Target, r.StartedAt, r.FinishedAt, r.Fetched, r.Created, r.Updated, r.Linked, r.Merged, r.Unchanged,
                        r.Error, current = r.BatchId == lastBatch,
                    }),
            };
        });

        g.MapGet("/runs", async (AppDb db, int? limit, CancellationToken ct) =>
            (await db.IngestionRuns.OrderByDescending(r => r.StartedAt).Take(Math.Clamp(limit ?? 100, 1, 500)).ToListAsync(ct)));

        // ?wait=true runs inline and returns the summary (tests, CLI); otherwise it starts in the background.
        g.MapPost("/run", async (bool? wait, IngestionCoordinator coordinator, IHostApplicationLifetime life, CancellationToken ct) =>
        {
            var (result, retry) = coordinator.CanStartManual();
            if (result == IngestionCoordinator.StartResult.Busy) throw ApiError.Conflict("ingestion.running", "A run is already in progress");
            if (result == IngestionCoordinator.StartResult.CoolingDown)
                throw new ApiError(429, "ingestion.cooldown", $"Manual runs are limited; try again in {Math.Ceiling(retry!.Value.TotalMinutes)} min");
            if (wait == true)
            {
                var summary = await coordinator.RunAsync("manual", ct);
                return summary == null ? throw ApiError.Conflict("ingestion.running", "A run is already in progress") : Results.Ok(summary);
            }
            _ = Task.Run(() => coordinator.RunAsync("manual", life.ApplicationStopping));
            return Results.Accepted("/api/ingestion/status", new { started = true });
        });
    }
}
