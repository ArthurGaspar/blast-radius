using Microsoft.Extensions.Options;

namespace BlastRadius.Api.Ingestion;

public sealed class IngestionOptions
{
    /// <summary>Run on startup and then every <see cref="IntervalHours"/>.</summary>
    public bool Scheduled { get; set; } = true;
    public double IntervalHours { get; set; } = 6;
    /// <summary>Minimum gap between manual runs, to stay polite with the upstream APIs.</summary>
    public double ManualCooldownMinutes { get; set; } = 10;
}

/// <summary>Serializes ingestion runs (scheduled or manual) and remembers the last result.</summary>
public sealed class IngestionCoordinator(IServiceScopeFactory scopes, IOptions<IngestionOptions> options, TimeProvider time,
                                         ILogger<IngestionCoordinator> log)
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private DateTimeOffset? _lastManual;

    public bool Running => _gate.CurrentCount == 0;
    public IngestionSummary? Last { get; private set; }
    public DateTimeOffset? NextScheduled { get; set; }

    public enum StartResult { Started, Busy, CoolingDown }

    public (StartResult Result, TimeSpan? RetryAfter) CanStartManual()
    {
        if (Running) return (StartResult.Busy, null);
        var cooldown = TimeSpan.FromMinutes(options.Value.ManualCooldownMinutes);
        if (_lastManual is { } last && time.GetUtcNow() - last < cooldown)
            return (StartResult.CoolingDown, cooldown - (time.GetUtcNow() - last));
        return (StartResult.Started, null);
    }

    public async Task<IngestionSummary?> RunAsync(string trigger, CancellationToken ct)
    {
        if (!await _gate.WaitAsync(0, ct)) return null;
        try
        {
            if (trigger == "manual") _lastManual = time.GetUtcNow();
            using var scope = scopes.CreateScope();
            var service = scope.ServiceProvider.GetRequiredService<IngestionService>();
            Last = await service.RunAsync(trigger, ct);
            return Last;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogError(ex, "Ingestion failed");
            throw;
        }
        finally
        {
            _gate.Release();
        }
    }
}

public sealed class IngestionScheduler(IngestionCoordinator coordinator, IOptions<IngestionOptions> options, TimeProvider time,
                                       ILogger<IngestionScheduler> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Scheduled) return;
        var interval = TimeSpan.FromHours(options.Value.IntervalHours);
        await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await coordinator.RunAsync("schedule", stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                log.LogError(ex, "Scheduled ingestion failed; retrying at the next interval");
            }
            coordinator.NextScheduled = time.GetUtcNow() + interval;
            await Task.Delay(interval, stoppingToken);
        }
    }
}
