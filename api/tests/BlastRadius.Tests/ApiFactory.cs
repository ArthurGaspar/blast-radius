using BlastRadius.Api.Ingestion;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace BlastRadius.Tests;

/// <summary>
/// The real app on an in-memory SQLite database (or PostgreSQL when a connection string is given),
/// with every external source answered from shared/fixtures.
/// </summary>
public sealed class ApiFactory : WebApplicationFactory<Program>
{
    public static string Fixtures(string day) => Path.Combine(AppContext.BaseDirectory, "shared", "fixtures", day);

    private readonly SqliteConnection? _keepAlive;
    private readonly string _provider;
    private readonly string _connection;

    public ApiFactory(string? postgres = null)
    {
        if (postgres != null)
        {
            _provider = "postgres";
            _connection = postgres;
        }
        else
        {
            _provider = "sqlite";
            _connection = $"Data Source=file:br-{Guid.NewGuid():N}?mode=memory&cache=shared";
            _keepAlive = new SqliteConnection(_connection);
            _keepAlive.Open(); // the in-memory database lives as long as one connection is open
        }
    }

    public void UseFixtures(string day) => Services.GetRequiredService<FixtureState>().Dir = Fixtures(day);

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("Database:Provider", _provider);
        builder.UseSetting("ConnectionStrings:Default", _connection);
        builder.UseSetting("Sources:FixtureDir", Fixtures("day1"));
        builder.UseSetting("Ingestion:Scheduled", "false");
        builder.UseSetting("Ingestion:ManualCooldownMinutes", "0");
        builder.UseSetting("RateLimits:AuthPerMinute", "1000");
        builder.UseSetting("Jwt:Secret", "test-secret-test-secret-test-secret-test");
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing) _keepAlive?.Dispose();
    }
}
