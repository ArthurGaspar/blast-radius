using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using BlastRadius.Api;
using BlastRadius.Api.Data;
using BlastRadius.Api.Exposure;
using BlastRadius.Api.Http;
using BlastRadius.Api.Ingestion;
using BlastRadius.Api.Notifications;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<Catalog>();
builder.Services.Configure<JwtOptions>(config.GetSection("Jwt"));
builder.Services.Configure<SourceOptions>(config.GetSection("Sources"));
builder.Services.Configure<IngestionOptions>(config.GetSection("Ingestion"));
builder.Services.Configure<WebhookOptions>(config.GetSection("Webhooks"));
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter(System.Text.Json.JsonNamingPolicy.CamelCase)));

// Database: PostgreSQL in deployments, SQLite for a zero-install local run and for tests.
var provider = config["Database:Provider"] ?? "sqlite";
var connection = config.GetConnectionString("Default") ?? "Data Source=blast-radius.db";
builder.Services.AddDbContext<AppDb>(o =>
{
    if (provider == "postgres") o.UseNpgsql(connection);
    else o.UseSqlite(connection);
});

// Sources. With Sources:FixtureDir set, every source reads recorded responses instead of the network.
var fixtures = new FixtureState { Dir = config["Sources:FixtureDir"] };
builder.Services.AddSingleton(fixtures);
void Source<T>() where T : class
{
    var b = builder.Services.AddHttpClient<T>(c => c.Timeout = TimeSpan.FromSeconds(60));
    if (fixtures.Dir != null) b.ConfigurePrimaryHttpMessageHandler(sp => new FixtureHandler(sp.GetRequiredService<FixtureState>()));
}
Source<NvdClient>();
Source<GhsaClient>();
Source<KevClient>();
Source<EpssClient>();
builder.Services.AddHttpClient("webhooks").ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });

builder.Services.AddScoped<ExposureService>();
builder.Services.AddScoped<Notifier>();
builder.Services.AddScoped<IngestionService>();
builder.Services.AddSingleton<IngestionCoordinator>();
builder.Services.AddHostedService<IngestionScheduler>();

var jwt = config.GetSection("Jwt").Get<JwtOptions>() ?? new JwtOptions();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
{
    o.MapInboundClaims = true;
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidIssuer = jwt.Issuer,
        ValidAudience = jwt.Issuer,
        IssuerSigningKey = jwt.Key(),
        ClockSkew = TimeSpan.FromSeconds(30),
    };
});
builder.Services.AddAuthorization();

builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = 429;
    o.AddPolicy("auth", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = config.GetValue("RateLimits:AuthPerMinute", 20), Window = TimeSpan.FromMinutes(1) }));
});

var origins = config.GetSection("Cors:Origins").Get<string[]>() ?? ["http://localhost:5173"];
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.WithOrigins(origins).AllowAnyHeader().WithMethods("GET", "POST", "PUT", "DELETE")));
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    if (provider == "postgres") db.Database.Migrate();
    else db.Database.EnsureCreated();
}

if (args is ["snapshot", var output, ..])
{
    Environment.ExitCode = await SnapshotCommand.RunAsync(app.Services, output, CancellationToken.None);
    return;
}

app.UseExceptionHandler();
app.UseApiErrors();
app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapOpenApi();
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
AuthEndpoints.Map(app);
InventoryEndpoints.Map(app);
IntelEndpoints.Map(app);
AlertEndpoints.Map(app);
IngestionEndpoints.Map(app);

app.Run();

public partial class Program;
