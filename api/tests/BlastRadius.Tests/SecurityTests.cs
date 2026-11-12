using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Nodes;
using BlastRadius.Api.Http;
using BlastRadius.Api.Notifications;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace BlastRadius.Tests;

public class SecurityTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("10.2.3.4", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.168.1.1", true)]
    [InlineData("169.254.169.254", true)]
    [InlineData("100.64.0.1", true)]
    [InlineData("0.0.0.0", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("::1", true)]
    [InlineData("fd00::1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("::ffff:127.0.0.1", true)]
    [InlineData("2606:4700::1111", false)]
    public void Classifies_addresses(string ip, bool isPrivate) =>
        Assert.Equal(isPrivate, WebhookGuard.IsPrivate(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("https://hooks.example.com/x", null)]
    [InlineData("http://hooks.example.com/x", "https")]
    [InlineData("ftp://hooks.example.com/x", "http(s)")]
    [InlineData("https://localhost/x", "this server")]
    [InlineData("https://[::1]/x", "this server")]
    [InlineData("https://10.0.0.5/x", "private")]
    public void Checks_webhook_urls(string url, string? problem)
    {
        var result = WebhookGuard.CheckSyntax(url, allowPrivate: false);
        if (problem == null) Assert.Null(result);
        else Assert.Contains(problem, result);
    }

    private static async Task<HttpClient> SignedInAsync(HttpClient client, string user)
    {
        var res = await client.PostAsJsonAsync("/api/auth/register", new { username = user, displayName = user, password = "correct-horse-1" }, Ct);
        var token = (await res.Content.ReadFromJsonAsync<JsonObject>(Ct))!["token"]!.GetValue<string>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    [Fact]
    public async Task Rejects_expired_and_forged_tokens()
    {
        await using var factory = new ApiFactory();
        var client = factory.CreateClient();
        await SignedInAsync(client, "dana");
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/me", Ct)).StatusCode);
        var sub = (await (await client.GetAsync("/api/me", Ct)).Content.ReadFromJsonAsync<JsonObject>(Ct))!["user"]!["id"]!.GetValue<string>();

        string Make(string secret, DateTime notBefore, DateTime expires) => new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            "blast-radius", "blast-radius", [new Claim(JwtRegisteredClaimNames.Sub, sub)], notBefore, expires,
            new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)), SecurityAlgorithms.HmacSha256)));

        var now = DateTime.UtcNow;
        foreach (var token in new[]
                 {
                     Make("test-secret-test-secret-test-secret-test", now.AddHours(-13), now.AddHours(-1)), // expired
                     Make("someone-elses-secret-someone-elses-secret", now, now.AddHours(1)),           // forged
                 })
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, "/api/me");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(req, Ct)).StatusCode);
        }
    }

    [Fact]
    public async Task Rate_limits_sign_in_attempts()
    {
        await using var factory = new ApiFactory();
        var client = factory.WithWebHostBuilder(b => b.UseSetting("RateLimits:AuthPerMinute", "3")).CreateClient();
        var codes = new List<HttpStatusCode>();
        for (int i = 0; i < 5; i++)
            codes.Add((await client.PostAsJsonAsync("/api/auth/login", new { username = "nobody", password = "guess-guess-1" }, Ct)).StatusCode);
        Assert.Equal([HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized,
                      HttpStatusCode.TooManyRequests, HttpStatusCode.TooManyRequests], codes);
    }

    [Fact]
    public async Task Manual_ingestion_has_a_cooldown()
    {
        await using var factory = new ApiFactory();
        var client = factory.WithWebHostBuilder(b => b.UseSetting("Ingestion:ManualCooldownMinutes", "10")).CreateClient();
        await SignedInAsync(client, "erin");
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/api/ingestion/run?wait=true", null, Ct)).StatusCode);
        var second = await client.PostAsync("/api/ingestion/run?wait=true", null, Ct);
        Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
        Assert.Equal("ingestion.cooldown", (await second.Content.ReadFromJsonAsync<JsonObject>(Ct))!["code"]!.GetValue<string>());
    }

    /// <summary>Captures webhook calls instead of sending them.</summary>
    private sealed class Receiver(HttpStatusCode status) : HttpMessageHandler
    {
        public List<JsonObject> Bodies { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Bodies.Add(JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!.AsObject());
            return new HttpResponseMessage(status);
        }
    }

    [Theory]
    [InlineData(HttpStatusCode.OK, "delivered")]
    [InlineData(HttpStatusCode.InternalServerError, "failed")]
    public async Task Delivers_notifications_to_webhooks(HttpStatusCode answer, string outcome)
    {
        var receiver = new Receiver(answer);
        await using var factory = new ApiFactory();
        var client = factory.WithWebHostBuilder(b =>
        {
            // the receiver stands in for the network, so the address check would only see a fake host
            b.UseSetting("Webhooks:AllowPrivateTargets", "true");
            b.ConfigureTestServices(s => s.AddHttpClient("webhooks").ConfigurePrimaryHttpMessageHandler(() => receiver));
        }).CreateClient();
        await SignedInAsync(client, "frankie");

        var site = await (await client.PostAsJsonAsync("/api/sites", new { name = "Lab", kind = "office", presetKey = "tokyo" }, Ct)).Content.ReadFromJsonAsync<JsonObject>(Ct);
        await client.PostAsJsonAsync("/api/assets", new { siteId = site!["id"]!.GetValue<string>(), productKey = "ollama", version = "0.1.30" }, Ct);
        var sub = await client.PostAsJsonAsync("/api/subscriptions", new { name = "Ops channel", scope = "all", minSeverity = "critical", webhookUrl = "https://hooks.test/blast" }, Ct);
        Assert.Equal(HttpStatusCode.Created, sub.StatusCode);
        await client.PostAsync("/api/ingestion/run?wait=true", null, Ct);

        var body = Assert.Single(receiver.Bodies);
        Assert.Equal("Ops channel", body["subscription"]!.GetValue<string>());
        var notes = body["notifications"]!.AsArray();
        Assert.NotEmpty(notes);
        Assert.All(notes, n => Assert.Equal("critical", n!["vulnerability"]!["severity"]!.GetValue<string>()));

        var deliveries = (await client.GetFromJsonAsync<JsonArray>("/api/deliveries", Ct))!;
        Assert.Equal(outcome, Assert.Single(deliveries)!["outcome"]!.GetValue<string>());
    }

    [Fact]
    public async Task Blocks_webhooks_that_resolve_to_private_addresses_at_send_time()
    {
        var receiver = new Receiver(HttpStatusCode.OK);
        await using var factory = new ApiFactory();
        var client = factory.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
            s.AddHttpClient("webhooks").ConfigurePrimaryHttpMessageHandler(() => receiver))).CreateClient();
        await SignedInAsync(client, "gray");
        // passes the syntax check (a hostname), but "localtest.me" resolves to 127.0.0.1
        var sub = await (await client.PostAsJsonAsync("/api/subscriptions",
            new { name = "Sneaky", scope = "all", minSeverity = "low", webhookUrl = "https://localtest.me/hook" }, Ct)).Content.ReadFromJsonAsync<JsonObject>(Ct);
        var test = await (await client.PostAsync($"/api/subscriptions/{sub!["id"]}/test", null, Ct)).Content.ReadFromJsonAsync<JsonObject>(Ct);
        Assert.Contains(test!["outcome"]!.GetValue<string>(), new[] { "blocked", "failed" }); // failed only if DNS is unavailable
        Assert.Empty(receiver.Bodies);
    }
}
