using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace BlastRadius.Api.Ingestion;

public sealed class SourceOptions
{
    public string NvdBaseUrl { get; set; } = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    public string? NvdApiKey { get; set; }
    public string GithubBaseUrl { get; set; } = "https://api.github.com";
    public string? GithubToken { get; set; }
    public string KevUrl { get; set; } = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
    public string EpssBaseUrl { get; set; } = "https://api.first.org/data/v1/epss";
    /// <summary>When set, requests are answered from recorded responses in this folder instead of the network.</summary>
    public string? FixtureDir { get; set; }

    /// <summary>NVD allows 5 requests per 30 s without a key and 50 with one.</summary>
    public TimeSpan NvdDelay => FixtureDir != null ? TimeSpan.Zero : NvdApiKey is { Length: > 0 } ? TimeSpan.FromMilliseconds(700) : TimeSpan.FromSeconds(6.5);
}

public sealed record KevEntry(string Cve, DateOnly? Added, DateOnly? Due, bool Ransomware, string? Action);

public sealed record EpssScore(double Epss, double Percentile);

/// <summary>NVD CVE API 2.0, queried per product with virtualMatchString.</summary>
public sealed class NvdClient(HttpClient http, IOptions<SourceOptions> options)
{
    private readonly SourceOptions _o = options.Value;

    // NVD's limit is per client, across all queries, so the spacing is process-wide.
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static DateTimeOffset _lastRequest = DateTimeOffset.MinValue;

    private async Task<HttpResponseMessage> SendThrottledAsync(string url, CancellationToken ct)
    {
        for (int attempt = 1; ; attempt++)
        {
            await Gate.WaitAsync(ct);
            try
            {
                var wait = _lastRequest + _o.NvdDelay - DateTimeOffset.UtcNow;
                if (wait > TimeSpan.Zero) await Task.Delay(wait, ct);
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                if (_o.NvdApiKey is { Length: > 0 } key) req.Headers.Add("apiKey", key);
                var res = await http.SendAsync(req, ct);
                _lastRequest = DateTimeOffset.UtcNow;
                bool retryable = res.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable or HttpStatusCode.Forbidden;
                if (!retryable || attempt == 4) return res;
                // NVD answers 403/429/503 when throttling; back off, honouring Retry-After when present
                var backoff = res.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(10 * attempt);
                res.Dispose();
                _lastRequest = DateTimeOffset.UtcNow + backoff;
            }
            finally
            {
                Gate.Release();
            }
        }
    }

    public async IAsyncEnumerable<JsonElement> FetchAsync(string vendor, string product, DateTimeOffset? since,
                                                          DateTimeOffset now, [EnumeratorCancellation] CancellationToken ct)
    {
        int start = 0;
        while (true)
        {
            var q = new StringBuilder($"{_o.NvdBaseUrl}?virtualMatchString=cpe:2.3:a:{Uri.EscapeDataString(vendor)}:{Uri.EscapeDataString(product)}&resultsPerPage=2000&startIndex={start}");
            // incremental window; NVD caps it at 120 days, beyond that fetch everything
            if (since is { } s && now - s < TimeSpan.FromDays(119))
                q.Append($"&lastModStartDate={s.UtcDateTime:yyyy-MM-ddTHH:mm:ss.fffZ}&lastModEndDate={now.UtcDateTime:yyyy-MM-ddTHH:mm:ss.fffZ}");
            using var res = await SendThrottledAsync(q.ToString(), ct);
            res.EnsureSuccessStatusCode();
            using var doc = await JsonDocument.ParseAsync(await res.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
            var root = doc.RootElement;
            int total = root.GetProperty("totalResults").GetInt32();
            int count = 0;
            foreach (var v in root.GetProperty("vulnerabilities").EnumerateArray())
            {
                count++;
                yield return v.GetProperty("cve").Clone();
            }
            start += count;
            if (count == 0 || start >= total) yield break;
        }
    }
}

/// <summary>GitHub Advisory Database, global advisories filtered by ecosystem and package.</summary>
public sealed class GhsaClient(HttpClient http, IOptions<SourceOptions> options)
{
    private readonly SourceOptions _o = options.Value;

    /// <param name="since">Only advisories published or updated since then (GitHub filters by day; one day of overlap is kept).</param>
    public async IAsyncEnumerable<JsonElement> FetchAsync(string ecosystem, string package, DateTimeOffset? since,
                                                          [EnumeratorCancellation] CancellationToken ct)
    {
        string? url = $"{_o.GithubBaseUrl}/advisories?ecosystem={Uri.EscapeDataString(ecosystem)}&affects={Uri.EscapeDataString(package)}&per_page=100";
        if (since is { } s) url += "&modified=" + Uri.EscapeDataString($">={s.UtcDateTime.AddDays(-1):yyyy-MM-dd}");
        while (url != null)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.UserAgent.ParseAdd("blast-radius");
            req.Headers.Accept.ParseAdd("application/vnd.github+json");
            if (_o.GithubToken is { Length: > 0 } token) req.Headers.Authorization = new("Bearer", token);
            using var res = await http.SendAsync(req, ct);
            res.EnsureSuccessStatusCode();
            using var doc = await JsonDocument.ParseAsync(await res.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
            foreach (var a in doc.RootElement.EnumerateArray()) yield return a.Clone();
            url = NextLink(res);
        }
    }

    private static string? NextLink(HttpResponseMessage res)
    {
        if (!res.Headers.TryGetValues("Link", out var values)) return null;
        foreach (var part in string.Join(",", values).Split(','))
        {
            var seg = part.Split(';');
            if (seg.Length == 2 && seg[1].Trim() == "rel=\"next\"") return seg[0].Trim().Trim('<', '>');
        }
        return null;
    }
}

/// <summary>CISA Known Exploited Vulnerabilities, from the cisagov/kev-data mirror.</summary>
public sealed class KevClient(HttpClient http, IOptions<SourceOptions> options)
{
    public async Task<List<KevEntry>> FetchAsync(CancellationToken ct)
    {
        using var res = await http.GetAsync(options.Value.KevUrl, ct);
        res.EnsureSuccessStatusCode();
        using var doc = await JsonDocument.ParseAsync(await res.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        var list = new List<KevEntry>();
        foreach (var v in doc.RootElement.GetProperty("vulnerabilities").EnumerateArray())
        {
            static DateOnly? D(JsonElement e, string n) => e.TryGetProperty(n, out var p) && DateOnly.TryParse(p.GetString(), out var d) ? d : null;
            list.Add(new KevEntry(v.GetProperty("cveID").GetString()!, D(v, "dateAdded"), D(v, "dueDate"),
                v.TryGetProperty("knownRansomwareCampaignUse", out var r) && r.GetString() == "Known",
                v.TryGetProperty("requiredAction", out var a) ? a.GetString() : null));
        }
        return list;
    }
}

/// <summary>FIRST EPSS: probability that a CVE is exploited in the next 30 days.</summary>
public sealed class EpssClient(HttpClient http, IOptions<SourceOptions> options)
{
    public async Task<Dictionary<string, EpssScore>> FetchAsync(IReadOnlyCollection<string> cves, CancellationToken ct)
    {
        var result = new Dictionary<string, EpssScore>();
        foreach (var chunk in cves.Chunk(100))
        {
            var url = $"{options.Value.EpssBaseUrl}?cve={string.Join(",", chunk)}&limit=100";
            using var res = await http.GetAsync(url, ct);
            res.EnsureSuccessStatusCode();
            using var doc = await JsonDocument.ParseAsync(await res.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
            foreach (var row in doc.RootElement.GetProperty("data").EnumerateArray())
            {
                static double N(JsonElement e, string n) => double.Parse(e.GetProperty(n).GetString()!, System.Globalization.CultureInfo.InvariantCulture);
                result[row.GetProperty("cve").GetString()!] = new EpssScore(N(row, "epss"), N(row, "percentile"));
            }
        }
        return result;
    }
}

/// <summary>
/// Answers source requests from recorded responses (shared/fixtures). Used by tests and offline runs.
/// The folder can be switched at runtime so a test can ingest "day1" and then "day2".
/// </summary>
public sealed class FixtureHandler(FixtureState state) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var dir = state.Dir ?? throw new InvalidOperationException("No fixture folder selected");
        var uri = request.RequestUri!;
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        string? file = null;
        string empty = "{}";
        if (uri.Host.Contains("nvd.nist.gov"))
        {
            var parts = (query["virtualMatchString"] ?? "").Split(':');
            file = Path.Combine(dir, "nvd", $"{parts.ElementAtOrDefault(3)}_{parts.ElementAtOrDefault(4)}.json");
            empty = """{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}""";
        }
        else if (uri.AbsolutePath.EndsWith("/advisories"))
        {
            file = Path.Combine(dir, "ghsa", query["ecosystem"] ?? "", (query["affects"] ?? "").Replace('/', '_') + ".json");
            empty = "[]";
        }
        else if (uri.AbsolutePath.EndsWith("known_exploited_vulnerabilities.json"))
        {
            file = Path.Combine(dir, "kev.json");
            empty = """{"vulnerabilities":[]}""";
        }
        else if (uri.Host.Contains("first.org"))
        {
            var wanted = (query["cve"] ?? "").Split(',').ToHashSet();
            var path = Path.Combine(dir, "epss.json");
            var rows = File.Exists(path)
                ? JsonDocument.Parse(File.ReadAllText(path)).RootElement.GetProperty("data").EnumerateArray()
                    .Where(r => wanted.Contains(r.GetProperty("cve").GetString()!)).Select(r => r.Clone()).ToList()
                : [];
            return Task.FromResult(Json(JsonSerializer.Serialize(new { data = rows })));
        }
        if (file == null) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        return Task.FromResult(Json(File.Exists(file) ? File.ReadAllText(file) : empty));
    }

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}

public sealed class FixtureState
{
    public string? Dir { get; set; }
}
