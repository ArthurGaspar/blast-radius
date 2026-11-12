using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace BlastRadius.Tests;

/// <summary>
/// Plays shared/contract/scenario.json against the API. web/src/engine/contract.test.ts plays the same file against
/// the browser engine, so both behave the same on the same recorded data.
/// </summary>
public static partial class ContractRunner
{
    [GeneratedRegex(@"\{([A-Za-z0-9:]+)\}")]
    private static partial Regex Placeholder();

    [GeneratedRegex(@"\.([A-Za-z0-9_]+)|\[(\d+)\]")]
    private static partial Regex PathSegment();

    public static async Task RunAsync(ApiFactory factory, ITestOutputHelper? output = null)
    {
        var scenario = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "shared", "contract", "scenario.json")))!;
        var saved = new Dictionary<string, JsonNode?>();
        var client = factory.CreateClient();
        int n = 0;

        foreach (var step in scenario["steps"]!.AsArray())
        {
            n++;
            if (step!["fixtures"] is { } day)
            {
                factory.UseFixtures(day.GetValue<string>());
                continue;
            }
            string name = $"{n:00} {step["name"]}";
            var req = new HttpRequestMessage(new HttpMethod(step["method"]!.GetValue<string>()), Interpolate(step["path"]!.GetValue<string>(), saved));
            if (step["as"] is { } who)
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", saved[$"token:{who}"]!.GetValue<string>());
            if (step["body"] is { } body)
                req.Content = new StringContent(Substitute(body, saved)!.ToJsonString(), Encoding.UTF8, "application/json");

            var res = await client.SendAsync(req, TestContext.Current.CancellationToken);
            var text = await res.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            JsonNode? json = string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
            output?.WriteLine($"{name} -> {(int)res.StatusCode}");

            var expect = step["expect"]!;
            Assert.True((int)res.StatusCode == expect["status"]!.GetValue<int>(), $"{name}: status {(int)res.StatusCode}, body {Clip(text)}");
            if (expect["code"] is { } code)
                Assert.True(json?["code"]?.GetValue<string>() == code.GetValue<string>(), $"{name}: code, body {Clip(text)}");
            if (expect["json"] is JsonObject checks)
                foreach (var (path, want) in checks)
                {
                    var got = Select(json, path);
                    Assert.True(Satisfies(got, want), $"{name}: {path} expected {want?.ToJsonString()} but got {got?.ToJsonString() ?? "nothing"}; body {Clip(text)}");
                }
            if (step["save"] is JsonObject saves)
                foreach (var (key, path) in saves)
                {
                    var value = Select(json, path!.GetValue<string>());
                    Assert.True(value != null, $"{name}: nothing at {path} to save as {key}");
                    saved[key] = value!.DeepClone();
                }
        }
    }

    public static JsonNode? Select(JsonNode? root, string path)
    {
        bool length = path.EndsWith('#');
        var p = length ? path[..^1] : path;
        var node = root;
        foreach (Match m in PathSegment().Matches(p[1..]))
        {
            if (node == null) return null;
            node = m.Groups[1].Success
                ? (node is JsonObject o && o.TryGetPropertyValue(m.Groups[1].Value, out var v) ? v : null)
                : (node is JsonArray a && int.Parse(m.Groups[2].Value) < a.Count ? a[int.Parse(m.Groups[2].Value)] : null);
        }
        if (!length || node == null) return node;
        return JsonValue.Create(node is JsonArray arr ? arr.Count : ((JsonObject)node).Count);
    }

    /// <summary>Equality, with numbers compared by value; {gt|gte|lt|contains} objects express ranges.</summary>
    public static bool Satisfies(JsonNode? got, JsonNode? want)
    {
        if (want is JsonObject op && op.Count == 1 && op.First().Key is "gt" or "gte" or "lt" or "contains")
        {
            var (key, arg) = op.First();
            if (key == "contains") return got?.GetValueKind() == JsonValueKind.String && got.GetValue<string>().Contains(arg!.GetValue<string>());
            if (got?.GetValueKind() != JsonValueKind.Number) return false;
            double g = Num(got), a = Num(arg!);
            return key switch { "gt" => g > a, "gte" => g >= a, _ => g < a };
        }
        if (want?.GetValueKind() == JsonValueKind.Number && got?.GetValueKind() == JsonValueKind.Number)
            return Math.Abs(Num(want) - Num(got)) < 1e-9;
        return JsonNode.DeepEquals(got, want);
    }

    private static double Num(JsonNode n) => double.Parse(n.ToJsonString(), System.Globalization.CultureInfo.InvariantCulture);

    private static string Interpolate(string text, Dictionary<string, JsonNode?> saved) =>
        Placeholder().Replace(text, m => saved.TryGetValue(m.Groups[1].Value, out var v) ? v!.ToString() : throw new InvalidOperationException($"nothing saved as {m.Value}"));

    private static JsonNode? Substitute(JsonNode? node, Dictionary<string, JsonNode?> saved) => node switch
    {
        JsonValue v when v.GetValueKind() == JsonValueKind.String && Placeholder().Match(v.GetValue<string>()) is { Success: true } m
                         && m.Value == v.GetValue<string>() => saved[m.Groups[1].Value]?.DeepClone(),
        JsonValue v when v.GetValueKind() == JsonValueKind.String => JsonValue.Create(Interpolate(v.GetValue<string>(), saved)),
        JsonArray a => new JsonArray(a.Select(x => Substitute(x, saved)).ToArray()),
        JsonObject o => new JsonObject(o.Select(kv => KeyValuePair.Create(kv.Key, Substitute(kv.Value, saved)))),
        _ => node?.DeepClone(),
    };

    private static string Clip(string s) => s.Length > 600 ? s[..600] + "…" : s;
}
