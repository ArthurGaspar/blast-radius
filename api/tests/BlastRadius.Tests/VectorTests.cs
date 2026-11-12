using System.Text.Json;
using BlastRadius.Api.Matching;

namespace BlastRadius.Tests;

/// <summary>shared/vectors.json: the same cases run in web/src/engine/vectors.test.ts.</summary>
public class VectorTests
{
    private static readonly JsonElement Vectors =
        JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "shared", "vectors.json"))).RootElement;

    public static TheoryData<string, string, int> CompareCases()
    {
        var data = new TheoryData<string, string, int>();
        foreach (var c in Vectors.GetProperty("compare").EnumerateArray())
            data.Add(c[0].GetString()!, c[1].GetString()!, c[2].GetInt32());
        return data;
    }

    [Theory]
    [MemberData(nameof(CompareCases))]
    public void Compares_versions(string a, string b, int expected)
    {
        Assert.Equal(expected, Math.Sign(VersionComparer.Compare(a, b)));
        Assert.Equal(-expected, Math.Sign(VersionComparer.Compare(b, a)));
    }

    public static TheoryData<string, string, string> GhsaCases()
    {
        var data = new TheoryData<string, string, string>();
        foreach (var c in Vectors.GetProperty("ghsaRanges").EnumerateArray())
            data.Add(c.GetProperty("range").GetString()!, c.GetProperty("version").GetString()!, c.GetProperty("expect").GetString()!);
        return data;
    }

    [Theory]
    [MemberData(nameof(GhsaCases))]
    public void Evaluates_github_ranges(string range, string version, string expected)
    {
        var r = AffectedRange.FromGhsa("pip", "x", range, null);
        Assert.Equal(expected, r.Evaluate(version).ToString().ToLowerInvariant());
    }

    public static TheoryData<string, string, string> NvdCases()
    {
        var data = new TheoryData<string, string, string>();
        foreach (var c in Vectors.GetProperty("nvdCriteria").EnumerateArray())
            data.Add(c.GetProperty("match").GetRawText(), c.GetProperty("version").GetString()!, c.GetProperty("expect").GetString()!);
        return data;
    }

    [Theory]
    [MemberData(nameof(NvdCases))]
    public void Evaluates_nvd_cpe_matches(string match, string version, string expected)
    {
        var m = JsonDocument.Parse(match).RootElement;
        string? Opt(string name) => m.TryGetProperty(name, out var v) ? v.GetString() : null;
        var r = AffectedRange.FromNvd(m.GetProperty("criteria").GetString()!, Opt("versionStartIncluding"),
            Opt("versionStartExcluding"), Opt("versionEndIncluding"), Opt("versionEndExcluding"));
        Assert.NotNull(r);
        Assert.Equal(expected, r.Evaluate(version).ToString().ToLowerInvariant());
    }

    public static TheoryData<string, string> PrecedenceCases()
    {
        var data = new TheoryData<string, string>();
        foreach (var c in Vectors.GetProperty("precedence").EnumerateArray())
            data.Add(c.GetProperty("about").GetString()!, c.GetRawText());
        return data;
    }

    [Theory]
    [MemberData(nameof(PrecedenceCases))]
    public void Prefers_specific_statements(string about, string json)
    {
        var c = JsonDocument.Parse(json).RootElement;
        var ranges = JsonSerializer.Deserialize<List<AffectedRange>>(c.GetProperty("ranges").GetRawText(), new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        var (status, _) = AffectedRange.Best(ranges, c.GetProperty("version").GetString());
        Assert.True(c.GetProperty("expect").GetString() == status.ToString().ToLowerInvariant(), about);
    }

    [Fact]
    public void Normalizes_package_names()
    {
        foreach (var c in Vectors.GetProperty("packageNames").EnumerateArray())
        {
            string eco = c[0].GetString()!;
            bool same = Identity.PackageKey(eco, c[1].GetString()!) == Identity.PackageKey(eco, c[2].GetString()!);
            Assert.True(same == c[3].GetBoolean(), $"{c[1]} vs {c[2]}");
        }
    }

    [Fact]
    public void Scores_danger()
    {
        foreach (var c in Vectors.GetProperty("danger").EnumerateArray())
        {
            double? cvss = c.GetProperty("cvss").ValueKind == JsonValueKind.Null ? null : c.GetProperty("cvss").GetDouble();
            string? severity = c.GetProperty("severity").ValueKind == JsonValueKind.Null ? null : c.GetProperty("severity").GetString();
            var status = c.GetProperty("status").GetString() == "possible" ? MatchStatus.Possible : MatchStatus.Affected;
            double score = Danger.Score(cvss, severity, c.GetProperty("kev").GetBoolean(), c.GetProperty("epss").GetDouble(), status);
            Assert.Equal(c.GetProperty("expect").GetDouble(), score);
            Assert.Equal(c.GetProperty("level").GetString(), Danger.Level(score));
        }
    }
}
