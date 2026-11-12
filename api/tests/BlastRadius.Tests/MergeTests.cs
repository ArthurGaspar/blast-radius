using System.Text.Json;
using BlastRadius.Api.Data;
using BlastRadius.Api.Ingestion;

namespace BlastRadius.Tests;

/// <summary>Dedup rules on recorded NVD and GitHub responses.</summary>
public class MergeTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-12T00:00:00Z");

    private static Advisory Nvd(string cve)
    {
        var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(ApiFactory.Fixtures("day2"), "nvd", "ollama_ollama.json")));
        var e = doc.RootElement.GetProperty("vulnerabilities").EnumerateArray().Select(x => x.GetProperty("cve")).First(c => c.GetProperty("id").GetString() == cve);
        return Normalize.FromNvd(e);
    }

    private static Advisory Ghsa(string id)
    {
        var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(ApiFactory.Fixtures("day2"), "ghsa", "go", "github.com_ollama_ollama.json")));
        return Normalize.FromGhsa(doc.RootElement.EnumerateArray().First(a => a.GetProperty("ghsa_id").GetString() == id));
    }

    private static Vulnerability Fold(params Advisory[] advisories)
    {
        var v = new Vulnerability { Id = Merge.PreferredId(advisories.SelectMany(a => a.Aliases)) };
        foreach (var a in advisories) Merge.Apply(v, a, Now);
        return v;
    }

    [Fact]
    public void Github_and_nvd_describe_the_same_cve()
    {
        var nvd = Nvd("CVE-2024-37032");
        var gh = Ghsa("GHSA-8hqg-whrw-pv92");
        Assert.Equal("CVE-2024-37032", gh.Cve);
        Assert.Equal("medium", gh.Severity);   // GitHub's own rating
        Assert.Equal(8.8, nvd.CvssScore);       // NVD's

        var v = Fold(nvd, gh);
        Assert.Equal("CVE-2024-37032", v.Id);
        Assert.Equal(["CVE-2024-37032", "GHSA-8hqg-whrw-pv92"], v.Aliases);
        Assert.Equal(["ghsa", "nvd"], v.Sources);
        Assert.Equal(8.8, v.CvssScore);
        Assert.Equal("nvd", v.CvssSource);
        Assert.Equal("high", v.Severity);
        Assert.Equal("ghsa", v.TitleSource);
        Assert.StartsWith("Ollama", v.Title);
        Assert.Equal(2, v.Ranges.Count);
    }

    [Fact]
    public void Merging_is_independent_of_arrival_order()
    {
        var a = Fold(Nvd("CVE-2024-37032"), Ghsa("GHSA-8hqg-whrw-pv92"));
        var b = Fold(Ghsa("GHSA-8hqg-whrw-pv92"), Nvd("CVE-2024-37032"));
        Assert.Equal(a.Title, b.Title);
        Assert.Equal(a.Description, b.Description);
        Assert.Equal(a.CvssScore, b.CvssScore);
        Assert.Equal(a.Severity, b.Severity);
        Assert.Equal(a.Published, b.Published);
        Assert.Equal(a.Modified, b.Modified);
        Assert.Equal(a.Aliases, b.Aliases);
        Assert.Equal(a.Sources, b.Sources);
        Assert.Equal(a.Ranges.OrderBy(r => r.Source), b.Ranges.OrderBy(r => r.Source));
    }

    [Fact]
    public void Reapplying_the_same_advisory_changes_nothing()
    {
        var v = Fold(Nvd("CVE-2024-37032"), Ghsa("GHSA-8hqg-whrw-pv92"));
        Assert.False(Merge.Apply(v, Ghsa("GHSA-8hqg-whrw-pv92"), Now.AddDays(1)));
        Assert.False(Merge.Apply(v, Nvd("CVE-2024-37032"), Now.AddDays(1)));
    }

    [Fact]
    public void A_source_replaces_only_its_own_ranges()
    {
        var v = Fold(Nvd("CVE-2024-37032"), Ghsa("GHSA-8hqg-whrw-pv92"));
        var withdrawn = Ghsa("GHSA-8hqg-whrw-pv92") with { Withdrawn = true };
        Merge.Apply(v, withdrawn, Now);
        Assert.All(v.Ranges, r => Assert.Equal("nvd", r.Source));
        Assert.False(v.Withdrawn); // NVD still backs it
    }

    [Fact]
    public void Absorbing_a_duplicate_keeps_the_best_of_both()
    {
        var cve = Fold(Nvd("CVE-2024-37032"));
        var gh = Fold(Ghsa("GHSA-8hqg-whrw-pv92") with { Aliases = ["GHSA-8hqg-whrw-pv92"] });
        Assert.Equal("GHSA-8hqg-whrw-pv92", gh.Id);
        gh.Kev = true;
        Merge.Absorb(cve, gh);
        Assert.Contains("GHSA-8hqg-whrw-pv92", cve.Aliases);
        Assert.Equal("nvd", cve.CvssSource);
        Assert.Equal("ghsa", cve.TitleSource);
        Assert.True(cve.Kev);
        Assert.Equal(2, cve.Ranges.Count);
    }
}
