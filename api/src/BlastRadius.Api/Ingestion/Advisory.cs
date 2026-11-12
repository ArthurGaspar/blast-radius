using System.Text.Json;
using BlastRadius.Api.Data;
using BlastRadius.Api.Matching;

namespace BlastRadius.Api.Ingestion;

/// <summary>One source's statement about one vulnerability, before deduplication.</summary>
public sealed record Advisory
{
    public required string Source { get; init; } // nvd | ghsa
    public required string SourceId { get; init; }
    public required List<string> Aliases { get; init; }
    public string? Title { get; init; }
    public string? Description { get; init; }
    public double? CvssScore { get; init; }
    public string? CvssVector { get; init; }
    public string? Severity { get; init; }
    public DateTimeOffset? Published { get; init; }
    public DateTimeOffset? Modified { get; init; }
    public bool Withdrawn { get; init; }
    public List<string> Cwes { get; init; } = [];
    public List<AffectedRange> Ranges { get; init; } = [];
    public List<Reference> References { get; init; } = [];

    public string? Cve => Aliases.FirstOrDefault(a => a.StartsWith("CVE-", StringComparison.Ordinal));
}

/// <summary>Turns raw NVD 2.0 and GitHub Advisory Database JSON into <see cref="Advisory"/> records.</summary>
public static class Normalize
{
    public static Advisory FromNvd(JsonElement cve)
    {
        string id = cve.GetProperty("id").GetString()!;
        string? description = cve.TryGetProperty("descriptions", out var ds)
            ? ds.EnumerateArray().Where(d => d.GetProperty("lang").GetString() == "en")
                .Select(d => d.GetProperty("value").GetString()).FirstOrDefault()
            : null;

        double? score = null;
        string? vector = null, severity = null;
        if (cve.TryGetProperty("metrics", out var metrics))
        {
            foreach (var key in new[] { "cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
            {
                if (!metrics.TryGetProperty(key, out var list) || list.GetArrayLength() == 0) continue;
                var pick = list.EnumerateArray().FirstOrDefault(m => m.TryGetProperty("type", out var t) && t.GetString() == "Primary");
                if (pick.ValueKind == JsonValueKind.Undefined) pick = list[0];
                var data = pick.GetProperty("cvssData");
                score = data.GetProperty("baseScore").GetDouble();
                vector = data.TryGetProperty("vectorString", out var vs) ? vs.GetString() : null;
                severity = Danger.SeverityFromScore(score.Value);
                break;
            }
        }

        var cwes = new List<string>();
        if (cve.TryGetProperty("weaknesses", out var ws))
            foreach (var w in ws.EnumerateArray())
                foreach (var d in w.GetProperty("description").EnumerateArray())
                {
                    var v = d.GetProperty("value").GetString();
                    if (v != null && v.StartsWith("CWE-") && !cwes.Contains(v)) cwes.Add(v);
                }

        var ranges = new List<AffectedRange>();
        if (cve.TryGetProperty("configurations", out var configs))
            foreach (var config in configs.EnumerateArray())
                foreach (var node in config.GetProperty("nodes").EnumerateArray())
                {
                    if (!node.TryGetProperty("cpeMatch", out var cms)) continue;
                    foreach (var cm in cms.EnumerateArray())
                    {
                        if (!cm.GetProperty("vulnerable").GetBoolean()) continue;
                        string? Opt(string n) => cm.TryGetProperty(n, out var p) ? p.GetString() : null;
                        var r = AffectedRange.FromNvd(cm.GetProperty("criteria").GetString()!, Opt("versionStartIncluding"),
                            Opt("versionStartExcluding"), Opt("versionEndIncluding"), Opt("versionEndExcluding"));
                        if (r != null && !ranges.Contains(r)) ranges.Add(r);
                    }
                }

        var refs = new List<Reference>();
        if (cve.TryGetProperty("references", out var rs))
            foreach (var r in rs.EnumerateArray())
            {
                var url = r.GetProperty("url").GetString()!;
                if (refs.All(x => x.Url != url)) refs.Add(new Reference { Url = url, Source = "nvd" });
            }

        return new Advisory
        {
            Source = "nvd",
            SourceId = id,
            Aliases = [id],
            Title = null,
            Description = description,
            CvssScore = score,
            CvssVector = vector,
            Severity = severity,
            Published = Date(cve, "published"),
            Modified = Date(cve, "lastModified"),
            Withdrawn = cve.TryGetProperty("vulnStatus", out var st) && st.GetString() == "Rejected",
            Cwes = cwes,
            Ranges = ranges,
            References = refs,
        };
    }

    public static Advisory FromGhsa(JsonElement a)
    {
        string ghsa = a.GetProperty("ghsa_id").GetString()!;
        var aliases = new List<string> { ghsa };
        if (a.TryGetProperty("identifiers", out var ids))
            foreach (var i in ids.EnumerateArray())
            {
                var v = i.GetProperty("value").GetString()!;
                if (!aliases.Contains(v)) aliases.Add(v);
            }
        if (a.TryGetProperty("cve_id", out var c) && c.ValueKind == JsonValueKind.String && !aliases.Contains(c.GetString()!))
            aliases.Add(c.GetString()!);

        double? score = null;
        string? vector = null;
        if (a.TryGetProperty("cvss_severities", out var sev))
        {
            foreach (var key in new[] { "cvss_v4", "cvss_v3" })
            {
                if (sev.TryGetProperty(key, out var s) && s.TryGetProperty("score", out var sc) && sc.ValueKind == JsonValueKind.Number && sc.GetDouble() > 0)
                {
                    score = sc.GetDouble();
                    vector = s.TryGetProperty("vector_string", out var vs) ? vs.GetString() : null;
                    break;
                }
            }
        }
        string? severity = a.TryGetProperty("severity", out var sv) ? sv.GetString() : null;
        severity = severity switch { "moderate" => "medium", "unknown" or null => null, _ => severity };

        var ranges = new List<AffectedRange>();
        if (a.TryGetProperty("vulnerabilities", out var vulns) && vulns.ValueKind == JsonValueKind.Array)
            foreach (var v in vulns.EnumerateArray())
            {
                var pkg = v.GetProperty("package");
                if (pkg.ValueKind != JsonValueKind.Object) continue;
                var r = AffectedRange.FromGhsa(pkg.GetProperty("ecosystem").GetString()!, pkg.GetProperty("name").GetString()!,
                    v.TryGetProperty("vulnerable_version_range", out var vr) ? vr.GetString() : null,
                    v.TryGetProperty("first_patched_version", out var fp) && fp.ValueKind == JsonValueKind.String ? fp.GetString() : null);
                if (!ranges.Contains(r)) ranges.Add(r);
            }

        var cwes = new List<string>();
        if (a.TryGetProperty("cwes", out var cw) && cw.ValueKind == JsonValueKind.Array)
            foreach (var x in cw.EnumerateArray())
            {
                var id = x.GetProperty("cwe_id").GetString();
                if (id != null && !cwes.Contains(id)) cwes.Add(id);
            }

        var refs = new List<Reference>();
        if (a.TryGetProperty("html_url", out var html) && html.ValueKind == JsonValueKind.String)
            refs.Add(new Reference { Url = html.GetString()!, Source = "ghsa" });
        if (a.TryGetProperty("references", out var rs) && rs.ValueKind == JsonValueKind.Array)
            foreach (var r in rs.EnumerateArray())
            {
                var url = r.GetString();
                if (url != null && refs.All(x => x.Url != url)) refs.Add(new Reference { Url = url, Source = "ghsa" });
            }

        return new Advisory
        {
            Source = "ghsa",
            SourceId = ghsa,
            Aliases = aliases,
            Title = a.TryGetProperty("summary", out var s2) ? s2.GetString() : null,
            Description = a.TryGetProperty("description", out var d2) ? d2.GetString() : null,
            CvssScore = score,
            CvssVector = vector,
            Severity = score is { } x2 ? Danger.SeverityFromScore(x2) : severity,
            Published = Date(a, "published_at"),
            Modified = Date(a, "updated_at"),
            Withdrawn = a.TryGetProperty("withdrawn_at", out var w) && w.ValueKind == JsonValueKind.String,
            Cwes = cwes,
            Ranges = ranges,
            References = refs,
        };
    }

    private static DateTimeOffset? Date(JsonElement e, string name)
    {
        if (!e.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.String) return null;
        var s = v.GetString()!;
        // NVD timestamps carry no zone and are UTC
        return DateTimeOffset.TryParse(s, null, System.Globalization.DateTimeStyles.AssumeUniversal, out var d) ? d.ToUniversalTime() : null;
    }
}
