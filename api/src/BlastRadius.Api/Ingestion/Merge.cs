using System.Text.Json;
using BlastRadius.Api.Data;
using BlastRadius.Api.Matching;

namespace BlastRadius.Api.Ingestion;

/// <summary>
/// Deduplication rules, applied the same way by the browser engine (web/src/engine/merge.ts):
/// <list type="bullet">
/// <item>Identity: the CVE when any source names one, else the GHSA id. All identifiers become aliases.</item>
/// <item>Title: GitHub's summary; if there is none, the first sentence of the description.</item>
/// <item>Description and CVSS: NVD wins; GitHub fills in what NVD lacks.</item>
/// <item>Ranges: each source owns its own; an update replaces that source's ranges only.
///   A withdrawn GitHub advisory drops GitHub's ranges; the record is withdrawn only if nothing else backs it.</item>
/// <item>Dates: earliest published, latest modified. References and CWEs: union.</item>
/// </list>
/// </summary>
public static class Merge
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static string PreferredId(IEnumerable<string> aliases)
    {
        var list = aliases.ToList();
        return list.Where(a => a.StartsWith("CVE-", StringComparison.Ordinal)).OrderBy(a => a, StringComparer.Ordinal).FirstOrDefault()
               ?? list.Where(a => a.StartsWith("GHSA-", StringComparison.Ordinal)).OrderBy(a => a, StringComparer.Ordinal).FirstOrDefault()
               ?? list[0];
    }

    /// <summary>Folds one source's advisory into a canonical record. Returns true when anything changed.</summary>
    public static bool Apply(Vulnerability v, Advisory a, DateTimeOffset now)
    {
        string before = Fingerprint(v);

        foreach (var alias in a.Aliases)
            if (!v.Aliases.Contains(alias)) v.Aliases.Add(alias);
        v.Aliases.Sort(StringComparer.Ordinal);
        if (!v.Sources.Contains(a.Source)) { v.Sources.Add(a.Source); v.Sources.Sort(StringComparer.Ordinal); }

        v.Ranges.RemoveAll(r => r.Source == a.Source);
        if (!a.Withdrawn) v.Ranges.AddRange(a.Ranges.Distinct());
        SortRanges(v.Ranges);
        v.Withdrawn = a.Withdrawn && v.Ranges.Count == 0 && v.Sources.All(s => s == a.Source);

        if (a.Source == "nvd")
        {
            if (!string.IsNullOrWhiteSpace(a.Description)) v.Description = a.Description!;
            if (a.CvssScore != null)
            {
                v.CvssScore = a.CvssScore; v.CvssVector = a.CvssVector; v.CvssSource = "nvd";
            }
        }
        else
        {
            if (!string.IsNullOrWhiteSpace(a.Title)) { v.Title = Trim(a.Title!, 300); v.TitleSource = "ghsa"; }
            if (string.IsNullOrWhiteSpace(v.Description) && !string.IsNullOrWhiteSpace(a.Description)) v.Description = a.Description!;
            if (a.CvssScore != null && v.CvssSource != "nvd")
            {
                v.CvssScore = a.CvssScore; v.CvssVector = a.CvssVector; v.CvssSource = "ghsa";
            }
        }
        if (v.TitleSource != "ghsa") { v.Title = FirstSentence(v.Description); v.TitleSource = "derived"; }
        v.Severity = v.CvssScore is { } s ? Danger.SeverityFromScore(s) : a.Severity ?? v.Severity;

        if (a.Published is { } p && (v.Published == null || p < v.Published)) v.Published = p;
        if (a.Modified is { } m && (v.Modified == null || m > v.Modified)) v.Modified = m;
        foreach (var c in a.Cwes) if (!v.Cwes.Contains(c)) v.Cwes.Add(c);
        foreach (var r in a.References) if (v.References.All(x => x.Url != r.Url)) v.References.Add(r);
        v.IdentityIndex = IndexOf(v.Ranges);

        bool changed = Fingerprint(v) != before;
        if (changed) v.UpdatedAt = now;
        return changed;
    }

    /// <summary>Merges a duplicate canonical record into <paramref name="target"/> (both described the same flaw).</summary>
    public static void Absorb(Vulnerability target, Vulnerability other)
    {
        foreach (var a in other.Aliases) if (!target.Aliases.Contains(a)) target.Aliases.Add(a);
        target.Aliases.Sort(StringComparer.Ordinal);
        foreach (var src in other.Sources) if (!target.Sources.Contains(src)) target.Sources.Add(src);
        target.Sources.Sort(StringComparer.Ordinal);
        foreach (var r in other.Ranges) if (!target.Ranges.Contains(r)) target.Ranges.Add(r);
        SortRanges(target.Ranges);
        foreach (var r in other.References) if (target.References.All(x => x.Url != r.Url)) target.References.Add(r);
        foreach (var c in other.Cwes) if (!target.Cwes.Contains(c)) target.Cwes.Add(c);

        if (target.TitleSource != "ghsa" && other.TitleSource == "ghsa") { target.Title = other.Title; target.TitleSource = "ghsa"; }
        if (string.IsNullOrWhiteSpace(target.Description)) target.Description = other.Description;
        if (target.TitleSource != "ghsa") target.Title = FirstSentence(target.Description);
        if (target.CvssSource != "nvd" && other.CvssScore != null && (other.CvssSource == "nvd" || target.CvssScore == null))
        {
            target.CvssScore = other.CvssScore; target.CvssVector = other.CvssVector; target.CvssSource = other.CvssSource;
        }
        if (target.CvssScore is { } s) target.Severity = Danger.SeverityFromScore(s);
        else if (Danger.SeverityRank(other.Severity) > Danger.SeverityRank(target.Severity)) target.Severity = other.Severity;
        if (other.Published is { } p && (target.Published == null || p < target.Published)) target.Published = p;
        if (other.Modified is { } m && (target.Modified == null || m > target.Modified)) target.Modified = m;
        target.Withdrawn = target.Withdrawn && other.Withdrawn;
        target.Kev |= other.Kev;
        target.KevAdded ??= other.KevAdded;
        target.KevDue ??= other.KevDue;
        target.KevRansomware |= other.KevRansomware;
        target.KevAction ??= other.KevAction;
        target.Epss ??= other.Epss;
        target.EpssPercentile ??= other.EpssPercentile;
        target.IdentityIndex = IndexOf(target.Ranges);
    }

    /// <summary>Copies a record under a new primary key (EF can't change keys in place).</summary>
    public static Vulnerability Rekey(Vulnerability v, string newId) => new()
    {
        Id = newId, Title = v.Title, TitleSource = v.TitleSource, Description = v.Description, Severity = v.Severity, CvssScore = v.CvssScore,
        CvssVector = v.CvssVector, CvssSource = v.CvssSource, Published = v.Published, Modified = v.Modified,
        Withdrawn = v.Withdrawn, Kev = v.Kev, KevAdded = v.KevAdded, KevDue = v.KevDue, KevRansomware = v.KevRansomware,
        KevAction = v.KevAction, Epss = v.Epss, EpssPercentile = v.EpssPercentile, Sources = [.. v.Sources],
        Aliases = [.. v.Aliases], Cwes = [.. v.Cwes], Ranges = [.. v.Ranges], References = [.. v.References],
        IdentityIndex = v.IdentityIndex, IngestedAt = v.IngestedAt, UpdatedAt = v.UpdatedAt,
    };

    /// <summary>Canonical order, so re-applying an unchanged advisory is a no-op rather than a reshuffle.</summary>
    public static void SortRanges(List<AffectedRange> ranges) =>
        ranges.Sort((x, y) => string.CompareOrdinal(RangeKey(x), RangeKey(y)));

    private static string RangeKey(AffectedRange r) => $"{r.Source}|{r.IdentityKey}|{r.Describe()}|{r.Fixed}";

    public static string IndexOf(IEnumerable<AffectedRange> ranges) =>
        "|" + string.Concat(ranges.Select(r => r.IdentityKey).Distinct().Order(StringComparer.Ordinal).Select(k => k + "|"));

    public static string FirstSentence(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return "";
        var t = text.Trim();
        int dot = t.IndexOf(". ", StringComparison.Ordinal);
        if (dot > 0 && dot < 200) t = t[..(dot + 1)];
        return Trim(t, 160);
    }

    private static string Trim(string s, int max) => s.Length <= max ? s : s[..(max - 1)].TrimEnd() + "…";

    private static string Fingerprint(Vulnerability v) => JsonSerializer.Serialize(new
    {
        v.Title, v.TitleSource, v.Description, v.Severity, v.CvssScore, v.CvssVector, v.CvssSource, v.Published, v.Modified,
        v.Withdrawn, v.Sources, v.Aliases, v.Cwes, v.Ranges, References = v.References.Select(r => r.Url),
    }, Json);
}
