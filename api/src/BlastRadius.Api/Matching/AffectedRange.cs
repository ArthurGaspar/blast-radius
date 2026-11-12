namespace BlastRadius.Api.Matching;

public enum MatchStatus { None, Possible, Affected }

/// <summary>
/// One affected-version statement from a source. Identity is either a CPE vendor/product (NVD) or an
/// ecosystem package (GitHub). Bounds follow NVD's naming; GitHub range strings are parsed into them.
/// </summary>
public sealed partial record AffectedRange
{
    public required string Source { get; init; }
    public string? CpeVendor { get; init; }
    public string? CpeProduct { get; init; }
    public string? Ecosystem { get; init; }
    public string? Package { get; init; }
    public string? Exact { get; init; }
    public string? StartIncluding { get; init; }
    public string? StartExcluding { get; init; }
    public string? EndIncluding { get; init; }
    public string? EndExcluding { get; init; }
    public string? Fixed { get; init; }

    /// <summary>Identity key used to index ranges: "cpe:vendor:product" or "pkg:ecosystem:name".</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public string IdentityKey => CpeVendor != null
        ? Identity.CpeKey(CpeVendor, CpeProduct!)
        : Identity.PackageKey(Ecosystem!, Package!);

    [System.Text.Json.Serialization.JsonIgnore]
    public bool HasBounds => StartIncluding != null || StartExcluding != null || EndIncluding != null || EndExcluding != null;

    public MatchStatus Evaluate(string? version)
    {
        if (string.IsNullOrWhiteSpace(version)) return MatchStatus.Possible;
        // NVD sometimes names a product with no versions at all: that says nothing about a known version
        if (Exact == null && !HasBounds) return MatchStatus.None;
        if (Exact != null) return Comparable(version, Exact) ? (VersionComparer.Compare(version, Exact) == 0 ? MatchStatus.Affected : MatchStatus.None) : MatchStatus.Possible;
        // A bound that excludes the version settles it; a bound in another scheme (a date against 3.17.2) can't confirm it.
        bool unsure = false;
        if (Check(StartIncluding, c => c < 0) is { } a) { if (a) return MatchStatus.None; } else unsure = true;
        if (Check(StartExcluding, c => c <= 0) is { } b) { if (b) return MatchStatus.None; } else unsure = true;
        if (Check(EndIncluding, c => c > 0) is { } d) { if (d) return MatchStatus.None; } else unsure = true;
        if (Check(EndExcluding, c => c >= 0) is { } e) { if (e) return MatchStatus.None; } else unsure = true;
        return unsure ? MatchStatus.Possible : MatchStatus.Affected;

        // true: this bound excludes the version; false: it doesn't; null: not comparable
        bool? Check(string? bound, Func<int, bool> excludes) =>
            bound == null ? false : Comparable(version, bound) ? excludes(VersionComparer.Compare(version, bound)) : null;
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"^\d{4}-\d{2}-\d{2}$")]
    private static partial System.Text.RegularExpressions.Regex DatePattern();

    /// <summary>NVD sometimes uses release dates as versions; a date and a release number can't be ordered.</summary>
    private static bool Comparable(string a, string b) => DatePattern().IsMatch(a.Trim()) == DatePattern().IsMatch(b.Trim());

    /// <summary>
    /// The verdict across all ranges for one product: specific statements (bounds or an exact version) take precedence
    /// over unbounded ones, then "affected" beats "possible". Returns the range that decided it.
    /// </summary>
    public static (MatchStatus Status, AffectedRange? Range) Best(IEnumerable<AffectedRange> ranges, string? version)
    {
        var list = ranges.ToList();
        var specific = list.Where(r => r.Exact != null || r.HasBounds).ToList();
        (MatchStatus Status, AffectedRange? Range) best = (MatchStatus.None, null);
        foreach (var r in specific.Count > 0 ? specific : list)
        {
            var s = r.Evaluate(version);
            if (s > best.Status) best = (s, r);
            if (s == MatchStatus.Affected) break;
        }
        return best;
    }

    /// <summary>Human-readable bounds, e.g. "&gt;= 2.49.0, &lt; 2.55.0" or "all versions".</summary>
    public string Describe()
    {
        if (Exact != null) return "= " + Exact;
        if (!HasBounds) return "all versions";
        var parts = new List<string>();
        if (StartIncluding != null) parts.Add(">= " + StartIncluding);
        if (StartExcluding != null) parts.Add("> " + StartExcluding);
        if (EndIncluding != null) parts.Add("<= " + EndIncluding);
        if (EndExcluding != null) parts.Add("< " + EndExcluding);
        return string.Join(", ", parts);
    }

    /// <summary>Parses GitHub's vulnerable_version_range, e.g. "&gt;= 2.49.0, &lt; 2.55.0" or "= 1.2.0".</summary>
    public static AffectedRange FromGhsa(string ecosystem, string package, string? range, string? firstPatched)
    {
        string? si = null, se = null, ei = null, ee = null, exact = null;
        foreach (var part in (range ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var (op, value) = part switch
            {
                _ when part.StartsWith(">=") => (">=", part[2..]),
                _ when part.StartsWith("<=") => ("<=", part[2..]),
                _ when part.StartsWith('>') => (">", part[1..]),
                _ when part.StartsWith('<') => ("<", part[1..]),
                _ when part.StartsWith('=') => ("=", part[1..]),
                _ => ("=", part),
            };
            value = value.Trim();
            switch (op)
            {
                case ">=": si = value; break;
                case ">": se = value; break;
                case "<=": ei = value; break;
                case "<": ee = value; break;
                default: exact = value; break;
            }
        }
        return new AffectedRange
        {
            Source = "ghsa", Ecosystem = ecosystem, Package = package,
            Exact = exact, StartIncluding = si, StartExcluding = se, EndIncluding = ei, EndExcluding = ee,
            Fixed = string.IsNullOrWhiteSpace(firstPatched) ? null : firstPatched,
        };
    }

    /// <summary>
    /// Builds a range from an NVD cpeMatch. A concrete version in the CPE (with its update field, e.g.
    /// openssh 9.7 p1 → "9.7p1") becomes an exact match; "*" and "-" defer to the explicit bounds.
    /// Returns null for non-application CPEs or malformed criteria.
    /// </summary>
    public static AffectedRange? FromNvd(string criteria, string? startIncluding, string? startExcluding,
                                         string? endIncluding, string? endExcluding)
    {
        var f = criteria.Split(':');
        if (f.Length < 7 || f[0] != "cpe" || f[2] != "a") return null;
        string version = Unescape(f[5]);
        string update = Unescape(f[6]);
        string? exact = null;
        if (version != "*" && version != "-")
        {
            exact = update is "*" or "-" or "" ? version : version + update;
        }
        return new AffectedRange
        {
            Source = "nvd", CpeVendor = Unescape(f[3]), CpeProduct = Unescape(f[4]), Exact = exact,
            StartIncluding = startIncluding, StartExcluding = startExcluding,
            EndIncluding = endIncluding, EndExcluding = endExcluding,
            Fixed = endExcluding,
        };
    }

    private static string Unescape(string s) => s.Replace("\\", "");
}
