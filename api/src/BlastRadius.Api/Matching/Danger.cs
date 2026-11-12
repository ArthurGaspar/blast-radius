namespace BlastRadius.Api.Matching;

/// <summary>
/// Danger of one vulnerability on one asset, 0–10, and the level that colors the map.
/// score = CVSS (or a severity fallback) + 2 if actively exploited (CISA KEV) + 3 × EPSS probability,
/// capped at 10, then × 0.6 when the asset's version is unknown and the match is only possible.
/// </summary>
public static class Danger
{
    public static double Score(double? cvss, string? severity, bool kev, double? epss, MatchStatus status)
    {
        double baseScore = cvss ?? severity switch
        {
            "critical" => 9.5,
            "high" => 7.5,
            "medium" => 5.0,
            "low" => 2.5,
            _ => 5.0,
        };
        double s = Math.Min(10, baseScore + (kev ? 2 : 0) + 3 * (epss ?? 0));
        if (status == MatchStatus.Possible) s *= 0.6;
        return Math.Round(s, 1, MidpointRounding.AwayFromZero);
    }

    public static string Level(double score) => score switch
    {
        >= 9 => "severe",
        >= 7 => "high",
        >= 4 => "elevated",
        > 0 => "low",
        _ => "clear",
    };

    public static int SeverityRank(string? severity) => severity switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };

    public static string SeverityFromScore(double score) => score switch
    {
        >= 9 => "critical",
        >= 7 => "high",
        >= 4 => "medium",
        > 0 => "low",
        _ => "none",
    };
}
