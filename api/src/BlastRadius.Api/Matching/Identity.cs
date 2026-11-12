using System.Text.RegularExpressions;

namespace BlastRadius.Api.Matching;

/// <summary>Normalized identity keys so "Jupyter_Server" on PyPI and "jupyter-server" are the same package.</summary>
public static partial class Identity
{
    [GeneratedRegex("[-_.]+")]
    private static partial Regex PipSeparators();

    public static string NormalizePackage(string ecosystem, string name)
    {
        var n = name.Trim().ToLowerInvariant();
        // PEP 503: runs of -, _ and . are equivalent
        return ecosystem.Trim().ToLowerInvariant() == "pip" ? PipSeparators().Replace(n, "-") : n;
    }

    public static string PackageKey(string ecosystem, string name) =>
        $"pkg:{ecosystem.Trim().ToLowerInvariant()}:{NormalizePackage(ecosystem, name)}";

    public static string CpeKey(string vendor, string product) =>
        $"cpe:{vendor.Trim().ToLowerInvariant()}:{product.Trim().ToLowerInvariant()}";
}
