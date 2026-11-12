using System.Text.RegularExpressions;

namespace BlastRadius.Api.Matching;

/// <summary>
/// Compares version strings across ecosystems without knowing which ecosystem they come from.
/// Handles dotted numbers, PEP 440 / SemVer pre-releases (dev &lt; a &lt; b &lt; rc), post-releases
/// (".post1", OpenSSH "p1") and OpenSSL-style letter suffixes ("1.1.1w"). Build metadata after "+" is ignored.
/// The web client has a line-by-line port (web/src/engine/versions.ts); shared/vectors.json pins both.
/// </summary>
public static partial class VersionComparer
{
    private enum Kind { Pre = 0, End = 1, Number = 2, Post = 3 }

    private readonly record struct Token(Kind Kind, long Number, int Rank, string Text);

    private static readonly Dictionary<string, int> PreRanks = new()
    {
        ["dev"] = 0, ["snapshot"] = 0,
        ["a"] = 1, ["alpha"] = 1,
        ["b"] = 2, ["beta"] = 2,
        ["pre"] = 3, ["preview"] = 3, ["m"] = 3,
        ["c"] = 4, ["rc"] = 4, ["cr"] = 4,
    };

    private static readonly HashSet<string> PostWords = ["post", "p", "patch", "pl", "r", "rev"];
    private static readonly HashSet<string> Neutral = ["final", "ga", "release", "stable"];

    [GeneratedRegex(@"\d+|[a-z]+")]
    private static partial Regex TokenPattern();

    public static int Compare(string a, string b)
    {
        var ta = Tokenize(a);
        var tb = Tokenize(b);
        for (int i = 0; i < Math.Max(ta.Count, tb.Count); i++)
        {
            var x = i < ta.Count ? ta[i] : new Token(Kind.End, 0, 0, "");
            var y = i < tb.Count ? tb[i] : new Token(Kind.End, 0, 0, "");
            int c = CompareTokens(x, y);
            if (c != 0) return c;
        }
        return 0;
    }

    private static int CompareTokens(Token x, Token y)
    {
        // A missing component equals zero: 1.0 == 1.0.0
        if (x.Kind == Kind.End && y.Kind == Kind.Number && y.Number == 0) return 0;
        if (y.Kind == Kind.End && x.Kind == Kind.Number && x.Number == 0) return 0;
        if (x.Kind != y.Kind) return x.Kind.CompareTo(y.Kind);
        return x.Kind switch
        {
            Kind.Number => x.Number.CompareTo(y.Number),
            Kind.Pre => x.Rank != y.Rank ? x.Rank.CompareTo(y.Rank) : string.CompareOrdinal(x.Text, y.Text),
            Kind.Post => string.CompareOrdinal(x.Text, y.Text),
            _ => 0,
        };
    }

    private static List<Token> Tokenize(string raw)
    {
        var s = raw.Trim().ToLowerInvariant();
        int plus = s.IndexOf('+');
        if (plus >= 0) s = s[..plus];
        if (s.StartsWith('v') && s.Length > 1 && char.IsDigit(s[1])) s = s[1..];

        var matches = TokenPattern().Matches(s);
        var tokens = new List<Token>(matches.Count);
        for (int i = 0; i < matches.Count; i++)
        {
            var text = matches[i].Value;
            if (char.IsDigit(text[0]))
            {
                tokens.Add(new Token(Kind.Number, long.TryParse(text, out var n) ? n : long.MaxValue, 0, text));
                continue;
            }
            if (Neutral.Contains(text)) continue;
            bool last = i == matches.Count - 1;
            bool afterNumber = i > 0 && char.IsDigit(matches[i - 1].Value[0])
                               && matches[i - 1].Index + matches[i - 1].Length == matches[i].Index;
            if (text.Length == 1 && last && afterNumber)
            {
                // trailing letter glued to a number: OpenSSL 1.1.1w, a later release than 1.1.1
                tokens.Add(new Token(Kind.Post, 0, 0, text));
            }
            else if (PostWords.Contains(text))
            {
                tokens.Add(new Token(Kind.Post, 0, 0, text));
            }
            else
            {
                tokens.Add(new Token(Kind.Pre, 0, PreRanks.GetValueOrDefault(text, 0), text));
            }
        }
        return tokens;
    }
}
