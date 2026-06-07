using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace PlasmaGameManager.Protocol;

public static class PlasmaFieldParser
{
    private static readonly Regex FieldPattern = new(
        @"(?<key>[A-Za-z0-9_.-]+)=(?<value>""[^""]*""|[^,\s\)]+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static IReadOnlyDictionary<string, string> ParseFields(string text)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in FieldPattern.Matches(text))
        {
            var key = match.Groups["key"].Value.Trim();
            var value = match.Groups["value"].Value.Trim().Trim('"');
            if (key.Length != 0)
            {
                fields[key] = value;
            }
        }

        return new ReadOnlyDictionary<string, string>(fields);
    }

    public static IReadOnlyList<string> Tokenize(string text)
    {
        var tokens = new List<string>();
        var start = -1;
        var quoted = false;

        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '"')
            {
                quoted = !quoted;
            }

            if (!quoted && char.IsWhiteSpace(c))
            {
                if (start >= 0)
                {
                    tokens.Add(text[start..i]);
                    start = -1;
                }
            }
            else if (start < 0)
            {
                start = i;
            }
        }

        if (start >= 0)
        {
            tokens.Add(text[start..]);
        }

        return tokens;
    }
}
