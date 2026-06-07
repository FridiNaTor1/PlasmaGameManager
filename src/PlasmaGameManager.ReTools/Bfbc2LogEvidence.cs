using System.Text.Json;
using System.Text.RegularExpressions;

namespace PlasmaGameManager.ReTools;

public static partial class Bfbc2LogEvidence
{
    public static async Task ExportAsync(string inputLog, string outputPath)
    {
        var lines = File.Exists(inputLog) ? File.ReadAllLines(inputLog) : Array.Empty<string>();
        var entries = new List<object>();

        foreach (var line in lines)
        {
            var match = LogLinePattern().Match(line);
            if (!match.Success)
            {
                continue;
            }

            var source = match.Groups["source"].Value;
            var text = match.Groups["text"].Value;
            if (!IsRelevant(source, text))
            {
                continue;
            }

            entries.Add(new
            {
                Source = source,
                Thread = match.Groups["thread"].Value,
                Severity = match.Groups["severity"].Value,
                Text = text,
                Category = Categorize(source, text)
            });
        }

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            Input = inputLog,
            Count = entries.Count,
            Entries = entries
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static bool IsRelevant(string source, string text)
    {
        return source.Contains("/Backend/Plasma/", StringComparison.OrdinalIgnoreCase)
            || source.Contains("/Online/", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Plasma", StringComparison.OrdinalIgnoreCase)
            || text.Contains("ServerBackend", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Map available", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Attempting listen", StringComparison.OrdinalIgnoreCase)
            || text.Contains("The server is called", StringComparison.OrdinalIgnoreCase);
    }

    private static string Categorize(string source, string text)
    {
        if (source.Contains("ServerBackend", StringComparison.OrdinalIgnoreCase) || text.Contains("ServerBackend", StringComparison.OrdinalIgnoreCase))
        {
            return "plasma-server-backend";
        }

        if (source.Contains("ServerMapList", StringComparison.OrdinalIgnoreCase) || text.Contains("Map available", StringComparison.OrdinalIgnoreCase))
        {
            return "map-list";
        }

        if (text.Contains("listen", StringComparison.OrdinalIgnoreCase))
        {
            return "network-listen";
        }

        if (text.Contains("server is called", StringComparison.OrdinalIgnoreCase))
        {
            return "server-identity";
        }

        return "other";
    }

    [GeneratedRegex("\\] (?<source>[^:]+): \\\"(?<thread>[^\\\"]+)\\\": (?<severity>[^:]+): (?<text>.*)$", RegexOptions.CultureInvariant)]
    private static partial Regex LogLinePattern();
}
