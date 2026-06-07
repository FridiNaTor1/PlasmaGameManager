using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Tf2Ps3UnresolvedExportPlanWriter
{
    public static async Task WriteAsync(string unresolvedTargetsPath, string outputDir)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(unresolvedTargetsPath));
        var targets = doc.RootElement.GetProperty("targets").EnumerateArray()
            .Select(Target.From)
            .ToArray();

        Directory.CreateDirectory(outputDir);

        var addressLines = BuildGroupedLines(targets, target => target.AddressContextTargets);
        var functionLines = BuildGroupedLines(targets, target => target.FunctionContextTargets);
        var helperLines = BuildGroupedLines(targets, target => target.HelperCallerTargets);

        await File.WriteAllLinesAsync(Path.Combine(outputDir, "tf2ps3-unresolved-address-context-targets.txt"), addressLines);
        await File.WriteAllLinesAsync(Path.Combine(outputDir, "tf2ps3-unresolved-function-context-targets.txt"), functionLines);
        await File.WriteAllLinesAsync(Path.Combine(outputDir, "tf2ps3-unresolved-helper-caller-targets.txt"), helperLines);

        await File.WriteAllTextAsync(Path.Combine(outputDir, "tf2ps3-unresolved-export-plan-summary.json"), JsonSerializer.Serialize(new
        {
            status = "seeded-from-tf2ps3-unresolved-targets",
            input = unresolvedTargetsPath,
            outputDir,
            summary = new
            {
                TargetCount = targets.Length,
                AddressContextTargetCount = targets.SelectMany(static target => target.AddressContextTargets).Distinct(StringComparer.Ordinal).Count(),
                FunctionContextTargetCount = targets.SelectMany(static target => target.FunctionContextTargets).Distinct(StringComparer.Ordinal).Count(),
                HelperCallerTargetCount = targets.SelectMany(static target => target.HelperCallerTargets).Distinct(StringComparer.Ordinal).Count()
            },
            files = new
            {
                AddressContextTargets = Path.Combine(outputDir, "tf2ps3-unresolved-address-context-targets.txt"),
                FunctionContextTargets = Path.Combine(outputDir, "tf2ps3-unresolved-function-context-targets.txt"),
                HelperCallerTargets = Path.Combine(outputDir, "tf2ps3-unresolved-helper-caller-targets.txt")
            },
            targets = targets.Select(static target => new
            {
                target.Role,
                target.Priority,
                target.AddressContextTargets,
                target.FunctionContextTargets,
                target.HelperCallerTargets
            }).ToArray()
        }, JsonOptions));
    }

    private static string[] BuildGroupedLines(Target[] targets, Func<Target, string[]> selector)
    {
        var lines = new List<string>
        {
            "# Generated from re/tf2ps3/unresolved-targets.json.",
            "# Blank/comment lines are ignored by the Ghidra exporters."
        };
        var emitted = new HashSet<string>(StringComparer.Ordinal);

        foreach (var target in targets.OrderByDescending(static target => PriorityRank(target.Priority)).ThenBy(static target => target.Role, StringComparer.Ordinal))
        {
            var values = selector(target)
                .Where(static value => value.Length > 0)
                .Distinct(StringComparer.Ordinal)
                .Where(emitted.Add)
                .Order(StringComparer.Ordinal)
                .ToArray();
            if (values.Length == 0)
            {
                continue;
            }

            lines.Add("");
            lines.Add($"# {target.Priority}: {target.Role}");
            lines.AddRange(values);
        }

        return lines.ToArray();
    }

    private static int PriorityRank(string priority)
    {
        return priority switch
        {
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0
        };
    }

    private sealed record Target(
        string Role,
        string Priority,
        string[] AddressContextTargets,
        string[] FunctionContextTargets,
        string[] HelperCallerTargets)
    {
        public static Target From(JsonElement element)
        {
            return new Target(
                GetString(element, "Role"),
                GetString(element, "Priority"),
                Strings(element, "AddressContextTargets"),
                Strings(element, "FunctionContextTargets"),
                Strings(element, "HelperCallerTargets"));
        }
    }

    private static string[] Strings(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var array) || array.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<string>();
        }

        return array.EnumerateArray()
            .Select(static value => value.GetString() ?? "")
            .Where(static value => value.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    private static string GetString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) ? value.GetString() ?? "" : "";
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}
