using System.Text.Json;
using System.Text.RegularExpressions;

namespace PlasmaGameManager.ReTools;

public static partial class Bfbc2CallerDecompileReducer
{
    public static async Task ReduceAsync(string dispatcherTablePath, string callerDecompilesPath, string outputPath)
    {
        using var dispatcherDoc = JsonDocument.Parse(File.ReadAllText(dispatcherTablePath));
        using var callersDoc = JsonDocument.Parse(File.ReadAllText(callerDecompilesPath));

        var targetRoles = dispatcherDoc.RootElement.TryGetProperty("targets", out var targetsElement)
            ? targetsElement
                .EnumerateArray()
                .ToDictionary(
                    static e => e.GetProperty("Target").GetString() ?? "",
                    static e => new TargetRole(
                        e.GetProperty("Component").GetString() ?? "",
                        e.GetProperty("InferredRole").GetString() ?? ""),
                    StringComparer.Ordinal)
            : new Dictionary<string, TargetRole>(StringComparer.Ordinal);

        var callerTargetMap = dispatcherDoc.RootElement.TryGetProperty("nextCallerLayerTargets", out var nextCallersElement)
            ? nextCallersElement
                .EnumerateArray()
                .ToDictionary(
                    static e => e.GetProperty("FunctionEntry").GetString() ?? "",
                    e => e.GetProperty("ReferencedTargets").EnumerateArray()
                        .Select(static t => t.GetProperty("Target").GetString() ?? "")
                        .Where(static t => t.Length != 0)
                        .ToArray(),
                    StringComparer.Ordinal)
            : new Dictionary<string, string[]>(StringComparer.Ordinal);

        var functions = callersDoc.RootElement.GetProperty("functions")
            .EnumerateArray()
            .Select(e => BuildFunctionSummary(e, callerTargetMap, targetRoles))
            .OrderBy(static f => f.Entry, StringComparer.Ordinal)
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-bfbc2-caller-layer-decompiles",
            note = "Summarizes the first caller layer above focused BFBC2 Plasma/GameManager functions. This is still below full dispatcher completeness, but it captures concrete native semantics for server callbacks and backend setup.",
            functions,
            nativeSemantics = BuildNativeSemantics(functions)
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static FunctionSummary BuildFunctionSummary(
        JsonElement functionElement,
        Dictionary<string, string[]> callerTargetMap,
        Dictionary<string, TargetRole> targetRoles)
    {
        var entry = functionElement.TryGetProperty("entry", out var entryElement)
            ? entryElement.GetString() ?? ""
            : functionElement.GetProperty("requested").GetString() ?? "";
        var body = functionElement.TryGetProperty("body", out var bodyElement) ? bodyElement.GetString() ?? "" : "";
        callerTargetMap.TryGetValue(entry, out var referencedTargets);
        referencedTargets ??= Array.Empty<string>();

        var targetSummaries = referencedTargets
            .Select(target =>
            {
                targetRoles.TryGetValue(target, out var role);
                return new TargetSummary(target, role?.Component ?? "Unknown", role?.Role ?? "unclassified");
            })
            .ToArray();

        var attributeIndices = AttributeSetterPattern().Matches(body)
            .Select(static m => int.Parse(m.Groups["index"].Value))
            .Distinct()
            .Order()
            .ToArray();
        var branchConstants = BranchConstantPattern().Matches(body)
            .Select(static m => m.Groups["value"].Value)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var logStrings = LogStringPattern().Matches(body)
            .Select(static m => m.Groups["value"].Value)
            .Where(static s => IsRelevantLogString(s))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var stateOffsets = StateOffsetPattern().Matches(body)
            .Select(static m => "0x" + m.Groups["offset"].Value)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();

        return new FunctionSummary(
            entry,
            functionElement.GetProperty("name").GetString() ?? "",
            functionElement.GetProperty("signature").GetString() ?? "",
            body.Length,
            functionElement.TryGetProperty("instructions", out var instructions) ? instructions.GetArrayLength() : 0,
            targetSummaries,
            attributeIndices,
            branchConstants,
            logStrings,
            stateOffsets,
            InferSemantics(body, targetSummaries, attributeIndices, branchConstants, logStrings));
    }

    private static object BuildNativeSemantics(FunctionSummary[] functions)
    {
        return new
        {
            BackendAttributeSlots = functions
                .Where(static f => f.AttributeIndices.Length != 0)
                .Select(static f => new
                {
                    f.Entry,
                    f.Name,
                    Indices = f.AttributeIndices,
                    Meaning = "BFBC2 ServerBackend initializes/updates attribute slots 0 through 8 through one focused setter target."
                })
                .ToArray(),
            AssociationCallbacks = functions
                .Where(static f => f.Semantics.Contains("association", StringComparison.OrdinalIgnoreCase))
                .Select(static f => new
                {
                    f.Entry,
                    f.Name,
                    BranchConstants = f.BranchConstants,
                    StateOffsets = f.StateOffsets,
                    LogStrings = f.LogStrings,
                    Meaning = "Association-add handling branches on result code, validates owner/associate objects, mutates backend association lists, and can trigger deferred dog-tag send when fewer than three pending entries remain."
                })
                .ToArray(),
            CleanupCallbacks = functions
                .Where(static f => f.Semantics.Contains("cleanup", StringComparison.OrdinalIgnoreCase) || f.Semantics.Contains("destructor", StringComparison.OrdinalIgnoreCase))
                .Select(static f => new
                {
                    f.Entry,
                    f.Name,
                    f.Semantics,
                    Targets = f.ReferencedTargets
                })
                .ToArray()
        };
    }

    private static string InferSemantics(
        string body,
        TargetSummary[] targets,
        int[] attributeIndices,
        string[] branchConstants,
        string[] logStrings)
    {
        if (attributeIndices.SequenceEqual(Enumerable.Range(0, 9)))
        {
            return "server backend bulk attribute-slot update for slots 0 through 8";
        }

        if (logStrings.Any(static s => s.Contains("onAssociationsAdded", StringComparison.Ordinal)))
        {
            var branches = branchConstants.Length == 0 ? "" : $" Branches: {string.Join(", ", branchConstants)}.";
            return "server backend association-add callback; handles owner and associate records, association result codes, and queued association state." + branches;
        }

        if (targets.Any(static t => t.Role.Contains("player-left", StringComparison.Ordinal)))
        {
            return "server game manager player-left cleanup bridge";
        }

        if (targets.Any(static t => t.Role.Contains("voice cleanup", StringComparison.Ordinal)))
        {
            return "server game manager listener player voice cleanup bridge";
        }

        if (targets.Any(static t => t.Role.Contains("destructor", StringComparison.Ordinal)))
        {
            return "lifecycle destructor/cleanup wrapper";
        }

        if (body.Contains("FUN_00a02190", StringComparison.Ordinal))
        {
            return "association completion path can issue deferred dog-tag send";
        }

        return targets.Length == 0 ? "unclassified caller-layer function" : "caller-layer wrapper around focused GameManager target";
    }

    private static bool IsRelevantLogString(string value)
    {
        return value.Contains("ServerBackend", StringComparison.Ordinal)
            || value.Contains("ServerGameManager", StringComparison.Ordinal)
            || value.Contains("Association", StringComparison.Ordinal)
            || value.Contains("associate", StringComparison.Ordinal)
            || value.Contains("owner", StringComparison.Ordinal)
            || value.Contains("Player", StringComparison.Ordinal);
    }

    private sealed record TargetRole(string Component, string Role);

    private sealed record TargetSummary(string Target, string Component, string Role);

    private sealed record FunctionSummary(
        string Entry,
        string Name,
        string Signature,
        int BodyLength,
        int InstructionSampleCount,
        TargetSummary[] ReferencedTargets,
        int[] AttributeIndices,
        string[] BranchConstants,
        string[] LogStrings,
        string[] StateOffsets,
        string Semantics);

    [GeneratedRegex("FUN_009c6e00\\([^,]+,(?<index>[0-9]+),", RegexOptions.CultureInvariant)]
    private static partial Regex AttributeSetterPattern();

    [GeneratedRegex("param_2 == (?<value>-?0x[0-9a-f]+|-?[0-9]+)", RegexOptions.CultureInvariant)]
    private static partial Regex BranchConstantPattern();

    [GeneratedRegex("\"(?<value>[^\"]+)\"", RegexOptions.CultureInvariant)]
    private static partial Regex LogStringPattern();

    [GeneratedRegex("param_1 \\+ 0x(?<offset>[0-9a-f]+)", RegexOptions.CultureInvariant)]
    private static partial Regex StateOffsetPattern();
}
