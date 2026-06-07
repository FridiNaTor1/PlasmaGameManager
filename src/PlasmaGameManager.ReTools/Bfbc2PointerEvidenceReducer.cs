using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Bfbc2PointerEvidenceReducer
{
    public static async Task ReduceAsync(string handlersPath, string pointerEvidencePath, string dispatcherTablePath)
    {
        using var handlersDoc = JsonDocument.Parse(File.ReadAllText(handlersPath));
        using var pointersDoc = JsonDocument.Parse(File.ReadAllText(pointerEvidencePath));

        var functionEvidence = handlersDoc.RootElement.GetProperty("serverRelevantFunctions")
            .EnumerateArray()
            .ToDictionary(
                static e => e.GetProperty("FunctionEntry").GetString() ?? "",
                static e => new FunctionEvidence(
                    e.GetProperty("Component").GetString() ?? "",
                    e.GetProperty("Function").GetString() ?? "",
                    e.GetProperty("ReferenceCount").GetInt32(),
                    e.GetProperty("EvidenceStrings").EnumerateArray()
                        .Select(static s => s.GetString() ?? "")
                        .Where(static s => s.Length != 0)
                        .ToArray()),
                StringComparer.Ordinal);

        var targets = pointersDoc.RootElement.GetProperty("targets").EnumerateArray()
            .Select(e => BuildTarget(e, functionEvidence))
            .OrderBy(static t => t.Component, StringComparer.Ordinal)
            .ThenBy(static t => t.Target, StringComparer.Ordinal)
            .ToArray();

        var nextCallerLayerTargets = targets
            .SelectMany(static target => target.CallsiteFunctions.Select(caller => new
            {
                Entry = caller.FromFunctionEntry,
                Name = caller.FromFunction,
                Callee = target.Target,
                CalleeComponent = target.Component,
                CalleeRole = target.InferredRole
            }))
            .Where(static caller => caller.Entry.Length != 0)
            .GroupBy(static caller => caller.Entry, StringComparer.Ordinal)
            .Select(static group => new
            {
                FunctionEntry = group.Key,
                Function = group.Select(static caller => caller.Name).FirstOrDefault(static name => name.Length != 0) ?? "",
                ReferencedTargets = group
                    .Select(static caller => new
                    {
                        Target = caller.Callee,
                        Component = caller.CalleeComponent,
                        Role = caller.CalleeRole
                    })
                    .Distinct()
                    .OrderBy(static target => target.Target, StringComparer.Ordinal)
                    .ToArray()
            })
            .OrderBy(static caller => caller.FunctionEntry, StringComparer.Ordinal)
            .ToArray();

        var rawCallsitesNeedingFunctionRecovery = targets
            .SelectMany(static target => target.RawCallsitesWithoutFunction.Select(callsite => new
            {
                callsite.From,
                callsite.Type,
                callsite.Source,
                Callee = target.Target,
                CalleeComponent = target.Component,
                CalleeRole = target.InferredRole
            }))
            .OrderBy(static callsite => callsite.From, StringComparer.Ordinal)
            .ThenBy(static callsite => callsite.Callee, StringComparer.Ordinal)
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(dispatcherTablePath)!);
        await File.WriteAllTextAsync(dispatcherTablePath, JsonSerializer.Serialize(new
        {
            status = "pending-dispatcher-vtable-resolution",
            evidence = "Targeted Ghidra pointer export found direct callsites for BFBC2 Plasma/GameManager functions. It did not recover a complete vtable/dispatcher table yet.",
            summary = new
            {
                TargetCount = targets.Length,
                DirectReferenceCount = targets.Sum(static t => t.DirectReferenceCount),
                DataPointerCount = targets.Sum(static t => t.DataPointerSites.Length),
                PointerTableCandidateCount = targets.Sum(static t => t.PointerTableCandidates.Length),
                NextCallerLayerFunctionCount = nextCallerLayerTargets.Length,
                RawCallsiteRecoveryCount = rawCallsitesNeedingFunctionRecovery.Length
            },
            requiredNextSteps = new[]
            {
                "Export/decompile nextCallerLayerTargets to locate the real dispatcher and message decode layer.",
                "Recover functions around rawCallsitesNeedingFunctionRecovery where Ghidra did not create a function boundary.",
                "Re-run pointer-table recovery after caller-layer functions are recovered and named.",
                "Map caller-layer branches to packet constructors, send targets, and state transitions."
            },
            targets,
            nextCallerLayerTargets,
            rawCallsitesNeedingFunctionRecovery
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static TargetEvidence BuildTarget(JsonElement targetElement, Dictionary<string, FunctionEvidence> functionEvidence)
    {
        var target = targetElement.GetProperty("target").GetString() ?? "";
        functionEvidence.TryGetValue(target, out var evidence);

        var directReferences = targetElement.GetProperty("directReferences").EnumerateArray()
            .Select(static e => new DirectReference(
                e.GetProperty("from").GetString() ?? "",
                e.GetProperty("type").GetString() ?? "",
                e.GetProperty("source").GetString() ?? "",
                e.GetProperty("fromFunction").GetString() ?? "",
                e.GetProperty("fromFunctionEntry").GetString() ?? ""))
            .ToArray();

        var callsiteFunctions = directReferences
            .Where(r => r.FromFunctionEntry.Length != 0 && !StringComparer.Ordinal.Equals(r.FromFunctionEntry, target))
            .GroupBy(static r => $"{r.FromFunctionEntry}|{r.FromFunction}", StringComparer.Ordinal)
            .Select(static group => new CallsiteFunction(
                group.First().FromFunctionEntry,
                group.First().FromFunction,
                group.Select(static r => new Callsite(r.From, r.Type, r.Source)).OrderBy(static r => r.From, StringComparer.Ordinal).ToArray()))
            .OrderBy(static r => r.FromFunctionEntry, StringComparer.Ordinal)
            .ToArray();

        var rawCallsitesWithoutFunction = directReferences
            .Where(static r => r.FromFunctionEntry.Length == 0)
            .Select(static r => new Callsite(r.From, r.Type, r.Source))
            .OrderBy(static r => r.From, StringComparer.Ordinal)
            .ToArray();

        var dataPointerSites = targetElement.GetProperty("dataPointers").EnumerateArray()
            .Select(static e => new DataPointerSite(
                e.GetProperty("address").GetString() ?? "",
                e.GetProperty("block").GetString() ?? "",
                e.GetProperty("writable").GetBoolean(),
                e.GetProperty("executable").GetBoolean()))
            .OrderBy(static r => r.Address, StringComparer.Ordinal)
            .ToArray();

        var pointerTableCandidates = targetElement.GetProperty("pointerTables").EnumerateArray()
            .Select(ReadPointerTableCandidate)
            .ToArray();

        return new TargetEvidence(
            target,
            targetElement.GetProperty("targetName").GetString() ?? "",
            evidence?.Component ?? "Unknown",
            evidence?.Function ?? "",
            evidence?.ReferenceCount ?? 0,
            evidence?.EvidenceStrings ?? Array.Empty<string>(),
            directReferences.Length,
            callsiteFunctions,
            rawCallsitesWithoutFunction,
            dataPointerSites,
            pointerTableCandidates,
            InferRole(evidence?.EvidenceStrings ?? Array.Empty<string>(), evidence?.Component ?? ""));
    }

    private static PointerTableCandidate ReadPointerTableCandidate(JsonElement element)
    {
        var entries = element.TryGetProperty("entries", out var entriesElement)
            ? entriesElement.EnumerateArray()
                .Select(static e => new PointerTableEntry(
                    e.GetProperty("address").GetString() ?? "",
                    e.GetProperty("value").GetString() ?? "",
                    e.TryGetProperty("name", out var nameElement) ? nameElement.GetString() ?? "" : ""))
                .ToArray()
            : Array.Empty<PointerTableEntry>();

        return new PointerTableCandidate(
            element.GetProperty("start").GetString() ?? "",
            element.GetProperty("block").GetString() ?? "",
            entries);
    }

    private static string InferRole(string[] evidenceStrings, string component)
    {
        var evidence = string.Join('\n', evidenceStrings);
        if (evidence.Contains("onAssociationsAdded", StringComparison.Ordinal))
        {
            return "association-add callback";
        }

        if (evidence.Contains("onAssociationOpened", StringComparison.Ordinal))
        {
            return "association-open callback";
        }

        if (evidence.Contains("onPlayerLeft", StringComparison.Ordinal))
        {
            return "player-left callback";
        }

        if (evidence.Contains("onPlayerVoiceCleanup", StringComparison.Ordinal))
        {
            return "player voice cleanup callback";
        }

        if (evidence.Contains("setGameAttributes", StringComparison.Ordinal))
        {
            return "game attribute update";
        }

        if (evidence.Contains("setPersistentServerInfo", StringComparison.Ordinal))
        {
            return "persistent server info update";
        }

        if (evidence.Contains("readPersistentInfo", StringComparison.Ordinal))
        {
            return "persistent info read";
        }

        if (evidence.Contains("issueSendDogTags", StringComparison.Ordinal))
        {
            return "dog tag send path";
        }

        if (evidence.Contains("disconnect", StringComparison.Ordinal) || evidence.Contains("onDisconnect", StringComparison.Ordinal))
        {
            return "disconnect path";
        }

        if (evidence.Contains("::create", StringComparison.Ordinal))
        {
            return "factory/create path";
        }

        if (evidence.Contains("::~", StringComparison.Ordinal))
        {
            return "destructor/cleanup path";
        }

        return component.Length == 0 ? "unclassified" : $"focused {component} target";
    }

    private sealed record FunctionEvidence(string Component, string Function, int ReferenceCount, string[] EvidenceStrings);

    private sealed record TargetEvidence(
        string Target,
        string TargetName,
        string Component,
        string EvidenceFunction,
        int FocusedReferenceCount,
        string[] EvidenceStrings,
        int DirectReferenceCount,
        CallsiteFunction[] CallsiteFunctions,
        Callsite[] RawCallsitesWithoutFunction,
        DataPointerSite[] DataPointerSites,
        PointerTableCandidate[] PointerTableCandidates,
        string InferredRole);

    private sealed record DirectReference(string From, string Type, string Source, string FromFunction, string FromFunctionEntry);

    private sealed record CallsiteFunction(string FromFunctionEntry, string FromFunction, Callsite[] Callsites);

    private sealed record Callsite(string From, string Type, string Source);

    private sealed record DataPointerSite(string Address, string Block, bool Writable, bool Executable);

    private sealed record PointerTableCandidate(string Start, string Block, PointerTableEntry[] Entries);

    private sealed record PointerTableEntry(string Address, string Value, string Name);
}
