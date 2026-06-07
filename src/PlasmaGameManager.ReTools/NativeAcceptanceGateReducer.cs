using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class NativeAcceptanceGateReducer
{
    public static async Task ReduceAsync(
        string bfbc2DispatcherPath,
        string tf2DispatcherPath,
        string pcapCorpusPath,
        string outputPath,
        string? liveHandoffEvidencePath = null,
        string? sourceBridgeContractPath = null)
    {
        using var bfbc2Doc = JsonDocument.Parse(File.ReadAllText(bfbc2DispatcherPath));
        using var tf2Doc = JsonDocument.Parse(File.ReadAllText(tf2DispatcherPath));
        using var pcapDoc = File.Exists(pcapCorpusPath) ? JsonDocument.Parse(File.ReadAllText(pcapCorpusPath)) : null;
        using var liveDoc = liveHandoffEvidencePath is not null && File.Exists(liveHandoffEvidencePath)
            ? JsonDocument.Parse(File.ReadAllText(liveHandoffEvidencePath))
            : null;
        using var bridgeDoc = sourceBridgeContractPath is not null && File.Exists(sourceBridgeContractPath)
            ? JsonDocument.Parse(File.ReadAllText(sourceBridgeContractPath))
            : null;

        var gates = new[]
        {
            Bfbc2DispatcherGate(bfbc2Doc.RootElement),
            Tf2DispatcherGate(tf2Doc.RootElement),
            PcapCorpusGate(pcapDoc?.RootElement),
            ProfileReplayGate(pcapDoc?.RootElement),
            SourceBridgeContractGate(bridgeDoc?.RootElement),
            LiveRpcs3Gate(liveDoc?.RootElement)
        };

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-current-native-gamemanager-acceptance-evidence",
            overallStatus = gates.All(static gate => gate.Status == "passed") ? "complete" : "incomplete",
            note = "Requirement-by-requirement audit for the PlasmaGameManager plan. This report is intentionally strict: partial reverse-engineering, passing unit tests, and corpus coverage are not treated as live TF2 PS3 completion.",
            inputs = new
            {
                Bfbc2Dispatcher = bfbc2DispatcherPath,
                Tf2Dispatcher = tf2DispatcherPath,
                PcapCorpus = pcapCorpusPath,
                LiveHandoffEvidence = liveHandoffEvidencePath ?? "",
                SourceBridgeContract = sourceBridgeContractPath ?? ""
            },
            summary = new
            {
                GateCount = gates.Length,
                PassedGates = gates.Count(static gate => gate.Status == "passed"),
                IncompleteGates = gates.Count(static gate => gate.Status == "incomplete"),
                MissingEvidenceGates = gates.Count(static gate => gate.Status == "missing-evidence")
            },
            gates
        }, JsonOptions));
    }

    private static AcceptanceGate Bfbc2DispatcherGate(JsonElement root)
    {
        var summary = root.GetProperty("summary");
        var unknownSlots = summary.GetProperty("UnknownListenerSlots").GetInt32();
        var branchCount = summary.GetProperty("HandleMessageBranchCount").GetInt32();
        var confirmedBranches = summary.GetProperty("ConfirmedHandleMessageBranches").GetInt32();
        var nativeTypes = root.GetProperty("nativeOutgoingPacketTypes").EnumerateArray()
            .Select(static packet => packet.GetProperty("Type").GetInt32())
            .Distinct()
            .Order()
            .ToArray();
        var passed = unknownSlots == 0 && branchCount == confirmedBranches && RequiredNativeTypes.All(nativeTypes.Contains);
        return new AcceptanceGate(
            "bfbc2-handler-map-no-unknown-dispatcher-slots",
            passed ? "passed" : "incomplete",
            "BFBC2 handler map has no unknown dispatcher slots and recovered native packet families are represented.",
            new
            {
                UnknownListenerSlots = unknownSlots,
                HandleMessageBranchCount = branchCount,
                ConfirmedHandleMessageBranches = confirmedBranches,
                NativeOutgoingTypes = nativeTypes
            },
            passed ? Array.Empty<string>() : new[] { "Complete BFBC2 listener/handleMessage branch recovery and native packet-type coverage." });
    }

    private static AcceptanceGate Tf2DispatcherGate(JsonElement root)
    {
        var summary = root.GetProperty("summary");
        var unresolvedTargets = root.GetProperty("remainingNativeTargets").EnumerateArray()
            .Select(static target => target.GetProperty("Role").GetString() ?? "")
            .Where(static role => role.Length > 0)
            .ToArray();
        var unresolvedJoinCreateTargets = unresolvedTargets
            .Where(static role => !DeferredTf2NativeRoles.Contains(role, StringComparer.Ordinal))
            .ToArray();
        var deferredNativeTargets = unresolvedTargets
            .Where(static role => DeferredTf2NativeRoles.Contains(role, StringComparer.Ordinal))
            .ToArray();
        var coveredTypes = summary.GetProperty("CoveredPacketTypes").EnumerateArray()
            .Select(static packet => packet.GetInt32())
            .ToArray();
        var requiredRolesCovered = summary.GetProperty("RequiredJoinRolesCovered").GetInt32();
        var requiredRoleCount = summary.GetProperty("RequiredJoinRoleCount").GetInt32();
        var hasRequiredTypes = RequiredTf2NativeTypes.All(coveredTypes.Contains);
        var passed = unresolvedJoinCreateTargets.Length == 0 && requiredRolesCovered == requiredRoleCount && hasRequiredTypes;

        return new AcceptanceGate(
            "tf2ps3-gamemanager-map-covers-join-create-packet-types",
            passed ? "passed" : "incomplete",
            "TF.elf GameManager map covers every packet type used by TF2 join/create flows with implementation-ready entries.",
            new
            {
                RequiredJoinRolesCovered = requiredRolesCovered,
                RequiredJoinRoleCount = requiredRoleCount,
                CoveredPacketTypes = coveredTypes,
                RequiredPacketTypes = RequiredTf2NativeTypes,
                UnresolvedEntryPointRoles = unresolvedJoinCreateTargets,
                DeferredNativeRoles = deferredNativeTargets
            },
            passed ? Array.Empty<string>() : unresolvedJoinCreateTargets.Select(static role => $"Recover implementation-ready TF.elf entry/field order for {role}.").ToArray());
    }

    private static AcceptanceGate PcapCorpusGate(JsonElement? root)
    {
        if (root is null)
        {
            return Missing("pcap-semantic-analyzer-explains-selected-corpus", "Run scripts/analyze-pcap-corpus.sh to produce corpus evidence.");
        }

        var summary = root.Value.GetProperty("Summary");
        var unknownCount = summary.GetProperty("UnknownCount").GetInt32();
        var unknownGameManagerScopeCount = summary.TryGetProperty("UnknownGameManagerScopeCount", out var gameManagerUnknown)
            ? gameManagerUnknown.GetInt32()
            : unknownCount;
        var opaqueCount = summary.GetProperty("OpaqueControlCount").GetInt32();
        var opaqueGameManagerScopeCount = summary.TryGetProperty("OpaqueGameManagerScopeCount", out var gameManagerOpaque)
            ? gameManagerOpaque.GetInt32()
            : opaqueCount;
        var fileCount = summary.GetProperty("FileCount").GetInt32();
        var completeHello = summary.GetProperty("FilesWithCompleteHelloFlow").GetInt32();
        var roster = summary.GetProperty("FilesWithRoster").GetInt32();
        var passed = unknownGameManagerScopeCount == 0 && opaqueGameManagerScopeCount == 0 && completeHello > 0 && roster > 0;
        return new AcceptanceGate(
            "pcap-semantic-analyzer-explains-selected-corpus",
            passed ? "passed" : "incomplete",
            "PCAP semantic analyzer explains all selected GameManager packets and leaves no opaque/unknown GameManager surface.",
            new
            {
                FileCount = fileCount,
                FilesWithCompleteHelloFlow = completeHello,
                FilesWithRoster = roster,
                UnknownCount = unknownCount,
                UnknownGameManagerScopeCount = unknownGameManagerScopeCount,
                UnknownDiscoveryNoiseCount = summary.TryGetProperty("UnknownDiscoveryNoiseCount", out var discoveryUnknown) ? discoveryUnknown.GetInt32() : 0,
                UnknownSourceTrafficCount = summary.TryGetProperty("UnknownSourceTrafficCount", out var sourceUnknown) ? sourceUnknown.GetInt32() : 0,
                OpaqueControlCount = opaqueCount,
                OpaqueGameManagerScopeCount = opaqueGameManagerScopeCount,
                OpaqueSourceTrafficCount = summary.TryGetProperty("OpaqueSourceTrafficCount", out var sourceOpaque) ? sourceOpaque.GetInt32() : 0,
                TopUnknownShapes = root.Value.GetProperty("Summary").GetProperty("TopUnknownShapes")
            },
            passed
                ? Array.Empty<string>()
                : new[]
                {
                    "Reduce the opaque-session-control payload class into typed semantic commands where possible.",
                    "Classify or deliberately exclude remaining unknown UDP payload shapes from the GameManager corpus."
                });
    }

    private static AcceptanceGate ProfileReplayGate(JsonElement? root)
    {
        if (root is null)
        {
            return Missing("tf2-profile-passes-pcap-join-flows-without-replay-fallbacks", "Run scripts/analyze-pcap-corpus.sh and tests to produce profile/corpus evidence.");
        }

        var summary = root.Value.GetProperty("Summary");
        var completeHello = summary.GetProperty("FilesWithCompleteHelloFlow").GetInt32();
        var families = summary.GetProperty("ScenarioFamilies").EnumerateArray()
            .Select(static family => family.GetString() ?? "")
            .Where(static family => family.Length > 0)
            .ToArray();
        var coveredFamilies = RequiredScenarioFamilies.Where(families.Contains).ToArray();
        var passed = completeHello > 0 && coveredFamilies.Length == RequiredScenarioFamilies.Length;
        return new AcceptanceGate(
            "tf2-profile-passes-pcap-join-flows-without-replay-fallbacks",
            passed ? "passed" : "incomplete",
            "TF2 profile can process the selected PCAP join families through semantic handlers without importing old HLE replay artifacts.",
            new
            {
                FilesWithCompleteHelloFlow = completeHello,
                RequiredScenarioFamilies,
                CoveredRequiredScenarioFamilies = coveredFamilies
            },
            passed ? Array.Empty<string>() : RequiredScenarioFamilies.Except(coveredFamilies, StringComparer.Ordinal).Select(family => $"Add semantic PCAP/profile coverage for {family}.").ToArray());
    }

    private static AcceptanceGate LiveRpcs3Gate(JsonElement? root)
    {
        if (root is not null)
        {
            var gateStatus = root.Value.GetProperty("GateStatus").GetString() ?? "missing-evidence";
            var hasSourceHandoff = root.Value.GetProperty("HasSourceHandoffEvent").GetBoolean();
            var hasSourceMotd = root.Value.GetProperty("HasSourceMotdTraffic").GetBoolean();
            return new AcceptanceGate(
                "live-rpcs3-progresses-past-gamemanager-into-source-motd",
                gateStatus,
                "Next live RPCS3 test shows the TF2 PS3 client progressing past GameManager into Source/MOTD traffic.",
                new
                {
                    HasSourceHandoffEvent = hasSourceHandoff,
                    HasSourceMotdTraffic = hasSourceMotd,
                    GameManagerEvents = root.Value.GetProperty("GameManagerEvents"),
                    SourceEvidence = root.Value.GetProperty("SourceEvidence"),
                    MissingReasons = root.Value.GetProperty("MissingReasons")
                },
                gateStatus == "passed"
                    ? Array.Empty<string>()
                    : root.Value.GetProperty("MissingReasons").EnumerateArray()
                        .Select(static reason => reason.GetString() ?? "")
                        .Where(static reason => reason.Length > 0)
                        .ToArray());
        }

        return new AcceptanceGate(
            "live-rpcs3-progresses-past-gamemanager-into-source-motd",
            "missing-evidence",
            "Next live RPCS3 test shows the TF2 PS3 client progressing past GameManager into Source/MOTD traffic.",
            new
            {
                Evidence = "No current live RPCS3 log in this project proves Source/MOTD handoff after the native PlasmaGameManager profile."
            },
            new[]
            {
                "Run a live RPCS3 test with Arcadia pointing EGEG to PlasmaGameManager and PLASMA_EVIDENCE_LOG capturing GameManager events.",
                "Confirm the evidence log contains a source-handoff event and the live capture then shows Source/MOTD traffic."
            });
    }

    private static AcceptanceGate SourceBridgeContractGate(JsonElement? root)
    {
        if (root is null)
        {
            return Missing("pcap-source-bridge-contract-supports-hidden-backend", "Run scripts/analyze-source-bridge-contract.sh to produce Source bridge topology evidence.");
        }

        var summary = root.Value.GetProperty("Summary");
        var activeSourceFlows = summary.GetProperty("ActiveSourceFlowCount").GetInt32();
        var requiresPublicSource = summary.GetProperty("RequiresPublicSourceEndpointCount").GetInt32();
        var doesNotRequirePublicSource = summary.GetProperty("DoesNotRequirePublicSourceEndpointCount").GetInt32();
        var sequenceEstablished = summary.GetProperty("SourceTransportSequenceEstablishedCount").GetInt32();
        var mixed = summary.GetProperty("MixedCaptureSplitRequiredCount").GetInt32();
        var passed = activeSourceFlows > 0
            && requiresPublicSource == 0
            && doesNotRequirePublicSource > 0
            && sequenceEstablished == activeSourceFlows;

        return new AcceptanceGate(
            "pcap-source-bridge-contract-supports-hidden-backend",
            passed ? "passed" : "incomplete",
            "PCAP Source/gameplay traffic supports the hidden backend model: the PS3 client stays on visible GameManager/game-server endpoints while Source backend semantics sit behind the bridge.",
            new
            {
                ActiveSourceFlowCount = activeSourceFlows,
                SameVisibleFlowCompatibleCount = summary.GetProperty("SameVisibleFlowCompatibleCount").GetInt32(),
                MultiVisiblePortCompatibleCount = summary.GetProperty("MultiVisiblePortCompatibleCount").GetInt32(),
                MixedCaptureSplitRequiredCount = mixed,
                RequiresPublicSourceEndpointCount = requiresPublicSource,
                DoesNotRequirePublicSourceEndpointCount = doesNotRequirePublicSource,
                SourceTransportSequenceEstablishedCount = sequenceEstablished,
                CompatibilityCounts = summary.GetProperty("CompatibilityCounts")
            },
            passed
                ? mixed > 0
                    ? new[] { "Split mixed captures before deriving backend behavior from their secondary visible game-server address pairs." }
                    : Array.Empty<string>()
                : new[]
                {
                    "Resolve any active Source/gameplay flow that appears to require a public Source endpoint.",
                    "Establish the PS3 Source/gameplay transport sequence model for every active source flow."
                });
    }

    private static AcceptanceGate Missing(string id, string nextStep)
    {
        return new AcceptanceGate(id, "missing-evidence", id, new { }, new[] { nextStep });
    }

    private static readonly int[] RequiredNativeTypes = { 2, 3, 4, 5, 8, 9 };
    private static readonly int[] RequiredTf2NativeTypes = { 2, 3, 4, 5, 8, 9, 11 };
    private static readonly string[] DeferredTf2NativeRoles =
    {
        "player-inactivity-timeout"
    };
    private static readonly string[] RequiredScenarioFamilies =
    {
        "quick-match-to-motd",
        "custom-match-join-to-motd",
        "create-and-join",
        "2fort-play",
        "dustbowl-play",
        "connection"
    };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}

public sealed record AcceptanceGate(
    string Id,
    string Status,
    string Requirement,
    object Evidence,
    string[] NextWork);
