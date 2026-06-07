using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public sealed class PcapClientVisibleSourceEndpointAnalyzer
{
    public async Task<PcapClientVisibleSourceEndpointReport> AnalyzeDirectoryAsync(
        string inputDirectory,
        string outputPath)
    {
        var report = AnalyzeDirectory(inputDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
        return report;
    }

    public PcapClientVisibleSourceEndpointReport AnalyzeDirectory(string inputDirectory)
    {
        var bridge = new PcapSourceBridgeContractAnalyzer().AnalyzeDirectory(inputDirectory);
        var readiness = new PcapSourceTranslationReadinessAnalyzer().AnalyzeDirectory(inputDirectory);
        var readinessByFile = readiness.Files.ToDictionary(static file => file.File, StringComparer.Ordinal);
        var files = bridge.Files
            .Select(file => AnalyzeFile(file, readinessByFile.GetValueOrDefault(file.File)))
            .OrderBy(static file => file.File, StringComparer.Ordinal)
            .ToArray();
        return new PcapClientVisibleSourceEndpointReport(BuildSummary(files), files);
    }

    private static PcapClientVisibleSourceEndpointFile AnalyzeFile(
        PcapSourceBridgeContractFile bridge,
        PcapSourceTranslationReadinessFile? readiness)
    {
        var proofModel = ProofModelFor(bridge);
        return new PcapClientVisibleSourceEndpointFile(
            bridge.File,
            bridge.HasActiveSourceFlow,
            proofModel,
            ProofConclusion(proofModel),
            bridge.PrimaryFlow.ClientEndpoint,
            bridge.PrimaryFlow.ServerEndpoint,
            bridge.PrimaryFlow.InferredFrom,
            bridge.SourceTrafficVisibilityModel,
            bridge.SourceTrafficPacketCount,
            bridge.SourceTrafficOnPrimaryFlowCount,
            bridge.SourceTrafficOffPrimaryFlowCount,
            bridge.SourceTrafficPrimaryAddressPairCount,
            bridge.SourceTrafficOtherAddressPairCount,
            bridge.RequiresPublicSourceEndpoint,
            bridge.RequiresMultiPortListeners,
            bridge.VisibleSourceServerEndpoints,
            bridge.BridgeableVisibleServerEndpoints,
            bridge.SourceTransportSequenceEstablished,
            readiness?.Readiness == "pc-source-connectionless-compatible",
            readiness?.Readiness == "needs-ps3-source-transport-translator",
            readiness?.ClassicConnectionlessPacketCount ?? 0,
            readiness?.BodyContainsPcSourceMarkerCount ?? 0,
            bridge.TopVisibleSourceFlows);
    }

    private static PcapClientVisibleSourceEndpointSummary BuildSummary(PcapClientVisibleSourceEndpointFile[] files)
    {
        var active = files.Where(static file => file.HasActiveSourceFlow).ToArray();
        var analyzable = active.Where(static file => file.RequiresPublicSourceEndpoint == false).ToArray();
        var unknown = active.Where(static file => file.RequiresPublicSourceEndpoint is null).ToArray();
        var conclusion = active.Length > 0
            && active.Count(static file => file.RequiresPublicSourceEndpoint == true) == 0
            ? "The PCAP corpus proves the PS3 client's visible Source/gameplay traffic stays on the advertised GameManager/game-server surface for analyzable captures. Mixed captures must be split before deriving a single-session boundary. No active capture proves that the PS3 client needs a separate public PC Source endpoint."
            : "The PCAP corpus still contains active flows that could require a separate public Source endpoint.";

        return new PcapClientVisibleSourceEndpointSummary(
            files.Length,
            active.Length,
            files.Count(static file => file.ProofModel == "no-active-source-flow"),
            active.Count(static file => file.ProofModel == "same-visible-gamemanager-flow"),
            active.Count(static file => file.ProofModel == "same-game-server-address-multi-port"),
            active.Count(static file => file.ProofModel == "mixed-capture-needs-split"),
            active.Count(static file => file.ProofModel == "unknown"),
            active.Count(static file => file.RequiresPublicSourceEndpoint == true),
            analyzable.Length,
            unknown.Length,
            active.Count(static file => file.DirectPcSourceCompatible),
            active.Count(static file => file.RequiresPs3SourceTransportTranslator),
            active.Sum(static file => file.SourceTrafficPacketCount),
            active.Sum(static file => file.SourceTrafficOnPrimaryFlowCount),
            active.Sum(static file => file.SourceTrafficOffPrimaryFlowCount),
            active.Sum(static file => file.SourceTrafficPrimaryAddressPairCount),
            active.Sum(static file => file.SourceTrafficOtherAddressPairCount),
            active
                .SelectMany(static file => file.VisibleSourceServerEndpoints)
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray(),
            conclusion);
    }

    private static string ProofModelFor(PcapSourceBridgeContractFile bridge)
    {
        if (!bridge.HasActiveSourceFlow)
        {
            return "no-active-source-flow";
        }

        return bridge.CurrentServerCompatibility switch
        {
            "native-proxy-compatible-same-visible-flow" => "same-visible-gamemanager-flow",
            "native-proxy-compatible-with-multi-visible-ports" => "same-game-server-address-multi-port",
            "mixed-capture-split-required" => "mixed-capture-needs-split",
            _ => "unknown"
        };
    }

    private static string ProofConclusion(string proofModel)
    {
        return proofModel switch
        {
            "same-visible-gamemanager-flow" =>
                "This capture proves the PS3 client-visible Source/gameplay phase stays on the exact same UDP flow as the inferred GameManager server hello.",
            "same-game-server-address-multi-port" =>
                "This capture proves the PS3 client-visible Source/gameplay phase stays on the same client/server address pair, but uses additional visible UDP ports on the same game-server address.",
            "mixed-capture-needs-split" =>
                "This capture contains more than one visible game-server address pair. Split it into individual sessions before using it as backend-boundary proof.",
            "no-active-source-flow" =>
                "This capture has no active post-handoff Source/gameplay flow.",
            _ =>
                "This capture does not yet fit a known client-visible endpoint proof model."
        };
    }
}

public sealed record PcapClientVisibleSourceEndpointReport(
    PcapClientVisibleSourceEndpointSummary Summary,
    PcapClientVisibleSourceEndpointFile[] Files);

public sealed record PcapClientVisibleSourceEndpointSummary(
    int FileCount,
    int ActiveSourceFlowCount,
    int NoActiveSourceFlowCount,
    int SameVisibleGameManagerFlowCount,
    int SameGameServerAddressMultiPortCount,
    int MixedCaptureNeedsSplitCount,
    int UnknownActiveFlowCount,
    int RequiresPublicSourceEndpointCount,
    int DoesNotRequirePublicSourceEndpointCount,
    int PublicSourceEndpointUnknownCount,
    int DirectPcSourceCompatibleCount,
    int RequiresPs3SourceTransportTranslatorCount,
    int SourceTrafficPacketCount,
    int SourceTrafficOnPrimaryFlowCount,
    int SourceTrafficOffPrimaryFlowCount,
    int SourceTrafficPrimaryAddressPairCount,
    int SourceTrafficOtherAddressPairCount,
    string[] VisibleSourceServerEndpoints,
    string Conclusion);

public sealed record PcapClientVisibleSourceEndpointFile(
    string File,
    bool HasActiveSourceFlow,
    string ProofModel,
    string ProofConclusion,
    string PrimaryClientEndpoint,
    string PrimaryGameManagerServerEndpoint,
    string PrimaryFlowInferredFrom,
    string SourceTrafficVisibilityModel,
    int SourceTrafficPacketCount,
    int SourceTrafficOnPrimaryFlowCount,
    int SourceTrafficOffPrimaryFlowCount,
    int SourceTrafficPrimaryAddressPairCount,
    int SourceTrafficOtherAddressPairCount,
    bool? RequiresPublicSourceEndpoint,
    bool RequiresMultiPortListeners,
    string[] VisibleSourceServerEndpoints,
    string[] BridgeableVisibleServerEndpoints,
    bool SourceTransportSequenceEstablished,
    bool DirectPcSourceCompatible,
    bool RequiresPs3SourceTransportTranslator,
    int ClassicConnectionlessPacketCount,
    int PcSourceMarkerPacketCount,
    PcapSourceTrafficFlow[] TopVisibleSourceFlows);
