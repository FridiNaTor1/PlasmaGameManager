using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public sealed class PcapSourceBackendBoundaryAnalyzer
{
    public async Task<PcapSourceBackendBoundaryReport> AnalyzeDirectoryAsync(
        string inputDirectory,
        string outputPath,
        string sourceNetworkAnchorMapPath)
    {
        var report = AnalyzeDirectory(inputDirectory, sourceNetworkAnchorMapPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
        return report;
    }

    public PcapSourceBackendBoundaryReport AnalyzeDirectory(
        string inputDirectory,
        string sourceNetworkAnchorMapPath)
    {
        var bridge = new PcapSourceBridgeContractAnalyzer().AnalyzeDirectory(inputDirectory);
        var readiness = new PcapSourceTranslationReadinessAnalyzer().AnalyzeDirectory(inputDirectory);
        var native = new PcapSourceNativeBuilderCorrelationAnalyzer().AnalyzeDirectory(inputDirectory, sourceNetworkAnchorMapPath);

        var readinessByFile = readiness.Files.ToDictionary(static file => file.File, StringComparer.Ordinal);
        var nativeByFile = native.Files.ToDictionary(static file => file.File, StringComparer.Ordinal);
        var files = bridge.Files
            .Select(file => AnalyzeFile(file, readinessByFile.GetValueOrDefault(file.File), nativeByFile.GetValueOrDefault(file.File)))
            .OrderBy(static file => file.File, StringComparer.Ordinal)
            .ToArray();

        return new PcapSourceBackendBoundaryReport(
            "pcap-source-backend-boundary",
            BuildSummary(files, bridge, readiness, native),
            files);
    }

    private static PcapSourceBackendBoundaryFile AnalyzeFile(
        PcapSourceBridgeContractFile bridge,
        PcapSourceTranslationReadinessFile? readiness,
        PcapSourceNativeBuilderCorrelationFile? native)
    {
        var requiresNativeBackendOrTranslator = readiness?.Readiness == "needs-ps3-source-transport-translator";
        var directPcSourceCompatible = readiness?.Readiness == "pc-source-connectionless-compatible";
        var nativeBuilderCompatible = native?.NativeQueueCompatible ?? false;
        var privateBackendCompatible = bridge.RequiresPublicSourceEndpoint == false
            && requiresNativeBackendOrTranslator
            && nativeBuilderCompatible;
        var boundaryModel = BoundaryModelFor(bridge, requiresNativeBackendOrTranslator, nativeBuilderCompatible);

        return new PcapSourceBackendBoundaryFile(
            bridge.File,
            bridge.HasActiveSourceFlow,
            bridge.PrimaryFlow.ClientEndpoint,
            bridge.PrimaryFlow.ServerEndpoint,
            bridge.SourceTrafficVisibilityModel,
            boundaryModel,
            privateBackendCompatible,
            bridge.RequiresPublicSourceEndpoint,
            bridge.RequiresMultiPortListeners,
            requiresNativeBackendOrTranslator,
            directPcSourceCompatible,
            nativeBuilderCompatible,
            bridge.SourceTrafficPacketCount,
            readiness?.SourcePacketCount ?? 0,
            native?.SourcePacketCount ?? 0,
            readiness?.ClassicConnectionlessPacketCount ?? 0,
            readiness?.BodyContainsPcSourceMarkerCount ?? 0,
            native?.MaxPayloadLength ?? 0,
            bridge.VisibleSourceServerEndpoints,
            bridge.BridgeableVisibleServerEndpoints,
            ConclusionFor(boundaryModel));
    }

    private static PcapSourceBackendBoundarySummary BuildSummary(
        PcapSourceBackendBoundaryFile[] files,
        PcapSourceBridgeContractReport bridge,
        PcapSourceTranslationReadinessReport readiness,
        PcapSourceNativeBuilderCorrelationReport native)
    {
        var active = files.Where(static file => file.HasActiveSourceFlow).ToArray();
        var privateCompatible = active.Count(static file => file.PrivateBackendCompatible);
        var mixed = active.Count(static file => file.BoundaryModel == "mixed-visible-capture-split-required");
        var directPc = active.Count(static file => file.DirectPcSourceCompatible);
        var publicRequired = active.Count(static file => file.RequiresPublicSourceEndpoint == true);
        var conclusion = publicRequired == 0
            && directPc == 0
            && privateCompatible + mixed == active.Length
            && native.Summary.CorpusFitsNativeBuilderEnvelope
            ? "The PCAP corpus supports a PS3-visible GameManager/game-server endpoint with a private PS3-native Source backend or translator. No active capture proves that the PS3 client must know a separate public PC Source endpoint."
            : "The corpus still has active flows that need endpoint or backend-boundary review before the architecture can be treated as proven.";

        return new PcapSourceBackendBoundarySummary(
            files.Length,
            active.Length,
            privateCompatible,
            active.Count(static file => file.BoundaryModel == "ps3-visible-same-flow-private-backend"),
            active.Count(static file => file.BoundaryModel == "ps3-visible-multi-port-private-backend"),
            mixed,
            publicRequired,
            active.Count(static file => file.RequiresPublicSourceEndpoint == false),
            active.Count(static file => file.RequiresPublicSourceEndpoint is null),
            active.Count(static file => file.RequiresPs3NativeBackendOrTranslator),
            directPc,
            active.Count(static file => file.NativeBuilderCompatible),
            bridge.Summary.SourceTrafficPacketCount,
            readiness.Summary.SourcePacketCount,
            native.Summary.SourcePacketCount,
            readiness.Summary.ClassicConnectionlessPacketCount,
            readiness.Summary.BodyContainsPcSourceMarkerCount,
            native.Summary.MaxPayloadLength,
            native.Summary.CorpusFitsNativeBuilderEnvelope,
            conclusion,
            active
                .GroupBy(static file => file.BoundaryModel, StringComparer.Ordinal)
                .OrderBy(static group => group.Key, StringComparer.Ordinal)
                .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.Ordinal));
    }

    private static string BoundaryModelFor(
        PcapSourceBridgeContractFile bridge,
        bool requiresNativeBackendOrTranslator,
        bool nativeBuilderCompatible)
    {
        if (!bridge.HasActiveSourceFlow)
        {
            return "no-active-source-flow";
        }

        if (!requiresNativeBackendOrTranslator || !nativeBuilderCompatible)
        {
            return "backend-boundary-review-required";
        }

        return bridge.CurrentServerCompatibility switch
        {
            "native-proxy-compatible-same-visible-flow" => "ps3-visible-same-flow-private-backend",
            "native-proxy-compatible-with-multi-visible-ports" => "ps3-visible-multi-port-private-backend",
            "mixed-capture-split-required" => "mixed-visible-capture-split-required",
            _ => "backend-boundary-review-required"
        };
    }

    private static string ConclusionFor(string boundaryModel)
    {
        return boundaryModel switch
        {
            "ps3-visible-same-flow-private-backend" =>
                "Client-visible gameplay traffic stays on the same GameManager/game-server UDP flow; a private PS3-native Source backend or translator can sit behind that endpoint.",
            "ps3-visible-multi-port-private-backend" =>
                "Client-visible gameplay traffic stays on the same game-server address pair but uses additional visible UDP ports; bind those ports on the GameManager/game-server side and keep the Source backend private.",
            "mixed-visible-capture-split-required" =>
                "This capture includes additional visible address pairs. Split the capture into individual visible game-server sessions before deriving backend behavior.",
            "backend-boundary-review-required" =>
                "This active flow does not yet prove the private-backend contract because transport readiness or native-builder compatibility is incomplete.",
            _ =>
                "No active post-handoff Source/gameplay flow was found."
        };
    }
}

public sealed record PcapSourceBackendBoundaryReport(
    string Status,
    PcapSourceBackendBoundarySummary Summary,
    PcapSourceBackendBoundaryFile[] Files);

public sealed record PcapSourceBackendBoundarySummary(
    int FileCount,
    int ActiveSourceFlowCount,
    int PrivateBackendCompatibleFileCount,
    int SameFlowPrivateBackendFileCount,
    int MultiPortPrivateBackendFileCount,
    int MixedCaptureSplitRequiredCount,
    int RequiresPublicSourceEndpointCount,
    int DoesNotRequirePublicSourceEndpointCount,
    int PublicSourceEndpointUnknownCount,
    int NeedsPs3NativeBackendOrTranslatorFileCount,
    int DirectPcSourceCompatibleFileCount,
    int NativeBuilderCompatibleFileCount,
    int BridgeSourceTrafficPacketCount,
    int TranslationSourcePacketCount,
    int NativeBuilderSourcePacketCount,
    int ClassicConnectionlessPacketCount,
    int BodyContainsPcSourceMarkerCount,
    int MaxNativePayloadLength,
    bool CorpusFitsNativeBuilderEnvelope,
    string ArchitectureConclusion,
    IReadOnlyDictionary<string, int> BoundaryModelCounts);

public sealed record PcapSourceBackendBoundaryFile(
    string File,
    bool HasActiveSourceFlow,
    string ClientEndpoint,
    string PrimaryGameServerEndpoint,
    string SourceTrafficVisibilityModel,
    string BoundaryModel,
    bool PrivateBackendCompatible,
    bool? RequiresPublicSourceEndpoint,
    bool RequiresMultiPortListeners,
    bool RequiresPs3NativeBackendOrTranslator,
    bool DirectPcSourceCompatible,
    bool NativeBuilderCompatible,
    int BridgeSourceTrafficPacketCount,
    int TranslationSourcePacketCount,
    int NativeBuilderSourcePacketCount,
    int ClassicConnectionlessPacketCount,
    int BodyContainsPcSourceMarkerCount,
    int MaxNativePayloadLength,
    string[] VisibleSourceServerEndpoints,
    string[] BridgeableVisibleServerEndpoints,
    string Conclusion);
