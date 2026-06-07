using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public sealed class PcapSourceBridgeContractAnalyzer
{
    public async Task<PcapSourceBridgeContractReport> AnalyzeDirectoryAsync(string inputDirectory, string outputPath)
    {
        var report = AnalyzeDirectory(inputDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
        return report;
    }

    public PcapSourceBridgeContractReport AnalyzeDirectory(string inputDirectory)
    {
        var topology = new PcapHandoffTopologyAnalyzer().AnalyzeDirectory(inputDirectory);
        var transport = new PcapSourceTransportSemanticsAnalyzer().AnalyzeDirectory(inputDirectory);
        var transportByFile = transport.Files.ToDictionary(static file => file.File, StringComparer.Ordinal);

        var files = topology.Files
            .Select(file => AnalyzeFile(file, transportByFile.GetValueOrDefault(file.File)))
            .OrderBy(static file => file.File, StringComparer.Ordinal)
            .ToArray();
        return new PcapSourceBridgeContractReport(BuildSummary(files), files);
    }

    private static PcapSourceBridgeContractFile AnalyzeFile(
        PcapHandoffTopologyFile topology,
        PcapSourceTransportSemanticsFile? transport)
    {
        var hasActiveSourceFlow = transport?.HasActiveSourceFlow ?? false;
        var compatible = CompatibilityFor(topology.SourceTrafficVisibilityModel, hasActiveSourceFlow);
        var requiresPublicSourceEndpoint = RequiresPublicSourceEndpoint(compatible);
        var visibleServerEndpoints = topology.SourceTrafficServerEndpointCounts.Keys
            .Order(StringComparer.Ordinal)
            .ToArray();
        var bridgeableServerEndpoints = topology.TopSourceTrafficFlows
            .Where(static flow => flow.IsPrimaryAddressPair && flow.ServerEndpoint.Length > 0)
            .Select(static flow => flow.ServerEndpoint)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();

        return new PcapSourceBridgeContractFile(
            topology.File,
            hasActiveSourceFlow,
            topology.PrimaryFlow,
            topology.SourceTrafficVisibilityModel,
            compatible,
            BridgeConclusion(compatible),
            requiresPublicSourceEndpoint,
            RequiresMultiPortListeners(compatible),
            topology.SourceTrafficPacketCount,
            topology.SourceTrafficOnPrimaryFlowCount,
            topology.SourceTrafficOffPrimaryFlowCount,
            topology.SourceTrafficPrimaryAddressPairCount,
            topology.SourceTrafficOtherAddressPairCount,
            visibleServerEndpoints,
            bridgeableServerEndpoints,
            transport?.ClientSequence ?? EmptySequence("ClientToServer"),
            transport?.ServerSequence ?? EmptySequence("ServerToClient"),
            transport is not null
                && transport.HasActiveSourceFlow
                && transport.ParsedTransportPacketCount == transport.SourcePacketCount
                && transport.SourcePacketCount > 0,
            ActiveSequenceConclusion(transport),
            topology.TopSourceTrafficFlows.Take(8).ToArray());
    }

    private static string CompatibilityFor(string visibilityModel, bool hasActiveSourceFlow)
    {
        if (!hasActiveSourceFlow || visibilityModel == "no-source-traffic")
        {
            return "no-active-source-flow";
        }

        return visibilityModel switch
        {
            "same-visible-gamemanager-flow" => "native-proxy-compatible-same-visible-flow",
            "same-visible-gameserver-address-port-shift" => "native-proxy-compatible-with-multi-visible-ports",
            "mixed-visible-gameserver-addresses" => "mixed-capture-split-required",
            _ => "unknown"
        };
    }

    private static bool? RequiresPublicSourceEndpoint(string compatibility)
    {
        return compatibility switch
        {
            "native-proxy-compatible-same-visible-flow" => false,
            "native-proxy-compatible-with-multi-visible-ports" => false,
            "mixed-capture-split-required" => null,
            _ => null
        };
    }

    private static bool RequiresMultiPortListeners(string compatibility)
    {
        return compatibility == "native-proxy-compatible-with-multi-visible-ports";
    }

    private static string BridgeConclusion(string compatibility)
    {
        return compatibility switch
        {
            "native-proxy-compatible-same-visible-flow" =>
                "The PS3 client-visible Source/gameplay traffic stays on the same GameManager/game-server UDP endpoint. A private Source backend can sit behind the GameManager bridge; the PCAP does not require the client to know a public Source port.",
            "native-proxy-compatible-with-multi-visible-ports" =>
                "The PS3 client-visible Source/gameplay traffic stays on the same game-server address pair but shifts visible UDP ports. This matches a multi-port GameManager/game-server listener with a private Source backend; it still does not require a public Source endpoint.",
            "mixed-capture-split-required" =>
                "The capture contains Source/gameplay traffic on additional visible address pairs. Treat it as multiple visible game-server sessions/flows and split it before deriving backend behavior.",
            "no-active-source-flow" =>
                "No active post-handoff Source/gameplay flow was found in this capture.",
            _ =>
                "The observed flow does not fit a known bridge contract yet."
        };
    }

    private static string ActiveSequenceConclusion(PcapSourceTransportSemanticsFile? transport)
    {
        if (transport is null || !transport.HasActiveSourceFlow)
        {
            return "No active Source/gameplay flow was available for transport checks.";
        }

        if (transport.ParsedTransportPacketCount != transport.SourcePacketCount)
        {
            return "Some active Source/gameplay packets did not fit the candidate PS3 transport envelope.";
        }

        if (transport.ClientSequence.DecreaseCount <= 2 && transport.ServerSequence.DecreaseCount <= 2)
        {
            return "All active Source/gameplay packets decode with the offset-0 big-endian u16 candidate sequence, and both directions are mostly monotonic.";
        }

        return "All active Source/gameplay packets decode with the offset-0 big-endian u16 candidate sequence, but sequence monotonicity needs stream-boundary review.";
    }

    private static PcapSourceBridgeContractSummary BuildSummary(PcapSourceBridgeContractFile[] files)
    {
        var active = files.Where(static file => file.HasActiveSourceFlow).ToArray();
        return new PcapSourceBridgeContractSummary(
            files.Length,
            active.Length,
            active.Count(static file => file.CurrentServerCompatibility == "native-proxy-compatible-same-visible-flow"),
            active.Count(static file => file.CurrentServerCompatibility == "native-proxy-compatible-with-multi-visible-ports"),
            active.Count(static file => file.CurrentServerCompatibility == "mixed-capture-split-required"),
            files.Count(static file => file.CurrentServerCompatibility == "no-active-source-flow"),
            active.Count(static file => file.RequiresPublicSourceEndpoint == true),
            active.Count(static file => file.RequiresPublicSourceEndpoint == false),
            active.Count(static file => file.RequiresPublicSourceEndpoint is null),
            active.Count(static file => file.SourceTransportSequenceEstablished),
            active.Sum(static file => file.SourceTrafficPacketCount),
            active.Sum(static file => file.SourceTrafficPrimaryAddressPairCount),
            active.Sum(static file => file.SourceTrafficOtherAddressPairCount),
            active
                .GroupBy(static file => file.CurrentServerCompatibility, StringComparer.Ordinal)
                .OrderBy(static group => group.Key, StringComparer.Ordinal)
                .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.Ordinal));
    }

    private static PcapSourceSequenceStats EmptySequence(string direction)
    {
        return new PcapSourceSequenceStats(direction, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, []);
    }
}

public sealed record PcapSourceBridgeContractReport(
    PcapSourceBridgeContractSummary Summary,
    PcapSourceBridgeContractFile[] Files);

public sealed record PcapSourceBridgeContractSummary(
    int FileCount,
    int ActiveSourceFlowCount,
    int SameVisibleFlowCompatibleCount,
    int MultiVisiblePortCompatibleCount,
    int MixedCaptureSplitRequiredCount,
    int NoActiveSourceFlowCount,
    int RequiresPublicSourceEndpointCount,
    int DoesNotRequirePublicSourceEndpointCount,
    int PublicSourceEndpointUnknownCount,
    int SourceTransportSequenceEstablishedCount,
    int SourceTrafficPacketCount,
    int SourceTrafficPrimaryAddressPairCount,
    int SourceTrafficOtherAddressPairCount,
    IReadOnlyDictionary<string, int> CompatibilityCounts);

public sealed record PcapSourceBridgeContractFile(
    string File,
    bool HasActiveSourceFlow,
    PcapPrimaryFlow PrimaryFlow,
    string SourceTrafficVisibilityModel,
    string CurrentServerCompatibility,
    string BridgeConclusion,
    bool? RequiresPublicSourceEndpoint,
    bool RequiresMultiPortListeners,
    int SourceTrafficPacketCount,
    int SourceTrafficOnPrimaryFlowCount,
    int SourceTrafficOffPrimaryFlowCount,
    int SourceTrafficPrimaryAddressPairCount,
    int SourceTrafficOtherAddressPairCount,
    string[] VisibleSourceServerEndpoints,
    string[] BridgeableVisibleServerEndpoints,
    PcapSourceSequenceStats ClientSequence,
    PcapSourceSequenceStats ServerSequence,
    bool SourceTransportSequenceEstablished,
    string SourceTransportConclusion,
    PcapSourceTrafficFlow[] TopVisibleSourceFlows);
