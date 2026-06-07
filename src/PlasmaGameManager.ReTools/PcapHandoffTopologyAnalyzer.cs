using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class PcapHandoffTopologyAnalyzer
{
    private readonly PlasmaPacketClassifier _classifier = new();
    private readonly GameManagerCommandDecoder _commandDecoder = new();

    public async Task<PcapHandoffTopologyReport> AnalyzeDirectoryAsync(
        string inputDirectory,
        string outputPath,
        string? tf2DispatcherMapPath = null)
    {
        var report = AnalyzeDirectory(inputDirectory, tf2DispatcherMapPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
        return report;
    }

    public PcapHandoffTopologyReport AnalyzeDirectory(string inputDirectory, string? tf2DispatcherMapPath = null)
    {
        var files = Directory.EnumerateFiles(inputDirectory, "*.*", SearchOption.AllDirectories)
            .Where(static p => p.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            .OrderBy(static p => p, StringComparer.Ordinal)
            .ToArray();

        var fileReports = files.Select(file => AnalyzeFile(inputDirectory, file)).ToArray();
        return new PcapHandoffTopologyReport(BuildSummary(fileReports), fileReports);
    }

    private PcapHandoffTopologyFile AnalyzeFile(string inputDirectory, string file)
    {
        var packets = CaptureUdpPacketParser.ReadUdpPackets(file)
            .Where(static packet => packet.Payload.Length > 0)
            .Select(AnalyzePacket)
            .ToArray();
        var flow = InferPrimaryFlow(packets);
        var directed = packets
            .Select(packet => packet with
            {
                Direction = DirectionFor(packet, flow.ClientEndpoint, flow.ServerEndpoint),
                IsPrimaryFlow = IsPrimaryFlow(packet, flow.ClientEndpoint, flow.ServerEndpoint),
                SourceServerPort = SourceServerPort(packet, flow.ClientAddress, flow.ServerAddress)
            })
            .ToArray();
        var firstJoinComplete = directed
            .Where(static packet => packet.IsPrimaryFlow && packet.Phase == GameManagerScenarioPhase.JoinComplete)
            .Select(static packet => (long?)packet.PacketIndex)
            .FirstOrDefault();
        var afterJoinComplete = firstJoinComplete is null
            ? Array.Empty<PcapHandoffTopologyPacket>()
            : directed.Where(packet => packet.PacketIndex > firstJoinComplete.Value).ToArray();
        var sourceTraffic = directed.Where(static packet => packet.Phase == GameManagerScenarioPhase.SourceTraffic).ToArray();
        var sourceTrafficOnPrimaryAddressPair = sourceTraffic.Count(packet => IsPrimaryAddressPair(packet, flow.ClientAddress, flow.ServerAddress));
        var sourceTrafficServerEndpointCounts = sourceTraffic
            .Select(packet => SourceServerEndpoint(packet, flow.ClientAddress, flow.ServerAddress))
            .Where(static endpoint => endpoint is not null)
            .GroupBy(static endpoint => endpoint!, StringComparer.Ordinal)
            .OrderBy(static group => group.Key, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.Ordinal);
        var visibilityModel = SourceTrafficVisibilityModel(
            sourceTraffic.Length,
            sourceTraffic.Count(static packet => packet.IsPrimaryFlow),
            sourceTraffic.Length - sourceTrafficOnPrimaryAddressPair);

        return new PcapHandoffTopologyFile(
            Path.GetRelativePath(inputDirectory, file),
            directed.Length,
            flow,
            visibilityModel,
            SourceTrafficVisibilityConclusion(visibilityModel),
            firstJoinComplete,
            directed.Count(static packet => packet.IsPrimaryFlow),
            directed.Count(static packet => !packet.IsPrimaryFlow),
            sourceTraffic.Length,
            sourceTraffic.Count(static packet => packet.IsPrimaryFlow),
            sourceTraffic.Count(static packet => !packet.IsPrimaryFlow),
            sourceTrafficOnPrimaryAddressPair,
            sourceTraffic.Length - sourceTrafficOnPrimaryAddressPair,
            afterJoinComplete.Length,
            afterJoinComplete.Count(static packet => packet.IsPrimaryFlow),
            afterJoinComplete.Count(static packet => !packet.IsPrimaryFlow),
            sourceTraffic
                .Where(static packet => packet.SourceServerPort is not null)
                .GroupBy(static packet => packet.SourceServerPort!.Value)
                .OrderBy(static group => group.Key)
                .ToDictionary(static group => group.Key.ToString(), static group => group.Count(), StringComparer.Ordinal),
            sourceTrafficServerEndpointCounts,
            BuildTopSourceTrafficFlows(sourceTraffic, flow),
            directed
                .Where(static packet => packet.SourceServerPort is not null)
                .GroupBy(static packet => packet.SourceServerPort!.Value)
                .OrderBy(static group => group.Key)
                .ToDictionary(static group => group.Key.ToString(), static group => group.Count(), StringComparer.Ordinal),
            directed
                .GroupBy(static packet => packet.Direction)
                .OrderBy(static group => group.Key, StringComparer.Ordinal)
                .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.Ordinal),
            directed
                .GroupBy(static packet => packet.Phase.ToString())
                .OrderBy(static group => group.Key, StringComparer.Ordinal)
                .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.Ordinal),
            directed
                .Where(static packet => packet.Phase == GameManagerScenarioPhase.SourceTraffic)
                .Take(16)
                .ToArray());
    }

    private PcapHandoffTopologyPacket AnalyzePacket(CaptureUdpPacket packet)
    {
        var hasTransportFrame = PlasmaTransportFrame.TryDecode(packet.Payload, out var transportFrame);
        var semanticPayload = hasTransportFrame ? transportFrame.Payload : packet.Payload;
        var decoded = _classifier.Decode(semanticPayload, enableNativeBinary: hasTransportFrame);
        var command = _commandDecoder.Decode(decoded);
        var phase = GameManagerScenarioPhaseClassifier.Classify(command, packet.SourcePort, packet.DestinationPort);

        return new PcapHandoffTopologyPacket(
            packet.PacketIndex,
            packet.SourceAddress,
            packet.SourcePort,
            packet.DestinationAddress,
            packet.DestinationPort,
            $"{packet.SourceAddress}:{packet.SourcePort}",
            $"{packet.DestinationAddress}:{packet.DestinationPort}",
            "unknown",
            packet.Payload.Length,
            semanticPayload.Length,
            phase,
            decoded.Kind,
            decoded.Marker,
            command.Name,
            false,
            null,
            decoded.HexPrefix(16),
            decoded.AsciiPreview(48));
    }

    private static PcapPrimaryFlow InferPrimaryFlow(IReadOnlyList<PcapHandoffTopologyPacket> packets)
    {
        var serverHello = packets.FirstOrDefault(static packet => packet.Kind == PlasmaCommandKind.ServerHello);
        if (serverHello is not null)
        {
            return FlowFrom(serverHello, serverHello.DestinationEndpoint, serverHello.SourceEndpoint, "server-hello");
        }

        var clientHello = packets.FirstOrDefault(static packet => packet.Kind == PlasmaCommandKind.ClientHello);
        if (clientHello is not null)
        {
            return FlowFrom(clientHello, clientHello.SourceEndpoint, clientHello.DestinationEndpoint, "client-hello");
        }

        var gameManagerLike = packets.FirstOrDefault(static packet => packet.Kind != PlasmaCommandKind.Unknown);
        if (gameManagerLike is not null)
        {
            return FlowFrom(gameManagerLike, gameManagerLike.SourceEndpoint, gameManagerLike.DestinationEndpoint, "first-gamemanager-like");
        }

        return new PcapPrimaryFlow("", "", "", "", 0, 0, "none");
    }

    private static PcapPrimaryFlow FlowFrom(PcapHandoffTopologyPacket packet, string clientEndpoint, string serverEndpoint, string inferredFrom)
    {
        var clientIsSource = clientEndpoint == packet.SourceEndpoint;
        return new PcapPrimaryFlow(
            clientEndpoint,
            serverEndpoint,
            clientIsSource ? packet.SourceAddress : packet.DestinationAddress,
            clientIsSource ? packet.DestinationAddress : packet.SourceAddress,
            clientIsSource ? packet.SourcePort : packet.DestinationPort,
            clientIsSource ? packet.DestinationPort : packet.SourcePort,
            inferredFrom);
    }

    private static bool IsPrimaryFlow(PcapHandoffTopologyPacket packet, string clientEndpoint, string serverEndpoint)
    {
        return clientEndpoint.Length > 0
            && serverEndpoint.Length > 0
            && ((packet.SourceEndpoint == clientEndpoint && packet.DestinationEndpoint == serverEndpoint)
                || (packet.SourceEndpoint == serverEndpoint && packet.DestinationEndpoint == clientEndpoint));
    }

    private static string DirectionFor(PcapHandoffTopologyPacket packet, string clientEndpoint, string serverEndpoint)
    {
        if (clientEndpoint.Length == 0 || serverEndpoint.Length == 0)
        {
            return "unknown";
        }

        if (packet.SourceEndpoint == clientEndpoint && packet.DestinationEndpoint == serverEndpoint)
        {
            return "client-to-server";
        }

        if (packet.SourceEndpoint == serverEndpoint && packet.DestinationEndpoint == clientEndpoint)
        {
            return "server-to-client";
        }

        return "other";
    }

    private static int? SourceServerPort(PcapHandoffTopologyPacket packet, string clientAddress, string serverAddress)
    {
        if (clientAddress.Length == 0 || serverAddress.Length == 0)
        {
            return null;
        }

        if (packet.SourceAddress == clientAddress && packet.DestinationAddress == serverAddress)
        {
            return packet.DestinationPort;
        }

        if (packet.SourceAddress == serverAddress && packet.DestinationAddress == clientAddress)
        {
            return packet.SourcePort;
        }

        return null;
    }

    private static PcapHandoffTopologySummary BuildSummary(PcapHandoffTopologyFile[] files)
    {
        var filesWithSourceTraffic = files.Count(static file => file.SourceTrafficPacketCount > 0);
        var filesWhereSourceUsesPrimaryOnly = files.Count(static file =>
            file.SourceTrafficPacketCount > 0 && file.SourceTrafficOffPrimaryFlowCount == 0);
        var filesWhereSourceUsesPrimaryAddressPairOnly = files.Count(static file =>
            file.SourceTrafficPacketCount > 0 && file.SourceTrafficOtherAddressPairCount == 0);
        var filesWhereSourceUsesSingleServerEndpoint = files.Count(static file =>
            file.SourceTrafficPacketCount > 0 && file.SourceTrafficServerEndpointCounts.Count == 1);
        var visibilityCounts = files
            .GroupBy(static file => file.SourceTrafficVisibilityModel, StringComparer.Ordinal)
            .OrderBy(static group => group.Key, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.Ordinal);
        return new PcapHandoffTopologySummary(
            files.Length,
            files.Sum(static file => file.UdpPacketCount),
            filesWithSourceTraffic,
            filesWhereSourceUsesPrimaryOnly,
            filesWhereSourceUsesPrimaryAddressPairOnly,
            filesWhereSourceUsesSingleServerEndpoint,
            visibilityCounts,
            files.Sum(static file => file.SourceTrafficPacketCount),
            files.Sum(static file => file.SourceTrafficOnPrimaryFlowCount),
            files.Sum(static file => file.SourceTrafficOffPrimaryFlowCount),
            files.Sum(static file => file.SourceTrafficPrimaryAddressPairCount),
            files.Sum(static file => file.SourceTrafficOtherAddressPairCount),
            files.Sum(static file => file.AfterJoinCompletePacketCount),
            files.Sum(static file => file.AfterJoinCompleteOnPrimaryFlowCount),
            files.Sum(static file => file.AfterJoinCompleteOffPrimaryFlowCount));
    }

    private static bool IsPrimaryAddressPair(PcapHandoffTopologyPacket packet, string clientAddress, string serverAddress)
    {
        return clientAddress.Length > 0
            && serverAddress.Length > 0
            && ((packet.SourceAddress == clientAddress && packet.DestinationAddress == serverAddress)
                || (packet.SourceAddress == serverAddress && packet.DestinationAddress == clientAddress));
    }

    private static string SourceTrafficVisibilityModel(
        int sourceTrafficPacketCount,
        int sourceTrafficOnPrimaryFlowCount,
        int sourceTrafficOtherAddressPairCount)
    {
        if (sourceTrafficPacketCount == 0)
        {
            return "no-source-traffic";
        }

        if (sourceTrafficOnPrimaryFlowCount == sourceTrafficPacketCount)
        {
            return "same-visible-gamemanager-flow";
        }

        if (sourceTrafficOtherAddressPairCount == 0)
        {
            return "same-visible-gameserver-address-port-shift";
        }

        return "mixed-visible-gameserver-addresses";
    }

    private static string SourceTrafficVisibilityConclusion(string visibilityModel)
    {
        return visibilityModel switch
        {
            "same-visible-gamemanager-flow" =>
                "Post-handoff Source/gameplay-classified packets stay on the exact visible GameManager UDP endpoint.",
            "same-visible-gameserver-address-port-shift" =>
                "Post-handoff Source/gameplay-classified packets stay on the same visible game-server address pair, but use additional UDP ports.",
            "mixed-visible-gameserver-addresses" =>
                "The capture includes Source/gameplay-classified packets on additional visible address pairs; isolate active flows before deriving backend behavior.",
            _ =>
                "No post-handoff Source/gameplay-classified packets were found in this capture."
        };
    }

    private static string? SourceServerEndpoint(PcapHandoffTopologyPacket packet, string clientAddress, string serverAddress)
    {
        if (!IsPrimaryAddressPair(packet, clientAddress, serverAddress))
        {
            return null;
        }

        return packet.SourceAddress == serverAddress
            ? packet.SourceEndpoint
            : packet.DestinationEndpoint;
    }

    private static PcapSourceTrafficFlow[] BuildTopSourceTrafficFlows(
        IReadOnlyList<PcapHandoffTopologyPacket> sourceTraffic,
        PcapPrimaryFlow primaryFlow)
    {
        return sourceTraffic
            .GroupBy(packet => CanonicalEndpointPair(packet.SourceEndpoint, packet.DestinationEndpoint), StringComparer.Ordinal)
            .Select(group =>
            {
                var first = group.First();
                var sourcePacketCount = group.Count(packet => packet.SourceEndpoint == first.SourceEndpoint);
                var destinationPacketCount = group.Count(packet => packet.SourceEndpoint == first.DestinationEndpoint);
                var isPrimaryAddressPair = IsPrimaryAddressPair(first, primaryFlow.ClientAddress, primaryFlow.ServerAddress);
                var serverEndpoint = SourceServerEndpoint(first, primaryFlow.ClientAddress, primaryFlow.ServerAddress) ?? "";
                return new PcapSourceTrafficFlow(
                    group.Key,
                    group.Count(),
                    isPrimaryAddressPair,
                    group.Any(static packet => packet.IsPrimaryFlow),
                    serverEndpoint,
                    first.SourceEndpoint,
                    first.DestinationEndpoint,
                    sourcePacketCount,
                    destinationPacketCount,
                    group.Min(static packet => packet.PacketIndex),
                    group.Max(static packet => packet.PacketIndex),
                    first.HexPrefix,
                    first.AsciiPreview);
            })
            .OrderByDescending(static flow => flow.PacketCount)
            .ThenBy(static flow => flow.EndpointPair, StringComparer.Ordinal)
            .Take(24)
            .ToArray();
    }

    private static string CanonicalEndpointPair(string left, string right)
    {
        return string.CompareOrdinal(left, right) <= 0
            ? $"{left} <-> {right}"
            : $"{right} <-> {left}";
    }
}

public sealed record PcapHandoffTopologyReport(
    PcapHandoffTopologySummary Summary,
    PcapHandoffTopologyFile[] Files);

public sealed record PcapHandoffTopologySummary(
    int FileCount,
    int UdpPacketCount,
    int FilesWithSourceTraffic,
    int FilesWhereSourceTrafficUsesPrimaryFlowOnly,
    int FilesWhereSourceTrafficUsesPrimaryAddressPairOnly,
    int FilesWhereSourceTrafficUsesSingleServerEndpoint,
    IReadOnlyDictionary<string, int> SourceTrafficVisibilityModelCounts,
    int SourceTrafficPacketCount,
    int SourceTrafficOnPrimaryFlowCount,
    int SourceTrafficOffPrimaryFlowCount,
    int SourceTrafficPrimaryAddressPairCount,
    int SourceTrafficOtherAddressPairCount,
    int AfterJoinCompletePacketCount,
    int AfterJoinCompleteOnPrimaryFlowCount,
    int AfterJoinCompleteOffPrimaryFlowCount);

public sealed record PcapHandoffTopologyFile(
    string File,
    int UdpPacketCount,
    PcapPrimaryFlow PrimaryFlow,
    string SourceTrafficVisibilityModel,
    string SourceTrafficVisibilityConclusion,
    long? FirstJoinCompletePacketIndex,
    int PrimaryFlowPacketCount,
    int OtherFlowPacketCount,
    int SourceTrafficPacketCount,
    int SourceTrafficOnPrimaryFlowCount,
    int SourceTrafficOffPrimaryFlowCount,
    int SourceTrafficPrimaryAddressPairCount,
    int SourceTrafficOtherAddressPairCount,
    int AfterJoinCompletePacketCount,
    int AfterJoinCompleteOnPrimaryFlowCount,
    int AfterJoinCompleteOffPrimaryFlowCount,
    IReadOnlyDictionary<string, int> SourceTrafficServerPortCounts,
    IReadOnlyDictionary<string, int> SourceTrafficServerEndpointCounts,
    PcapSourceTrafficFlow[] TopSourceTrafficFlows,
    IReadOnlyDictionary<string, int> AllPrimaryAddressServerPortCounts,
    IReadOnlyDictionary<string, int> DirectionCounts,
    IReadOnlyDictionary<string, int> PhaseCounts,
    PcapHandoffTopologyPacket[] SourceTrafficSamples);

public sealed record PcapSourceTrafficFlow(
    string EndpointPair,
    int PacketCount,
    bool IsPrimaryAddressPair,
    bool IncludesPrimaryFlow,
    string ServerEndpoint,
    string SampleSourceEndpoint,
    string SampleDestinationEndpoint,
    int PacketsFromSampleSourceEndpoint,
    int PacketsFromSampleDestinationEndpoint,
    long FirstPacketIndex,
    long LastPacketIndex,
    string FirstHexPrefix,
    string FirstAsciiPreview);

public sealed record PcapPrimaryFlow(
    string ClientEndpoint,
    string ServerEndpoint,
    string ClientAddress,
    string ServerAddress,
    int ClientPort,
    int ServerPort,
    string InferredFrom);

public sealed record PcapHandoffTopologyPacket(
    long PacketIndex,
    string SourceAddress,
    int SourcePort,
    string DestinationAddress,
    int DestinationPort,
    string SourceEndpoint,
    string DestinationEndpoint,
    string Direction,
    int RawLength,
    int Length,
    GameManagerScenarioPhase Phase,
    PlasmaCommandKind Kind,
    string? Marker,
    string Command,
    bool IsPrimaryFlow,
    int? SourceServerPort,
    string HexPrefix,
    string AsciiPreview);
