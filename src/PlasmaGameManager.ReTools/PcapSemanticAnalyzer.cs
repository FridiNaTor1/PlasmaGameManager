using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class PcapSemanticAnalyzer
{
    private readonly PlasmaPacketClassifier _classifier = new();
    private readonly GameManagerCommandDecoder _commandDecoder = new();

    public async Task AnalyzeDirectoryAsync(string inputDirectory, string outputPath, string? tf2DispatcherMapPath = null)
    {
        var semanticCatalog = Tf2Ps3PcapSemanticCatalog.LoadOrDefault(tf2DispatcherMapPath);
        var files = Directory.EnumerateFiles(inputDirectory, "*.*", SearchOption.AllDirectories)
            .Where(static p => p.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            .OrderBy(static p => p, StringComparer.Ordinal)
            .ToArray();

        var result = new List<object>();
        foreach (var file in files)
        {
            var packets = CaptureUdpPacketParser.ReadUdpPackets(file)
                .Where(p => p.Payload.Length > 0)
                .Select(p =>
                {
                    var hasTransportFrame = PlasmaTransportFrame.TryDecode(p.Payload, out var transportFrame);
                    var semanticPayload = hasTransportFrame ? transportFrame.Payload : p.Payload;
                    var decoded = _classifier.Decode(semanticPayload, enableNativeBinary: hasTransportFrame);
                    var command = _commandDecoder.Decode(decoded);
                    var phase = GameManagerScenarioPhaseClassifier.Classify(command, p.SourcePort, p.DestinationPort);
                    var markerOffset = PcapPacketConfidence.FindMarkerOffset(semanticPayload, decoded.Marker);
                    var confidence = PcapPacketConfidence.Classify(semanticPayload, decoded, hasTransportFrame, markerOffset);
                    var semantic = semanticCatalog.Explain(command, decoded.Marker, confidence, hasTransportFrame);
                    return new SemanticPcapPacket(
                        p.PacketIndex,
                        $"{p.SourceAddress}:{p.SourcePort}",
                        $"{p.DestinationAddress}:{p.DestinationPort}",
                        "unknown",
                        p.Payload.Length,
                        semanticPayload.Length,
                        hasTransportFrame
                            ? new
                            {
                                Type = "bfbc2-plasma-md5-length",
                                transportFrame.HeaderBytes,
                                transportFrame.PayloadLength,
                                transportFrame.PaddingLength,
                                transportFrame.FrameLength,
                                transportFrame.Checksum,
                                transportFrame.ChecksumByteOrder
                            }
                            : null,
                        phase,
                        decoded.Kind,
                        decoded.Marker,
                        markerOffset,
                        confidence,
                        semantic,
                        command.Name,
                        command.TransactionId,
                        command.LocalId,
                        command.GameId,
                        command.PlayerId,
                        decoded.Explanation,
                        decoded.Fields,
                        decoded.HexPrefix(32),
                        decoded.AsciiPreview(96));
                })
                .ToArray();
            var conversation = InferConversationEndpoints(packets);
            var directedPackets = packets
                .Select(packet => packet with { Direction = DirectionFor(packet, conversation.ClientEndpoint, conversation.ServerEndpoint) })
                .ToArray();

            result.Add(new
            {
                File = Path.GetRelativePath(inputDirectory, file),
                UdpPacketCount = directedPackets.Length,
                Conversation = conversation,
                GameManagerLikeCount = directedPackets.Count(p => p.Kind != PlasmaCommandKind.Unknown),
                HighConfidenceGameManagerLikeCount = directedPackets.Count(p =>
                    p.Kind != PlasmaCommandKind.Unknown && p.Confidence == "high"),
                MediumOrHighConfidenceGameManagerLikeCount = directedPackets.Count(p =>
                    p.Kind != PlasmaCommandKind.Unknown && p.Confidence is "medium" or "high"),
                PhaseCounts = directedPackets
                    .GroupBy(p => p.Phase.ToString())
                    .OrderBy(g => g.Key, StringComparer.Ordinal)
                    .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal),
                DirectionCounts = directedPackets
                    .GroupBy(static p => p.Direction)
                    .OrderBy(g => g.Key, StringComparer.Ordinal)
                    .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal),
                SemanticRoleCounts = directedPackets
                    .GroupBy(static p => p.Semantic.Role)
                    .OrderBy(g => g.Key, StringComparer.Ordinal)
                    .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal),
                KindCounts = directedPackets
                    .GroupBy(p => p.Kind.ToString())
                    .OrderBy(g => g.Key, StringComparer.Ordinal)
                    .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal),
                ClientPackets = directedPackets
                    .Where(static packet => packet.Direction == "client-to-server")
                    .Select(PacketConversationView.From)
                    .ToArray(),
                ServerPackets = directedPackets
                    .Where(static packet => packet.Direction == "server-to-client")
                    .Select(PacketConversationView.From)
                    .ToArray(),
                Packets = directedPackets
            });
        }

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(result, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
    }

    private static PcapConversationEndpoints InferConversationEndpoints(IReadOnlyList<SemanticPcapPacket> packets)
    {
        var serverHello = packets.FirstOrDefault(static p => p.Kind == PlasmaCommandKind.ServerHello);
        if (serverHello is not null)
        {
            return new PcapConversationEndpoints(serverHello.Destination, serverHello.Source, "server-hello");
        }

        var clientHello = packets.FirstOrDefault(static p => p.Kind == PlasmaCommandKind.ClientHello);
        if (clientHello is not null)
        {
            return new PcapConversationEndpoints(clientHello.Source, clientHello.Destination, "client-hello");
        }

        var gameManagerLike = packets.FirstOrDefault(static p => p.Kind != PlasmaCommandKind.Unknown);
        return gameManagerLike is null
            ? new PcapConversationEndpoints("", "", "none")
            : new PcapConversationEndpoints(gameManagerLike.Source, gameManagerLike.Destination, "first-gamemanager-like");
    }

    private static string DirectionFor(SemanticPcapPacket packet, string clientEndpoint, string serverEndpoint)
    {
        if (clientEndpoint.Length == 0 || serverEndpoint.Length == 0)
        {
            return "unknown";
        }

        if (packet.Source == clientEndpoint && packet.Destination == serverEndpoint)
        {
            return "client-to-server";
        }

        if (packet.Source == serverEndpoint && packet.Destination == clientEndpoint)
        {
            return "server-to-client";
        }

        return "other";
    }
}

public sealed record PcapConversationEndpoints(
    string ClientEndpoint,
    string ServerEndpoint,
    string InferredFrom);

public sealed record PacketConversationView(
    long PacketIndex,
    string Direction,
    string Role,
    string PlainText,
    PlasmaCommandKind Kind,
    string? Marker,
    int? NativeType,
    int RawLength,
    int Length,
    string HexPrefix)
{
    public static PacketConversationView From(SemanticPcapPacket packet)
    {
        return new PacketConversationView(
            packet.PacketIndex,
            packet.Direction,
            packet.Semantic.Role,
            packet.Semantic.PlainText,
            packet.Kind,
            packet.Marker,
            packet.Semantic.NativeType,
            packet.RawLength,
            packet.Length,
            packet.HexPrefix);
    }
}

public sealed record SemanticPcapPacket(
    long PacketIndex,
    string Source,
    string Destination,
    string Direction,
    int RawLength,
    int Length,
    object? Transport,
    GameManagerScenarioPhase Phase,
    PlasmaCommandKind Kind,
    string? Marker,
    int? MarkerOffset,
    string Confidence,
    PcapSemanticExplanation Semantic,
    string Command,
    int? TransactionId,
    long? LocalId,
    long? GameId,
    int? PlayerId,
    string Explanation,
    IReadOnlyDictionary<string, string> Fields,
    string HexPrefix,
    string AsciiPreview);
