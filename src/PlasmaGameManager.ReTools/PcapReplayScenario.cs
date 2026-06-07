using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed record PcapReplayPacket(
    long PacketIndex,
    string Source,
    string Destination,
    int RawLength,
    int Length,
    PlasmaCommandKind Kind,
    GameManagerScenarioPhase Phase,
    string Confidence,
    string? Marker,
    int? MarkerOffset,
    string Command,
    int? TransactionId,
    long? LocalId,
    long? GameId,
    int? PlayerId);

public sealed record PcapReplaySummary(
    string File,
    int UdpPacketCount,
    int GameManagerLikeCount,
    IReadOnlyDictionary<GameManagerScenarioPhase, int> PhaseCounts,
    IReadOnlyDictionary<PlasmaCommandKind, int> KindCounts,
    IReadOnlyList<PcapReplayPacket> Packets)
{
    public bool HasHelloPair =>
        Packets.Any(p => p.Kind == PlasmaCommandKind.ClientHello) &&
        Packets.Any(p => p.Kind == PlasmaCommandKind.ServerHello);

    public bool HasRoster => Packets.Any(p => p.Phase == GameManagerScenarioPhase.Roster);

    public bool HasHandshakeControl => Packets.Any(p => p.Phase == GameManagerScenarioPhase.HandshakeControl);

    public bool HasSourceTraffic => Packets.Any(p => p.Phase == GameManagerScenarioPhase.SourceTraffic);

    public int HighConfidenceGameManagerLikeCount =>
        Packets.Count(p => p.Kind != PlasmaCommandKind.Unknown && p.Confidence == "high");

    public int MediumOrHighConfidenceGameManagerLikeCount =>
        Packets.Count(p => p.Kind != PlasmaCommandKind.Unknown && p.Confidence is "medium" or "high");
}

public sealed class PcapReplayScenario
{
    private readonly PlasmaPacketClassifier _classifier = new();
    private readonly GameManagerCommandDecoder _commandDecoder = new();

    public PcapReplaySummary Analyze(string path)
    {
        var packets = CaptureUdpPacketParser.ReadUdpPackets(path)
            .Where(static p => p.Payload.Length > 0)
            .Select(p =>
            {
                var hasTransportFrame = PlasmaTransportFrame.TryDecode(p.Payload, out var transportFrame);
                var semanticPayload = hasTransportFrame ? transportFrame.Payload : p.Payload;
                var decoded = _classifier.Decode(semanticPayload, enableNativeBinary: hasTransportFrame);
                var command = _commandDecoder.Decode(decoded);
                var phase = GameManagerScenarioPhaseClassifier.Classify(command, p.SourcePort, p.DestinationPort);
                var markerOffset = PcapPacketConfidence.FindMarkerOffset(semanticPayload, decoded.Marker);
                var confidence = PcapPacketConfidence.Classify(semanticPayload, decoded, hasTransportFrame, markerOffset);
                return new PcapReplayPacket(
                    p.PacketIndex,
                    $"{p.SourceAddress}:{p.SourcePort}",
                    $"{p.DestinationAddress}:{p.DestinationPort}",
                    p.Payload.Length,
                    semanticPayload.Length,
                    decoded.Kind,
                    phase,
                    confidence,
                    decoded.Marker,
                    markerOffset,
                    command.Name,
                    command.TransactionId,
                    command.LocalId,
                    command.GameId,
                    command.PlayerId);
            })
            .ToArray();

        return new PcapReplaySummary(
            path,
            packets.Length,
            packets.Count(static p => p.Kind != PlasmaCommandKind.Unknown),
            packets.GroupBy(static p => p.Phase).ToDictionary(static g => g.Key, static g => g.Count()),
            packets.GroupBy(static p => p.Kind).ToDictionary(static g => g.Key, static g => g.Count()),
            packets);
    }
}
