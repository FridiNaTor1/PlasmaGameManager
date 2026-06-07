using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class PcapActiveFlowReplayExtractor
{
    private readonly PlasmaPacketClassifier _classifier = new();
    private readonly GameManagerCommandDecoder _commandDecoder = new();

    public PcapActiveFlowReplay? Extract(string path)
    {
        var packets = CaptureUdpPacketParser.ReadUdpPackets(path)
            .Where(static packet => packet.Payload.Length > 0)
            .Select(DecodePacket)
            .ToArray();
        var serverHello = packets.FirstOrDefault(static packet => packet.Decoded.Kind == PlasmaCommandKind.ServerHello);
        if (serverHello is null)
        {
            return null;
        }

        var clientEndpoint = Endpoint(serverHello.Packet.DestinationAddress, serverHello.Packet.DestinationPort);
        var serverEndpoint = Endpoint(serverHello.Packet.SourceAddress, serverHello.Packet.SourcePort);
        var clientHello = packets.LastOrDefault(packet =>
            packet.Packet.PacketIndex < serverHello.Packet.PacketIndex
            && packet.Decoded.Kind == PlasmaCommandKind.ClientHello
            && Endpoint(packet.Packet.SourceAddress, packet.Packet.SourcePort) == clientEndpoint
            && Endpoint(packet.Packet.DestinationAddress, packet.Packet.DestinationPort) == serverEndpoint);
        if (clientHello is null)
        {
            return null;
        }

        var firstSourceClientPacket = packets.FirstOrDefault(packet =>
            packet.Packet.PacketIndex > serverHello.Packet.PacketIndex
            && packet.Phase == GameManagerScenarioPhase.SourceTraffic
            && Endpoint(packet.Packet.SourceAddress, packet.Packet.SourcePort) == clientEndpoint
            && Endpoint(packet.Packet.DestinationAddress, packet.Packet.DestinationPort) == serverEndpoint);
        if (firstSourceClientPacket is null)
        {
            return null;
        }

        var sourceClientPackets = packets
            .Where(packet =>
                packet.Packet.PacketIndex >= firstSourceClientPacket.Packet.PacketIndex
                && packet.Phase == GameManagerScenarioPhase.SourceTraffic
                && Endpoint(packet.Packet.SourceAddress, packet.Packet.SourcePort) == clientEndpoint
                && Endpoint(packet.Packet.DestinationAddress, packet.Packet.DestinationPort) == serverEndpoint)
            .Select(packet => new PcapActiveFlowPayload(
                packet.Packet.PacketIndex,
                packet.Packet.TimestampMicroseconds,
                packet.Packet.Payload,
                packet.Decoded.Kind,
                packet.Decoded.HexPrefix(16),
                packet.Decoded.AsciiPreview(48)))
            .ToArray();
        var sourceServerPackets = packets
            .Where(packet =>
                packet.Packet.PacketIndex > firstSourceClientPacket.Packet.PacketIndex
                && packet.Phase == GameManagerScenarioPhase.SourceTraffic
                && Endpoint(packet.Packet.SourceAddress, packet.Packet.SourcePort) == serverEndpoint
                && Endpoint(packet.Packet.DestinationAddress, packet.Packet.DestinationPort) == clientEndpoint)
            .Select(packet => new PcapActiveFlowPayload(
                packet.Packet.PacketIndex,
                packet.Packet.TimestampMicroseconds,
                packet.Packet.Payload,
                packet.Decoded.Kind,
                packet.Decoded.HexPrefix(16),
                packet.Decoded.AsciiPreview(48)))
            .ToArray();
        var sourcePackets = packets
            .Where(packet =>
                packet.Packet.PacketIndex >= firstSourceClientPacket.Packet.PacketIndex
                && packet.Phase == GameManagerScenarioPhase.SourceTraffic
                && IsActiveFlowPacket(packet, clientEndpoint, serverEndpoint))
            .Select(packet => new PcapActiveFlowDatagram(
                packet.Packet.PacketIndex,
                packet.Packet.TimestampMicroseconds,
                Endpoint(packet.Packet.SourceAddress, packet.Packet.SourcePort) == clientEndpoint
                    ? PcapActiveFlowDirection.ClientToServer
                    : PcapActiveFlowDirection.ServerToClient,
                packet.Packet.Payload,
                packet.Decoded.Kind,
                packet.Decoded.HexPrefix(16),
                packet.Decoded.AsciiPreview(48)))
            .ToArray();

        return new PcapActiveFlowReplay(
            path,
            clientEndpoint,
            serverEndpoint,
            serverHello.Packet.SourcePort,
            clientHello.Packet.PacketIndex,
            serverHello.Packet.PacketIndex,
            firstSourceClientPacket.Packet.PacketIndex,
            clientHello.Packet.Payload,
            firstSourceClientPacket.Packet.Payload,
            firstSourceClientPacket.Decoded.Kind,
            firstSourceClientPacket.Phase,
            firstSourceClientPacket.Decoded.HexPrefix(16),
            firstSourceClientPacket.Decoded.AsciiPreview(48),
            sourceClientPackets,
            sourceServerPackets,
            sourcePackets);
    }

    private DecodedCapturePacket DecodePacket(CaptureUdpPacket packet)
    {
        var hasTransportFrame = PlasmaTransportFrame.TryDecode(packet.Payload, out var transportFrame);
        var semanticPayload = hasTransportFrame ? transportFrame.Payload : packet.Payload;
        var decoded = _classifier.Decode(semanticPayload, enableNativeBinary: hasTransportFrame);
        var command = _commandDecoder.Decode(decoded);
        var phase = GameManagerScenarioPhaseClassifier.Classify(command, packet.SourcePort, packet.DestinationPort);
        return new DecodedCapturePacket(packet, decoded, phase);
    }

    private static string Endpoint(string address, int port) => $"{address}:{port}";

    private static bool IsActiveFlowPacket(DecodedCapturePacket packet, string clientEndpoint, string serverEndpoint)
    {
        var sourceEndpoint = Endpoint(packet.Packet.SourceAddress, packet.Packet.SourcePort);
        var destinationEndpoint = Endpoint(packet.Packet.DestinationAddress, packet.Packet.DestinationPort);
        return (sourceEndpoint == clientEndpoint && destinationEndpoint == serverEndpoint)
            || (sourceEndpoint == serverEndpoint && destinationEndpoint == clientEndpoint);
    }

    private sealed record DecodedCapturePacket(
        CaptureUdpPacket Packet,
        PlasmaPacket Decoded,
        GameManagerScenarioPhase Phase);
}

public sealed record PcapActiveFlowReplay(
    string Path,
    string ClientEndpoint,
    string ServerEndpoint,
    int ServerPort,
    long ClientHelloPacketIndex,
    long ServerHelloPacketIndex,
    long FirstSourceClientPacketIndex,
    byte[] ClientHelloPayload,
    byte[] FirstSourceClientPayload,
    PlasmaCommandKind FirstSourceClientKind,
    GameManagerScenarioPhase FirstSourceClientPhase,
    string FirstSourceHexPrefix,
    string FirstSourceAsciiPreview,
    PcapActiveFlowPayload[] SourceClientPackets,
    PcapActiveFlowPayload[] SourceServerPackets,
    PcapActiveFlowDatagram[] SourcePackets);

public sealed record PcapActiveFlowPayload(
    long PacketIndex,
    long TimestampMicroseconds,
    byte[] Payload,
    PlasmaCommandKind Kind,
    string HexPrefix,
    string AsciiPreview);

public enum PcapActiveFlowDirection
{
    ClientToServer,
    ServerToClient
}

public sealed record PcapActiveFlowDatagram(
    long PacketIndex,
    long TimestampMicroseconds,
    PcapActiveFlowDirection Direction,
    byte[] Payload,
    PlasmaCommandKind Kind,
    string HexPrefix,
    string AsciiPreview);
