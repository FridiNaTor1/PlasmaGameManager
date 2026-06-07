namespace PlasmaGameManager.Protocol;

public sealed record GameManagerCommand(
    PlasmaCommandKind Kind,
    string Name,
    int? TransactionId,
    long? LocalId,
    long? GameId,
    int? PlayerId,
    IReadOnlyDictionary<string, string> Fields,
    byte[] RawPayload)
{
    public bool IsOpaque => Kind is PlasmaCommandKind.Unknown or PlasmaCommandKind.OpaqueControl;
}

public sealed class GameManagerCommandDecoder
{
    private readonly PlasmaPacketClassifier _classifier = new();

    public GameManagerCommand Decode(ReadOnlySpan<byte> payload)
    {
        return Decode(_classifier.Decode(payload));
    }

    public GameManagerCommand Decode(PlasmaPacket packet)
    {
        var name = packet.Marker ?? packet.Kind.ToString();
        return new GameManagerCommand(
            packet.Kind,
            name,
            TryReadInt(packet.Fields, "TID"),
            TryReadLong(packet.Fields, "LID"),
            TryReadLong(packet.Fields, "GID"),
            TryReadInt(packet.Fields, "PID"),
            packet.Fields,
            packet.Payload);
    }

    private static int? TryReadInt(IReadOnlyDictionary<string, string> fields, string key)
    {
        return fields.TryGetValue(key, out var value) && int.TryParse(value, out var parsed) ? parsed : null;
    }

    private static long? TryReadLong(IReadOnlyDictionary<string, string> fields, string key)
    {
        return fields.TryGetValue(key, out var value) && long.TryParse(value, out var parsed) ? parsed : null;
    }
}

public enum GameManagerScenarioPhase
{
    Unknown,
    DiscoveryNoise,
    Hello,
    HandshakeControl,
    Reservation,
    Roster,
    Mesh,
    JoinComplete,
    SourceTraffic
}

public static class GameManagerScenarioPhaseClassifier
{
    public static GameManagerScenarioPhase Classify(GameManagerCommand command, int sourcePort, int destinationPort)
    {
        if (sourcePort is 53 or 67 or 68 or 137 or 138 or 1900 or 5353 or 5355
            || destinationPort is 53 or 67 or 68 or 137 or 138 or 1900 or 5353 or 5355)
        {
            return GameManagerScenarioPhase.DiscoveryNoise;
        }

        if (command.Kind is PlasmaCommandKind.ClientHello or PlasmaCommandKind.ServerHello)
        {
            return GameManagerScenarioPhase.Hello;
        }

        if (command.Kind is PlasmaCommandKind.ReservationRequest or PlasmaCommandKind.ReservationGranted or PlasmaCommandKind.PlayerEntered)
        {
            return GameManagerScenarioPhase.Reservation;
        }

        if (command.Kind is PlasmaCommandKind.Roster or PlasmaCommandKind.RosterAck)
        {
            return GameManagerScenarioPhase.Roster;
        }

        if (command.Kind is PlasmaCommandKind.MeshUpdate or PlasmaCommandKind.JoinAnnouncement or PlasmaCommandKind.MeshAck)
        {
            return GameManagerScenarioPhase.Mesh;
        }

        if (command.Kind is PlasmaCommandKind.JoinComplete or PlasmaCommandKind.HostHello)
        {
            return GameManagerScenarioPhase.JoinComplete;
        }

        if (command.Kind is PlasmaCommandKind.SourceProbe
            || IsSourceOrGameplayPort(sourcePort)
            || IsSourceOrGameplayPort(destinationPort))
        {
            return GameManagerScenarioPhase.SourceTraffic;
        }

        return command.Kind == PlasmaCommandKind.TextCommand ? GameManagerScenarioPhase.HandshakeControl : GameManagerScenarioPhase.Unknown;
    }

    private static bool IsSourceOrGameplayPort(int port)
    {
        return port is 27015 or 27016 || port is >= 3076 and <= 3105;
    }
}
