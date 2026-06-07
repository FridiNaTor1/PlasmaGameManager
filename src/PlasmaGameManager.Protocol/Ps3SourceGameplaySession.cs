namespace PlasmaGameManager.Protocol;

public sealed class Ps3SourceGameplaySession
{
    private readonly Dictionary<Ps3SourceGameplayDirection, Ps3SourceGameplayDirectionState> _states = new()
    {
        [Ps3SourceGameplayDirection.ClientToServer] = new(Ps3SourceGameplayDirection.ClientToServer),
        [Ps3SourceGameplayDirection.ServerToClient] = new(Ps3SourceGameplayDirection.ServerToClient)
    };

    public Ps3SourceGameplayObservation Observe(Ps3SourceGameplayDirection direction, ReadOnlySpan<byte> payload)
    {
        if (IsClassicSourceConnectionless(payload))
        {
            return new Ps3SourceGameplayObservation(
                direction,
                false,
                null,
                null,
                payload.Length,
                0,
                Ps3SourceGameplayPacketShape.ClassicConnectionless,
                Ps3SourceNativeFrameKind.EmptyBody,
                0,
                false,
                false,
                _states[direction].PacketCount);
        }

        if (!Ps3SourceTransportPacket.TryDecode(payload, out var packet))
        {
            return new Ps3SourceGameplayObservation(
                direction,
                false,
                null,
                null,
                payload.Length,
                0,
                Ps3SourceGameplayPacketShape.Invalid,
                Ps3SourceNativeFrameKind.EmptyBody,
                0,
                false,
                false,
                _states[direction].PacketCount);
        }

        var state = _states[direction];
        var previous = state.LastSequence;
        int? delta = previous is null
            ? null
            : Ps3SourceTransportPacket.SequenceDelta(previous.Value, packet.CandidateSequence);
        var sequenceDecrease = previous is not null && packet.CandidateSequence < previous.Value;
        var sequenceWrap = sequenceDecrease && delta is > 0;
        var shape = ClassifyShape(packet);
        var nativeFrame = packet.ClassifyNativeFrame();

        state.PacketCount++;
        state.LastSequence = packet.CandidateSequence;
        state.LastBodyLength = packet.Body.Length;
        state.ShapeCounts[shape] = state.ShapeCounts.GetValueOrDefault(shape) + 1;
        if (sequenceDecrease)
        {
            state.SequenceDecreaseCount++;
        }

        return new Ps3SourceGameplayObservation(
            direction,
            true,
            packet.CandidateSequence,
            delta,
            packet.PayloadLength,
            packet.Body.Length,
            shape,
            nativeFrame.Kind,
            Math.Round(Entropy(packet.Body), 3),
            sequenceDecrease,
            sequenceWrap,
            state.PacketCount);
    }

    public Ps3SourceGameplayDirectionState GetState(Ps3SourceGameplayDirection direction)
    {
        return _states[direction];
    }

    public Ps3SourceGameplaySummary BuildSummary()
    {
        var client = _states[Ps3SourceGameplayDirection.ClientToServer];
        var server = _states[Ps3SourceGameplayDirection.ServerToClient];
        return new Ps3SourceGameplaySummary(
            client.PacketCount + server.PacketCount,
            client.PacketCount,
            server.PacketCount,
            client.SequenceDecreaseCount,
            server.SequenceDecreaseCount,
            client.LastSequence,
            server.LastSequence,
            client.ShapeCounts
                .Concat(server.ShapeCounts)
                .GroupBy(static pair => pair.Key)
                .ToDictionary(static group => group.Key, static group => group.Sum(static pair => pair.Value)));
    }

    public static Ps3SourceGameplayPacketShape ClassifyShape(Ps3SourceTransportPacket packet)
    {
        var body = packet.Body;
        if (body.Length < 32)
        {
            return Ps3SourceGameplayPacketShape.ShortControl;
        }

        if (packet.PayloadLength >= 1000 || body.Length >= 998)
        {
            return Ps3SourceGameplayPacketShape.NearMtuFragment;
        }

        if (Entropy(body) >= 7.0)
        {
            return Ps3SourceGameplayPacketShape.HighEntropyBinary;
        }

        if (body.Length >= 256)
        {
            return Ps3SourceGameplayPacketShape.LargeBinary;
        }

        return Ps3SourceGameplayPacketShape.MediumBinary;
    }

    private static bool IsClassicSourceConnectionless(ReadOnlySpan<byte> payload)
    {
        return payload.Length >= 4
            && payload[0] == 0xff
            && payload[1] == 0xff
            && payload[2] == 0xff
            && payload[3] == 0xff;
    }

    private static double Entropy(byte[] body)
    {
        if (body.Length == 0)
        {
            return 0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (var b in body)
        {
            counts[b]++;
        }

        var entropy = 0.0;
        foreach (var count in counts)
        {
            if (count == 0)
            {
                continue;
            }

            var p = count / (double)body.Length;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }
}

public enum Ps3SourceGameplayDirection
{
    ClientToServer,
    ServerToClient
}

public enum Ps3SourceGameplayPacketShape
{
    Invalid,
    ClassicConnectionless,
    ShortControl,
    MediumBinary,
    LargeBinary,
    NearMtuFragment,
    HighEntropyBinary
}

public sealed record Ps3SourceGameplayObservation(
    Ps3SourceGameplayDirection Direction,
    bool IsTransportPacket,
    int? Sequence,
    int? SequenceDeltaFromPreviousSameDirection,
    int PayloadLength,
    int BodyLength,
    Ps3SourceGameplayPacketShape Shape,
    Ps3SourceNativeFrameKind NativeFrameKind,
    double BodyEntropy,
    bool SequenceDecrease,
    bool SequenceWrap,
    int DirectionPacketCount);

public sealed class Ps3SourceGameplayDirectionState
{
    public Ps3SourceGameplayDirectionState(Ps3SourceGameplayDirection direction)
    {
        Direction = direction;
    }

    public Ps3SourceGameplayDirection Direction { get; }

    public int PacketCount { get; set; }

    public ushort? LastSequence { get; set; }

    public int LastBodyLength { get; set; }

    public int SequenceDecreaseCount { get; set; }

    public Dictionary<Ps3SourceGameplayPacketShape, int> ShapeCounts { get; } = new();
}

public sealed record Ps3SourceGameplaySummary(
    int PacketCount,
    int ClientToServerPacketCount,
    int ServerToClientPacketCount,
    int ClientSequenceDecreaseCount,
    int ServerSequenceDecreaseCount,
    int? LastClientSequence,
    int? LastServerSequence,
    IReadOnlyDictionary<Ps3SourceGameplayPacketShape, int> ShapeCounts);
