namespace PlasmaGameManager.Protocol;

public sealed class GameManagerBinaryMessageBuilder
{
    private readonly List<byte> _bytes = [];

    private GameManagerBinaryMessageBuilder(byte messageType)
    {
        _bytes.Add(PlasmaIntegerCodec.WriteBiasedSByte(checked((sbyte)messageType)));
    }

    public static GameManagerBinaryMessageBuilder Message(byte messageType)
    {
        return new GameManagerBinaryMessageBuilder(messageType);
    }

    public static GameManagerBinaryMessageBuilder Addressed(byte messageType, int playerId)
    {
        return new GameManagerBinaryMessageBuilder(messageType).WriteBiasedInt32(playerId);
    }

    public GameManagerBinaryMessageBuilder WriteBiasedByte(sbyte value)
    {
        _bytes.Add(PlasmaIntegerCodec.WriteBiasedSByte(value));
        return this;
    }

    public GameManagerBinaryMessageBuilder WriteBiasedInt16(short value)
    {
        Span<byte> bytes = stackalloc byte[2];
        PlasmaIntegerCodec.WriteUInt16BigEndian(bytes, PlasmaIntegerCodec.WriteBiasedInt16(value));
        _bytes.AddRange(bytes);
        return this;
    }

    public GameManagerBinaryMessageBuilder WriteBiasedInt32(int value)
    {
        Span<byte> bytes = stackalloc byte[4];
        PlasmaIntegerCodec.WriteUInt32BigEndian(bytes, PlasmaIntegerCodec.WriteBiasedInt32(value));
        _bytes.AddRange(bytes);
        return this;
    }

    public GameManagerBinaryMessageBuilder WriteRaw(ReadOnlySpan<byte> value)
    {
        _bytes.AddRange(value);
        return this;
    }

    public byte[] Build()
    {
        return _bytes.ToArray();
    }
}
