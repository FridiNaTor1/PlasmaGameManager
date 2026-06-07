namespace PlasmaGameManager.Protocol;

public static class PlasmaIntegerCodec
{
    public static byte WriteBiasedSByte(sbyte value) => unchecked((byte)(value + 0x80));

    public static sbyte ReadBiasedSByte(byte value) => unchecked((sbyte)(value - 0x80));

    public static ushort WriteBiasedInt16(short value) => unchecked((ushort)(value + 0x8000));

    public static short ReadBiasedInt16(ushort value) => unchecked((short)(value - 0x8000));

    public static uint WriteBiasedInt32(int value) => unchecked((uint)(value + 0x80000000));

    public static int ReadBiasedInt32(uint value) => unchecked((int)(value - 0x80000000));

    public static ushort ReadUInt16BigEndian(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            throw new ArgumentException("Need at least 2 bytes.", nameof(data));
        }

        return (ushort)((data[0] << 8) | data[1]);
    }

    public static uint ReadUInt32BigEndian(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4)
        {
            throw new ArgumentException("Need at least 4 bytes.", nameof(data));
        }

        return ((uint)data[0] << 24) | ((uint)data[1] << 16) | ((uint)data[2] << 8) | data[3];
    }

    public static void WriteUInt16BigEndian(Span<byte> target, ushort value)
    {
        if (target.Length < 2)
        {
            throw new ArgumentException("Need at least 2 bytes.", nameof(target));
        }

        target[0] = (byte)(value >> 8);
        target[1] = (byte)value;
    }

    public static void WriteUInt32BigEndian(Span<byte> target, uint value)
    {
        if (target.Length < 4)
        {
            throw new ArgumentException("Need at least 4 bytes.", nameof(target));
        }

        target[0] = (byte)(value >> 24);
        target[1] = (byte)(value >> 16);
        target[2] = (byte)(value >> 8);
        target[3] = (byte)value;
    }
}
