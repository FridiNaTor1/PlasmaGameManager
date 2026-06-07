using System.Net;

namespace PlasmaGameManager.ReTools;

public sealed record CaptureUdpPacket(
    string SourceAddress,
    int SourcePort,
    string DestinationAddress,
    int DestinationPort,
    byte[] Payload,
    long PacketIndex,
    long TimestampMicroseconds);

public static class CaptureUdpPacketParser
{
    public static IEnumerable<CaptureUdpPacket> ReadUdpPackets(string path)
    {
        using var fs = File.OpenRead(path);
        Span<byte> header = stackalloc byte[4];
        if (fs.Read(header) != 4)
        {
            yield break;
        }

        fs.Position = 0;
        if (header.SequenceEqual(new byte[] { 0x0a, 0x0d, 0x0d, 0x0a }))
        {
            foreach (var packet in ReadPcapNg(fs))
            {
                yield return packet;
            }
        }
        else
        {
            foreach (var packet in ReadPcap(fs))
            {
                yield return packet;
            }
        }
    }

    private static IEnumerable<CaptureUdpPacket> ReadPcapNg(Stream stream)
    {
        var littleEndian = true;
        var packetIndex = 0L;
        var interfaceTimestampResolutions = new Dictionary<uint, byte>();

        while (TryReadExact(stream, 8, out var blockHeader))
        {
            var blockType = ReadUInt32(blockHeader, 0, littleEndian: true);
            var blockLength = ReadUInt32(blockHeader, 4, littleEndian);
            if (blockLength < 12 || blockLength > 128 * 1024 * 1024)
            {
                yield break;
            }

            if (!TryReadExact(stream, (int)blockLength - 8, out var blockRest))
            {
                yield break;
            }

            if (blockType == 0x0a0d0d0a && blockRest.Length >= 16)
            {
                var magic = ReadUInt32(blockRest, 0, littleEndian: true);
                littleEndian = magic == 0x1a2b3c4d;
            }
            else if (blockType == 0x00000001 && blockRest.Length >= 12)
            {
                var interfaceIndex = (uint)interfaceTimestampResolutions.Count;
                interfaceTimestampResolutions[interfaceIndex] = ReadPcapNgTimestampResolution(blockRest, littleEndian);
            }
            else if (blockType == 0x00000006 && blockRest.Length >= 20)
            {
                var interfaceId = ReadUInt32(blockRest, 0, littleEndian);
                var timestampHigh = ReadUInt32(blockRest, 4, littleEndian);
                var timestampLow = ReadUInt32(blockRest, 8, littleEndian);
                var timestamp = ((ulong)timestampHigh << 32) | timestampLow;
                var resolution = interfaceTimestampResolutions.TryGetValue(interfaceId, out var parsedResolution)
                    ? parsedResolution
                    : (byte)6;
                var timestampMicroseconds = ConvertPcapNgTimestampToMicroseconds(timestamp, resolution);
                var capturedLength = (int)ReadUInt32(blockRest, 12, littleEndian);
                if (capturedLength < 0 || 20 + capturedLength > blockRest.Length)
                {
                    continue;
                }

                var packet = blockRest.AsSpan(20, capturedLength).ToArray();
                if (TryExtractUdp(packet, timestampMicroseconds, out var udp))
                {
                    yield return udp with { PacketIndex = ++packetIndex };
                }
            }
        }
    }

    private static IEnumerable<CaptureUdpPacket> ReadPcap(Stream stream)
    {
        if (!TryReadExact(stream, 24, out var globalHeader))
        {
            yield break;
        }

        var littleEndian = MatchesMagic(globalHeader, 0xd4, 0xc3, 0xb2, 0xa1)
            || MatchesMagic(globalHeader, 0x4d, 0x3c, 0xb2, 0xa1);
        var nanosecondResolution = MatchesMagic(globalHeader, 0x4d, 0x3c, 0xb2, 0xa1)
            || MatchesMagic(globalHeader, 0xa1, 0xb2, 0x3c, 0x4d);

        var packetIndex = 0L;
        while (TryReadExact(stream, 16, out var recordHeader))
        {
            var timestampSeconds = ReadUInt32(recordHeader, 0, littleEndian);
            var timestampFraction = ReadUInt32(recordHeader, 4, littleEndian);
            var timestampMicroseconds = ((long)timestampSeconds * 1_000_000)
                + (nanosecondResolution ? timestampFraction / 1_000 : timestampFraction);
            var capturedLength = (int)ReadUInt32(recordHeader, 8, littleEndian);
            if (capturedLength < 0 || capturedLength > 32 * 1024 * 1024)
            {
                yield break;
            }

            if (!TryReadExact(stream, capturedLength, out var packet))
            {
                yield break;
            }

            if (TryExtractUdp(packet, timestampMicroseconds, out var udp))
            {
                yield return udp with { PacketIndex = ++packetIndex };
            }
        }
    }

    private static bool TryExtractUdp(ReadOnlySpan<byte> packet, long timestampMicroseconds, out CaptureUdpPacket udp)
    {
        udp = default!;
        var offset = 0;

        if (packet.Length >= 14 && packet[12] == 0x08 && packet[13] == 0x00)
        {
            offset = 14;
        }
        else if (packet.Length >= 16 && packet[14] == 0x08 && packet[15] == 0x00)
        {
            offset = 16; // Linux cooked capture.
        }
        else if (packet.Length >= 1 && (packet[0] >> 4) == 4)
        {
            offset = 0; // Raw IPv4.
        }
        else
        {
            return false;
        }

        if (packet.Length < offset + 20 || (packet[offset] >> 4) != 4)
        {
            return false;
        }

        var ihl = (packet[offset] & 0x0f) * 4;
        if (ihl < 20 || packet.Length < offset + ihl + 8 || packet[offset + 9] != 17)
        {
            return false;
        }

        var sourceIp = new IPAddress(packet.Slice(offset + 12, 4));
        var destinationIp = new IPAddress(packet.Slice(offset + 16, 4));
        var udpOffset = offset + ihl;
        var sourcePort = (packet[udpOffset] << 8) | packet[udpOffset + 1];
        var destinationPort = (packet[udpOffset + 2] << 8) | packet[udpOffset + 3];
        var udpLength = (packet[udpOffset + 4] << 8) | packet[udpOffset + 5];
        if (udpLength < 8 || udpOffset + udpLength > packet.Length)
        {
            return false;
        }

        udp = new CaptureUdpPacket(
            sourceIp.ToString(),
            sourcePort,
            destinationIp.ToString(),
            destinationPort,
            packet.Slice(udpOffset + 8, udpLength - 8).ToArray(),
            0,
            timestampMicroseconds);
        return true;
    }

    private static byte ReadPcapNgTimestampResolution(ReadOnlySpan<byte> interfaceDescriptionBody, bool littleEndian)
    {
        // Interface Description Block fixed body is 8 bytes; options follow and end before the trailing block length.
        var offset = 8;
        var end = interfaceDescriptionBody.Length - 4;
        while (offset + 4 <= end)
        {
            var optionCode = ReadUInt16(interfaceDescriptionBody, offset, littleEndian);
            var optionLength = ReadUInt16(interfaceDescriptionBody, offset + 2, littleEndian);
            offset += 4;
            if (optionCode == 0)
            {
                break;
            }

            if (offset + optionLength > end)
            {
                break;
            }

            if (optionCode == 9 && optionLength >= 1)
            {
                return interfaceDescriptionBody[offset];
            }

            offset += Align32(optionLength);
        }

        return 6;
    }

    private static long ConvertPcapNgTimestampToMicroseconds(ulong timestamp, byte resolution)
    {
        if ((resolution & 0x80) == 0)
        {
            var decimalPlaces = resolution;
            if (decimalPlaces == 6)
            {
                return (long)timestamp;
            }

            var divisor = Pow10(decimalPlaces);
            return (long)((timestamp * 1_000_000UL) / divisor);
        }

        var binaryPlaces = resolution & 0x7f;
        return (long)((timestamp * 1_000_000UL) >> binaryPlaces);
    }

    private static int Align32(int value)
    {
        return (value + 3) & ~3;
    }

    private static ulong Pow10(int exponent)
    {
        var value = 1UL;
        for (var i = 0; i < exponent; i++)
        {
            value *= 10;
        }

        return value;
    }

    private static bool TryReadExact(Stream stream, int length, out byte[] data)
    {
        data = new byte[length];
        var offset = 0;
        while (offset < data.Length)
        {
            var read = stream.Read(data, offset, data.Length - offset);
            if (read == 0)
            {
                return false;
            }

            offset += read;
        }

        return true;
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset, bool littleEndian)
    {
        return littleEndian
            ? (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24))
            : (uint)((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]);
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset, bool littleEndian)
    {
        return littleEndian
            ? (ushort)(data[offset] | (data[offset + 1] << 8))
            : (ushort)((data[offset] << 8) | data[offset + 1]);
    }

    private static bool MatchesMagic(ReadOnlySpan<byte> data, byte a, byte b, byte c, byte d)
    {
        return data.Length >= 4 && data[0] == a && data[1] == b && data[2] == c && data[3] == d;
    }
}
