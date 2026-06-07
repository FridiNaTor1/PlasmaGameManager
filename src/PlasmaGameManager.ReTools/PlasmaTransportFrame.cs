using System.Security.Cryptography;

namespace PlasmaGameManager.ReTools;

public sealed record PlasmaTransportFrame(
    int HeaderBytes,
    int PayloadLength,
    int PaddingLength,
    string Checksum,
    string ChecksumByteOrder,
    byte[] Payload,
    byte[] Padding)
{
    public int BodyLength => PayloadLength + PaddingLength;
    public int FrameLength => HeaderBytes + BodyLength;

    public static bool TryDecode(ReadOnlySpan<byte> data, out PlasmaTransportFrame frame)
    {
        frame = default!;
        if (data.Length < 8)
        {
            return false;
        }

        var payloadLength = (data[4] << 8) | data[5];
        var paddingLength = (data[6] << 8) | data[7];
        var bodyLength = payloadLength + paddingLength;
        if (bodyLength != data.Length - 8 || bodyLength > 0x4a7)
        {
            return false;
        }

        Span<byte> digest = stackalloc byte[16];
        MD5.HashData(data[8..], digest);

        var checksumOrder = "";
        if (data[0] == digest[0] && data[1] == digest[1] && data[2] == digest[2] && data[3] == digest[3])
        {
            checksumOrder = "md5-prefix";
        }
        else if (data[0] == digest[3] && data[1] == digest[2] && data[2] == digest[1] && data[3] == digest[0])
        {
            checksumOrder = "md5-prefix-reversed";
        }
        else
        {
            return false;
        }

        frame = new PlasmaTransportFrame(
            HeaderBytes: 8,
            PayloadLength: payloadLength,
            PaddingLength: paddingLength,
            Checksum: Convert.ToHexString(data[..4]).ToLowerInvariant(),
            ChecksumByteOrder: checksumOrder,
            Payload: data.Slice(8, payloadLength).ToArray(),
            Padding: data.Slice(8 + payloadLength, paddingLength).ToArray());
        return true;
    }
}
