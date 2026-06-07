using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace PlasmaGameManager.Protocol;

public static class Ps3SourceGameplaySignatures
{
    public static string BodyRunSignature(IEnumerable<byte[]> payloads)
    {
        var bytes = new List<byte>();
        AppendBodyRun(bytes, payloads);
        return Sha256Hex(bytes);
    }

    public static string TurnBodySignature(
        IEnumerable<byte[]> clientPayloads,
        IEnumerable<byte[]> serverPayloads)
    {
        var bytes = new List<byte>();
        bytes.Add(0x43); // C
        AppendBodyRun(bytes, clientPayloads);
        bytes.Add(0x53); // S
        AppendBodyRun(bytes, serverPayloads);
        return Sha256Hex(bytes);
    }

    public static string ShapeRunSignature(IEnumerable<byte[]> payloads)
    {
        var bytes = new List<byte>();
        foreach (var payload in payloads)
        {
            if (Ps3SourceTransportPacket.TryDecode(payload, out var decoded))
            {
                AppendInt32(bytes, (int)Ps3SourceGameplaySession.ClassifyShape(decoded));
                AppendInt32(bytes, decoded.Body.Length);
            }
            else
            {
                AppendInt32(bytes, (int)Ps3SourceGameplayPacketShape.Invalid);
                AppendInt32(bytes, payload.Length);
            }
        }

        return Sha256Hex(bytes);
    }

    private static void AppendBodyRun(List<byte> bytes, IEnumerable<byte[]> payloads)
    {
        var payloadArray = payloads as byte[][] ?? payloads.ToArray();
        AppendInt32(bytes, payloadArray.Length);
        foreach (var payload in payloadArray)
        {
            var body = Ps3SourceTransportPacket.TryDecode(payload, out var decoded)
                ? decoded.Body.AsSpan()
                : payload.AsSpan();
            AppendInt32(bytes, body.Length);
            foreach (var value in body)
            {
                bytes.Add(value);
            }
        }
    }

    private static void AppendInt32(List<byte> bytes, int value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buffer, value);
        bytes.AddRange(buffer);
    }

    private static string Sha256Hex(List<byte> bytes)
    {
        return Convert.ToHexString(SHA256.HashData(CollectionsMarshal.AsSpan(bytes))).ToLowerInvariant();
    }
}
