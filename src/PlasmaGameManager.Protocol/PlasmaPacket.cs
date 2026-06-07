using System.Collections.ObjectModel;
using System.Text;

namespace PlasmaGameManager.Protocol;

public sealed record PlasmaPacket(
    PlasmaCommandKind Kind,
    byte[] Payload,
    string? Marker,
    IReadOnlyDictionary<string, string> Fields,
    IReadOnlyList<string> Tokens,
    string Explanation)
{
    public string HexPrefix(int bytes = 16)
    {
        var count = Math.Min(bytes, Payload.Length);
        return Convert.ToHexString(Payload.AsSpan(0, count)).ToLowerInvariant();
    }

    public string AsciiPreview(int bytes = 96)
    {
        var count = Math.Min(bytes, Payload.Length);
        Span<char> chars = stackalloc char[count];
        for (var i = 0; i < count; i++)
        {
            var b = Payload[i];
            chars[i] = b is >= 0x20 and <= 0x7e ? (char)b : '.';
        }

        return new string(chars);
    }

    public static PlasmaPacket Empty { get; } = new(
        PlasmaCommandKind.Empty,
        Array.Empty<byte>(),
        null,
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>()),
        Array.Empty<string>(),
        "empty datagram");
}

public sealed record PlasmaResponse(PlasmaCommandKind Kind, byte[] Payload, string Explanation);

public static class PlasmaText
{
    public static byte[] EncodeLine(string text) => Encoding.ASCII.GetBytes(text);

    public static string DecodeLossy(ReadOnlySpan<byte> data)
    {
        var chars = new char[data.Length];
        for (var i = 0; i < data.Length; i++)
        {
            var b = data[i];
            chars[i] = b is >= 0x20 and <= 0x7e ? (char)b : ' ';
        }

        return new string(chars);
    }
}
