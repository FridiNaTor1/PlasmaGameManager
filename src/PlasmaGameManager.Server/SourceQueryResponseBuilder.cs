using System.Text;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.Server;

public static class SourceQueryResponseBuilder
{
    private static readonly byte[] A2sInfoPrefix =
    [
        0xff, 0xff, 0xff, 0xff, 0x54
    ];

    public static bool TryBuildInfoResponse(GameManagerSession game, ReadOnlySpan<byte> request, out PlasmaResponse response)
    {
        response = new PlasmaResponse(PlasmaCommandKind.SourceProbe, Array.Empty<byte>(), "no source response");
        if (!IsA2sInfoRequest(request))
        {
            return false;
        }

        var bytes = new List<byte>
        {
            0xff, 0xff, 0xff, 0xff,
            0x49,
            17
        };
        WriteCString(bytes, game.Name);
        WriteCString(bytes, game.MapName);
        WriteCString(bytes, "tf");
        WriteCString(bytes, "Team Fortress");
        WriteUInt16LittleEndian(bytes, 440);
        bytes.Add((byte)Math.Clamp(game.Players.Count, 0, 255));
        bytes.Add((byte)Math.Clamp(game.MaxPlayers, 0, 255));
        bytes.Add(0);
        bytes.Add((byte)'d');
        bytes.Add((byte)'l');
        bytes.Add(0);
        bytes.Add(0);
        WriteCString(bytes, "1.0.0.0");

        response = new PlasmaResponse(
            PlasmaCommandKind.SourceProbe,
            bytes.ToArray(),
            "Source A2S_INFO response");
        return true;
    }

    public static bool IsA2sInfoRequest(ReadOnlySpan<byte> request)
    {
        return request.Length >= A2sInfoPrefix.Length
            && request[..A2sInfoPrefix.Length].SequenceEqual(A2sInfoPrefix)
            && PlasmaText.DecodeLossy(request[A2sInfoPrefix.Length..]).Contains("Source Engine Query", StringComparison.OrdinalIgnoreCase);
    }

    private static void WriteCString(List<byte> bytes, string value)
    {
        bytes.AddRange(Encoding.UTF8.GetBytes(value));
        bytes.Add(0);
    }

    private static void WriteUInt16LittleEndian(List<byte> bytes, ushort value)
    {
        bytes.Add((byte)value);
        bytes.Add((byte)(value >> 8));
    }
}
