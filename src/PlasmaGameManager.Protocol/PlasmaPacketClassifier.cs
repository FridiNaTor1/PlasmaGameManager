using System.Collections.ObjectModel;
using System.Text;

namespace PlasmaGameManager.Protocol;

public sealed class PlasmaPacketClassifier
{
    private static readonly string[] KnownMarkers =
    [
        "EGEG", "EGRS", "PENT", "UBRA", "UGAM", "COc", "PNG", "DSC", "PONG", "PING",
        "AddAssociations", "Join", "Leave", "Start", "Mesh", "Roster"
    ];

    public PlasmaPacket Decode(ReadOnlySpan<byte> payload, bool enableNativeBinary = false)
    {
        if (payload.IsEmpty)
        {
            return PlasmaPacket.Empty;
        }

        var bytes = payload.ToArray();
        var text = PlasmaText.DecodeLossy(payload);
        var marker = FindMarker(text);
        var fields = new Dictionary<string, string>(PlasmaFieldParser.ParseFields(text), StringComparer.OrdinalIgnoreCase);
        var nativeType = enableNativeBinary ? TryReadNativeMessageType(payload) : null;
        if (nativeType is not null)
        {
            fields["NativeType"] = nativeType.Value.ToString();
        }

        var tokens = PlasmaFieldParser.Tokenize(text);
        var kind = Classify(payload, text, marker, fields, enableNativeBinary);

        return new PlasmaPacket(
            kind,
            bytes,
            marker,
            new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(fields, StringComparer.OrdinalIgnoreCase)),
            tokens,
            Explain(kind, bytes, marker, fields));
    }

    public static bool LooksAscii(ReadOnlySpan<byte> payload)
    {
        if (payload.IsEmpty)
        {
            return false;
        }

        var printable = 0;
        foreach (var b in payload)
        {
            if (b is >= 0x20 and <= 0x7e or 0x09 or 0x0a or 0x0d)
            {
                printable++;
            }
        }

        return printable >= payload.Length * 0.70;
    }

    private static PlasmaCommandKind Classify(
        ReadOnlySpan<byte> payload,
        string text,
        string? marker,
        IReadOnlyDictionary<string, string> fields,
        bool enableNativeBinary)
    {
        if (payload.Length == 24 && !LooksAscii(payload))
        {
            return PlasmaCommandKind.ClientHello;
        }

        if (payload.Length == 20 && !LooksAscii(payload))
        {
            return PlasmaCommandKind.ServerHello;
        }

        if (marker is "EGEG")
        {
            return PlasmaCommandKind.ReservationRequest;
        }

        if (marker is "EGRS")
        {
            return PlasmaCommandKind.ReservationGranted;
        }

        if (marker is "PENT")
        {
            return PlasmaCommandKind.PlayerEntered;
        }

        if (marker is "UGAM")
        {
            return PlasmaCommandKind.JoinAnnouncement;
        }

        if (marker is "UBRA")
        {
            return fields.ContainsKey("JOIN") ? PlasmaCommandKind.MeshUpdate : PlasmaCommandKind.RosterAck;
        }

        if (marker is "COc" or "PNG" or "DSC"
            && IsStructuredRosterMarker(payload, FindAsciiMarkerOffset(payload, marker)))
        {
            return PlasmaCommandKind.Roster;
        }

        if (text.Contains("AddAssociations", StringComparison.OrdinalIgnoreCase))
        {
            return PlasmaCommandKind.MeshUpdate;
        }

        if (text.Contains("TID=", StringComparison.OrdinalIgnoreCase) || text.Contains("LID=", StringComparison.OrdinalIgnoreCase))
        {
            return PlasmaCommandKind.TextCommand;
        }

        if (payload.Length >= 256 && Entropy(payload) > 7.0)
        {
            return PlasmaCommandKind.OpaqueControl;
        }

        if (payload.Length >= 4 && PlasmaIntegerCodec.ReadUInt32BigEndian(payload) == 0xffffffff)
        {
            return PlasmaCommandKind.SourceProbe;
        }

        if (enableNativeBinary && !LooksAscii(payload) && TryReadNativeMessageType(payload) is { } nativeType)
        {
            return nativeType switch
            {
                2 or 3 => PlasmaCommandKind.Roster,
                4 => PlasmaCommandKind.RosterAck,
                5 => PlasmaCommandKind.JoinAnnouncement,
                8 or 9 or 11 => PlasmaCommandKind.MeshUpdate,
                _ => PlasmaCommandKind.Unknown
            };
        }

        return LooksAscii(payload) ? PlasmaCommandKind.TextCommand : PlasmaCommandKind.Unknown;
    }

    private static int? TryReadNativeMessageType(ReadOnlySpan<byte> payload)
    {
        if (payload.IsEmpty)
        {
            return null;
        }

        var value = PlasmaIntegerCodec.ReadBiasedSByte(payload[0]);
        return value switch
        {
            2 when payload.Length is >= 3 and <= 64 => value,
            3 or 5 or 8 when payload.Length <= 64 => value,
            4 or 9 or 11 when payload.Length is >= 5 and <= 64 => value,
            _ => null
        };
    }

    private static string? FindMarker(string text)
    {
        foreach (var marker in KnownMarkers)
        {
            if (text.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return marker;
            }
        }

        return null;
    }

    private static int? FindAsciiMarkerOffset(ReadOnlySpan<byte> payload, string marker)
    {
        var markerBytes = Encoding.ASCII.GetBytes(marker);
        for (var i = 0; i <= payload.Length - markerBytes.Length; i++)
        {
            if (payload.Slice(i, markerBytes.Length).SequenceEqual(markerBytes))
            {
                return i;
            }
        }

        return null;
    }

    private static bool IsStructuredRosterMarker(ReadOnlySpan<byte> payload, int? markerOffset)
    {
        if (markerOffset is not { } offset)
        {
            return false;
        }

        if (offset is not (0 or 4 or 8))
        {
            return false;
        }

        var after = offset + 3;
        return payload.Length >= after + 4
            && (payload[after] is 0 or 1 or 0x80 or 0x81 or 0xed
                || payload[after + 1] is 0 or 1 or 0x80 or 0x81 or 0xed);
    }

    private static string Explain(
        PlasmaCommandKind kind,
        byte[] payload,
        string? marker,
        IReadOnlyDictionary<string, string> fields)
    {
        var bits = new List<string> { kind.ToString() };
        if (marker is not null)
        {
            bits.Add($"marker={marker}");
        }

        if (fields.TryGetValue("TID", out var tid))
        {
            bits.Add($"tid={tid}");
        }

        if (fields.TryGetValue("LID", out var lid))
        {
            bits.Add($"lid={lid}");
        }

        if (fields.TryGetValue("PID", out var pid))
        {
            bits.Add($"pid={pid}");
        }

        if (fields.TryGetValue("GID", out var gid))
        {
            bits.Add($"gid={gid}");
        }

        if (fields.TryGetValue("NativeType", out var nativeType))
        {
            bits.Add($"nativeType={nativeType}");
        }

        bits.Add($"len={payload.Length}");
        if (kind == PlasmaCommandKind.OpaqueControl)
        {
            bits.Add($"entropy={Entropy(payload):0.00}");
        }

        return string.Join(" ", bits);
    }

    private static double Entropy(ReadOnlySpan<byte> data)
    {
        Span<int> counts = stackalloc int[256];
        foreach (var b in data)
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

            var p = (double)count / data.Length;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }
}
