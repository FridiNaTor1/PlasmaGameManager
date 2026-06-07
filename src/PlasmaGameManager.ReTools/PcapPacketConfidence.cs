using System.Text;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public static class PcapPacketConfidence
{
    public static string Classify(
        ReadOnlySpan<byte> payload,
        PlasmaPacket packet,
        bool hasTransportFrame,
        int? markerOffset)
    {
        if (packet.Kind == PlasmaCommandKind.Unknown)
        {
            return "none";
        }

        if (hasTransportFrame)
        {
            return "high";
        }

        if (packet.Kind is PlasmaCommandKind.ClientHello or PlasmaCommandKind.ServerHello or PlasmaCommandKind.SourceProbe)
        {
            return "high";
        }

        if (PlasmaPacketClassifier.LooksAscii(payload)
            && (packet.Fields.Count > 0 || packet.Marker is not null))
        {
            return "high";
        }

        if (packet.Marker is "COc" or "PNG" or "DSC")
        {
            return IsStructuredRosterMarker(payload, markerOffset) ? "medium" : "low";
        }

        if (packet.Kind == PlasmaCommandKind.OpaqueControl)
        {
            return "medium";
        }

        return packet.Fields.Count > 0 ? "medium" : "low";
    }

    public static int? FindMarkerOffset(ReadOnlySpan<byte> payload, string? marker)
    {
        if (marker is null)
        {
            return null;
        }

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
}
