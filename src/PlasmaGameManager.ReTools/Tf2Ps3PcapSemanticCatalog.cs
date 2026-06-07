using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class Tf2Ps3PcapSemanticCatalog
{
    private readonly Dictionary<int, string[]> _nativeTypeRoles;

    private Tf2Ps3PcapSemanticCatalog(Dictionary<int, string[]> nativeTypeRoles)
    {
        _nativeTypeRoles = nativeTypeRoles;
    }

    public static Tf2Ps3PcapSemanticCatalog LoadOrDefault(string? dispatcherMapPath)
    {
        if (dispatcherMapPath is null || !File.Exists(dispatcherMapPath))
        {
            return new Tf2Ps3PcapSemanticCatalog(DefaultNativeTypeRoles());
        }

        using var doc = JsonDocument.Parse(File.ReadAllBytes(dispatcherMapPath));
        var roles = new Dictionary<int, HashSet<string>>();
        foreach (var row in doc.RootElement.GetProperty("dispatcherRows").EnumerateArray())
        {
            var role = row.GetProperty("Role").GetString() ?? "";
            if (role.Length == 0)
            {
                continue;
            }

            foreach (var packet in row.GetProperty("PacketTypes").EnumerateArray())
            {
                var type = packet.GetProperty("Type").GetInt32();
                if (!roles.TryGetValue(type, out var packetRoles))
                {
                    packetRoles = new HashSet<string>(StringComparer.Ordinal);
                    roles.Add(type, packetRoles);
                }

                packetRoles.Add(role);
            }
        }

        var merged = DefaultNativeTypeRoles();
        foreach (var (type, packetRoles) in roles)
        {
            merged[type] = packetRoles.Order(StringComparer.Ordinal).ToArray();
        }

        return new Tf2Ps3PcapSemanticCatalog(merged);
    }

    public PcapSemanticExplanation Explain(GameManagerCommand command, string? marker, string confidence, bool hasTransportFrame)
    {
        var nativeType = TryNativeType(command);
        var roles = nativeType is null ? Array.Empty<string>() : _nativeTypeRoles.GetValueOrDefault(nativeType.Value, Array.Empty<string>());
        return new PcapSemanticExplanation(
            SemanticRole(command, marker, nativeType),
            PlainText(command, marker, nativeType, roles),
            nativeType,
            roles,
            nativeType is not null,
            hasTransportFrame,
            confidence);
    }

    private static string SemanticRole(GameManagerCommand command, string? marker, int? nativeType)
    {
        if (nativeType is not null)
        {
            return nativeType.Value switch
            {
                2 => "native-roster-header",
                3 => "native-roster-element",
                4 => "native-roster-ack-to-host",
                5 => "native-join-announcement",
                8 => "native-join-mesh-announcement",
                9 => "native-addressed-join-details",
                11 => "native-peer-mesh-to-host",
                _ => "native-unknown"
            };
        }

        return command.Kind switch
        {
            PlasmaCommandKind.ClientHello => "client-hello",
            PlasmaCommandKind.ServerHello => "server-hello",
            PlasmaCommandKind.ReservationRequest => "reservation-request",
            PlasmaCommandKind.ReservationGranted => "reservation-granted",
            PlasmaCommandKind.PlayerEntered => "player-entered",
            PlasmaCommandKind.Roster when marker is not null => $"text-roster-{marker}",
            PlasmaCommandKind.Roster => "roster",
            PlasmaCommandKind.RosterAck => "roster-ack",
            PlasmaCommandKind.JoinAnnouncement => "join-announcement",
            PlasmaCommandKind.MeshUpdate => "mesh-update",
            PlasmaCommandKind.SourceProbe => "source-probe",
            PlasmaCommandKind.OpaqueControl => "opaque-session-control",
            PlasmaCommandKind.TextCommand => "text-control",
            _ => "unknown"
        };
    }

    private static string PlainText(GameManagerCommand command, string? marker, int? nativeType, string[] roles)
    {
        if (nativeType is not null)
        {
            var roleText = roles.Length == 0 ? "no dispatcher role mapped yet" : string.Join(", ", roles);
            return $"Native TF2 GameManager type {nativeType}: {SemanticRole(command, marker, nativeType)} ({roleText}).";
        }

        var idBits = new[]
        {
            command.LocalId is null ? "" : $"LID={command.LocalId}",
            command.GameId is null ? "" : $"GID={command.GameId}",
            command.PlayerId is null ? "" : $"PID={command.PlayerId}",
            command.TransactionId is null ? "" : $"TID={command.TransactionId}"
        }.Where(static bit => bit.Length > 0);
        var suffix = string.Join(", ", idBits);
        if (suffix.Length > 0)
        {
            suffix = $" ({suffix})";
        }

        return command.Kind switch
        {
            PlasmaCommandKind.ClientHello => "Client opens the GameManager session with the 24-byte binary hello.",
            PlasmaCommandKind.ServerHello => "Server returns the 20-byte GameManager hello/session seed.",
            PlasmaCommandKind.ReservationRequest => $"Client asks to reserve/join an advertised game{suffix}.",
            PlasmaCommandKind.ReservationGranted => $"Server approves the theater reservation{suffix}.",
            PlasmaCommandKind.PlayerEntered => $"Server announces that the player entered the GameManager session{suffix}.",
            PlasmaCommandKind.Roster => $"Roster/session metadata record {marker ?? command.Name}{suffix}.",
            PlasmaCommandKind.RosterAck => $"Roster acknowledgement/control update{suffix}.",
            PlasmaCommandKind.JoinAnnouncement => $"Game join announcement/update{suffix}.",
            PlasmaCommandKind.MeshUpdate => $"Mesh membership or association update{suffix}.",
            PlasmaCommandKind.SourceProbe => "Source-engine query/probe traffic after or alongside GameManager.",
            PlasmaCommandKind.OpaqueControl => "High-entropy session control payload; currently treated as semantic GameManager control, not PC srcds bytes.",
            PlasmaCommandKind.TextCommand => $"Text control message {marker ?? command.Name}{suffix}.",
            _ => "Unclassified payload."
        };
    }

    private static int? TryNativeType(GameManagerCommand command)
    {
        return command.Fields.TryGetValue("NativeType", out var value) && int.TryParse(value, out var parsed) ? parsed : null;
    }

    private static Dictionary<int, string[]> DefaultNativeTypeRoles()
    {
        return new Dictionary<int, string[]>
        {
            [2] = ["send-roster"],
            [3] = ["send-roster"],
            [4] = ["receive-roster-element", "process-roster-notice-and-send-host-ack"],
            [5] = ["receive-roster-ack"],
            [8] = ["send-join-mesh-announcement"],
            [9] = ["receive-roster-ack", "send-join-mesh-announcement"],
            [11] = ["send-peer-mesh-to-host"]
        };
    }
}

public sealed record PcapSemanticExplanation(
    string Role,
    string PlainText,
    int? NativeType,
    string[] CandidateDispatcherRoles,
    bool IsNativeGameManager,
    bool IsTransportWrapped,
    string Confidence);
