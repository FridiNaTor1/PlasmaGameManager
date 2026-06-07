namespace PlasmaGameManager.Protocol;

public enum PlasmaCommandKind
{
    Unknown,
    Empty,
    TextCommand,
    ClientHello,
    ServerHello,
    ReservationRequest,
    ReservationGranted,
    PlayerEntered,
    Roster,
    RosterAck,
    JoinAnnouncement,
    MeshUpdate,
    MeshAck,
    JoinComplete,
    HostHello,
    SourceProbe,
    OpaqueControl
}
