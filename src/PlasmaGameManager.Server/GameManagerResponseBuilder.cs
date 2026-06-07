using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.Server;

public sealed class GameManagerResponseBuilder
{
    private readonly GameManagerSession _game;
    private readonly PlayerSession _player;

    public GameManagerResponseBuilder(GameManagerSession game, PlayerSession player)
    {
        _game = game;
        _player = player;
    }

    public PlasmaResponse ServerHello(PlasmaPacket request)
    {
        var payload = new byte[20];
        var prefix = request.Payload.AsSpan(0, Math.Min(8, request.Payload.Length));
        prefix.CopyTo(payload);
        PlasmaIntegerCodec.WriteUInt32BigEndian(payload.AsSpan(8), (uint)_game.GameId);
        PlasmaIntegerCodec.WriteUInt32BigEndian(payload.AsSpan(12), (uint)_player.PlayerId);
        PlasmaIntegerCodec.WriteUInt32BigEndian(payload.AsSpan(16), 0x504c474d); // PLGM
        return new PlasmaResponse(PlasmaCommandKind.ServerHello, payload, "20-byte server hello/session seed");
    }

    public PlasmaResponse ReservationGranted(int tid)
    {
        return Text(
            PlasmaCommandKind.ReservationGranted,
            GameManagerMessageBuilder.Notify("EGRS", "0x40000000")
                .Field("LID", _game.LocalId)
                .Field("GID", _game.GameId)
                .Field("ALLOWED", 1)
                .Field("PID", _player.PlayerId)
                .Field("TID", tid),
            "reservation accepted");
    }

    public PlasmaResponse PlayerEntered(int tid)
    {
        return Text(
            PlasmaCommandKind.PlayerEntered,
            GameManagerMessageBuilder.Notify("PENT", "0x40000000")
                .Field("LID", _game.LocalId)
                .Field("GID", _game.GameId)
                .Field("PID", _player.PlayerId)
                .Field("TID", tid),
            "player entered roster");
    }

    public PlasmaResponse Roster(int tid)
    {
        return Text(
            PlasmaCommandKind.Roster,
            GameManagerMessageBuilder.Notify("COc")
                .Field("LID", _game.LocalId)
                .Field("GID", _game.GameId)
                .Field("PID", _player.PlayerId)
                .Field("NAME", _player.Name)
                .Field("STATE", 4)
                .Field("TID", tid),
            "single-player roster element");
    }

    public PlasmaResponse MeshUpdate(int tid, bool joined)
    {
        var join = joined ? 1 : 0;
        return Text(
            PlasmaCommandKind.MeshUpdate,
            GameManagerMessageBuilder.Notify("UBRA", "0x40000000")
                .Field("LID", _game.LocalId)
                .Field("GID", _game.GameId)
                .Field("JOIN", join)
                .Field("START", 0)
                .Field("TID", tid),
            "mesh membership update");
    }

    public PlasmaResponse JoinAnnouncement(int tid)
    {
        return Text(
            PlasmaCommandKind.JoinAnnouncement,
            GameManagerMessageBuilder.Request("UGAM", "0x40000000")
                .Field("LID", _game.LocalId)
                .Field("GID", _game.GameId)
                .Field("JOIN", 0)
                .Field("MAX-PLAYERS", _game.MaxPlayers)
                .Field("B-maxObservers", 0)
                .Field("B-numObservers", 0)
                .Field("TID", tid),
            "game join announcement");
    }

    public PlasmaResponse JoinComplete(int tid)
    {
        return Text(
            PlasmaCommandKind.JoinComplete,
            GameManagerMessageBuilder.Notify("UBRA", "0x40000000")
                .Field("LID", _game.LocalId)
                .Field("GID", _game.GameId)
                .Field("START", 1)
                .Field("TID", tid),
            "join complete/source handoff ready");
    }

    public PlasmaResponse Ack(PlasmaCommandKind kind, int tid, string name)
    {
        return Text(
            kind,
            GameManagerMessageBuilder.Notify(name)
                .Field("PID", _player.PlayerId)
                .Field("TID", tid),
            $"{name} ack");
    }

    public PlasmaResponse NativeRosterHeader(short elementCount)
    {
        return new PlasmaResponse(
            PlasmaCommandKind.Roster,
            NativeGameManagerMessage.RosterHeader(elementCount),
            "native roster header type 2");
    }

    public PlasmaResponse NativeRosterElement()
    {
        return new PlasmaResponse(
            PlasmaCommandKind.Roster,
            NativeGameManagerMessage.RosterElement(),
            "native roster element type 3");
    }

    public PlasmaResponse NativeRosterAckToHost(int hostPlayerId)
    {
        return new PlasmaResponse(
            PlasmaCommandKind.RosterAck,
            NativeGameManagerMessage.RosterAckToHost(hostPlayerId),
            "native roster ack to host type 4");
    }

    public PlasmaResponse NativeJoinAnnouncement()
    {
        return new PlasmaResponse(
            PlasmaCommandKind.JoinAnnouncement,
            NativeGameManagerMessage.JoinAnnouncement(),
            "native join announcement type 5");
    }

    public PlasmaResponse NativeJoinMeshAnnouncement()
    {
        return new PlasmaResponse(
            PlasmaCommandKind.MeshUpdate,
            NativeGameManagerMessage.JoinMeshAnnouncement(),
            "native join mesh announcement type 8");
    }

    public PlasmaResponse NativeAddressedJoinDetails(int targetPlayerId)
    {
        return new PlasmaResponse(
            PlasmaCommandKind.MeshUpdate,
            NativeGameManagerMessage.AddressedJoinDetails(targetPlayerId),
            "native addressed join details type 9");
    }

    public PlasmaResponse NativePeerMeshToHost(int hostPlayerId)
    {
        return new PlasmaResponse(
            PlasmaCommandKind.MeshUpdate,
            NativeGameManagerMessage.PeerMeshToHost(hostPlayerId),
            "native peer mesh to host type 11");
    }

    private static PlasmaResponse Text(PlasmaCommandKind kind, GameManagerMessageBuilder builder, string explanation)
    {
        return new PlasmaResponse(kind, builder.BuildBytes(), explanation);
    }
}
