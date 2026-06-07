using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.Server;

public class Bfbc2R34Profile : IGameManagerProfile
{
    public virtual string Name => "bfbc2-r34";

    public virtual IReadOnlyList<PlasmaResponse> Handle(GameManagerSession game, PlayerSession player, PlasmaPacket packet)
    {
        return NativeFlow(game, player, packet, sourceHandoff: false);
    }

    protected static IReadOnlyList<PlasmaResponse> NativeFlow(
        GameManagerSession game,
        PlayerSession player,
        PlasmaPacket packet,
        bool sourceHandoff)
    {
        player.LastSeen = DateTimeOffset.UtcNow;
        player.LastTransactionId = ReadTransactionId(packet, player.LastTransactionId + 1);
        var tid = player.LastTransactionId;
        var responses = new List<PlasmaResponse>();
        var builder = new GameManagerResponseBuilder(game, player);

        switch (packet.Kind)
        {
            case PlasmaCommandKind.ClientHello:
                player.State = PlayerJoinState.Connected;
                responses.Add(builder.ServerHello(packet));
                break;
            case PlasmaCommandKind.ReservationRequest:
                player.State = PlayerJoinState.Reserved;
                responses.Add(builder.ReservationGranted(tid));
                responses.Add(builder.PlayerEntered(tid));
                break;
            case PlasmaCommandKind.PlayerEntered:
            case PlasmaCommandKind.RosterAck:
                player.State = PlayerJoinState.RosterSent;
                responses.Add(builder.Roster(tid));
                break;
            case PlasmaCommandKind.MeshUpdate:
            case PlasmaCommandKind.JoinAnnouncement:
                player.State = PlayerJoinState.MeshJoined;
                responses.Add(builder.MeshUpdate(tid, joined: true));
                responses.Add(builder.JoinAnnouncement(tid));
                break;
            case PlasmaCommandKind.MeshAck:
            case PlasmaCommandKind.OpaqueControl:
                player.State = sourceHandoff ? PlayerJoinState.SourceHandoff : PlayerJoinState.JoinComplete;
                responses.Add(builder.JoinComplete(tid));
                break;
            case PlasmaCommandKind.SourceProbe:
                player.State = PlayerJoinState.SourceHandoff;
                break;
            case PlasmaCommandKind.TextCommand:
            case PlasmaCommandKind.Unknown:
                if (player.State is PlayerJoinState.RosterSent
                    or PlayerJoinState.RosterNoticeProcessing
                    or PlayerJoinState.RosterNoticeComplete
                    or PlayerJoinState.MeshJoined
                    or PlayerJoinState.FullMeshReceived)
                {
                    player.State = PlayerJoinState.SourceHandoff;
                    break;
                }

                responses.Add(builder.Ack(PlasmaCommandKind.TextCommand, tid, "ACK"));
                break;
        }

        return responses;
    }

    private static int ReadTransactionId(PlasmaPacket packet, int fallback)
    {
        if (packet.Fields.TryGetValue("TID", out var tid) && int.TryParse(tid, out var parsed))
        {
            return parsed;
        }

        return fallback;
    }
}

public sealed class Tf2Ps3Profile : Bfbc2R34Profile
{
    public override string Name => "tf2-ps3";

    public override IReadOnlyList<PlasmaResponse> Handle(GameManagerSession game, PlayerSession player, PlasmaPacket packet)
    {
        if (player.Name.StartsWith("player", StringComparison.Ordinal))
        {
            player.Name = "The_FridiNaTor";
        }

        game.MaxPlayers = 24;
        player.LastSeen = DateTimeOffset.UtcNow;
        player.LastTransactionId = ReadTransactionId(packet, player.LastTransactionId + 1);
        var tid = player.LastTransactionId;
        var responses = new List<PlasmaResponse>();
        var builder = new GameManagerResponseBuilder(game, player);

        switch (packet.Kind)
        {
            case PlasmaCommandKind.ClientHello:
                player.State = PlayerJoinState.RosterSent;
                responses.Add(builder.ServerHello(packet));
                AddNativeRoster(game, player, responses, builder);
                break;
            case PlasmaCommandKind.ReservationRequest:
                player.State = PlayerJoinState.RosterSent;
                responses.Add(builder.ReservationGranted(tid));
                responses.Add(builder.PlayerEntered(tid));
                AddNativeRoster(game, player, responses, builder);
                break;
            case PlasmaCommandKind.RosterAck:
                player.State = PlayerJoinState.MeshJoined;
                responses.Add(builder.NativeJoinAnnouncement());
                responses.Add(builder.NativeAddressedJoinDetails(player.PlayerId));
                responses.Add(builder.NativeJoinMeshAnnouncement());
                responses.Add(builder.NativeAddressedJoinDetails(player.PlayerId));
                responses.Add(builder.NativePeerMeshToHost(player.PlayerId));
                break;
            case PlasmaCommandKind.Roster:
                ProcessRosterNotice(player, responses, builder);
                break;
            case PlasmaCommandKind.MeshUpdate:
            case PlasmaCommandKind.JoinAnnouncement:
                player.State = player.State is PlayerJoinState.RosterNoticeComplete or PlayerJoinState.MeshJoined
                    ? PlayerJoinState.FullMeshReceived
                    : PlayerJoinState.MeshJoined;
                responses.Add(builder.NativePeerMeshToHost(player.PlayerId));
                break;
            case PlasmaCommandKind.MeshAck:
            case PlasmaCommandKind.OpaqueControl:
                player.State = PlayerJoinState.SourceHandoff;
                responses.Add(builder.JoinComplete(tid));
                break;
            case PlasmaCommandKind.SourceProbe:
                player.State = PlayerJoinState.SourceHandoff;
                break;
            case PlasmaCommandKind.TextCommand:
            case PlasmaCommandKind.Unknown:
                if (player.State is PlayerJoinState.RosterSent
                    or PlayerJoinState.RosterNoticeProcessing
                    or PlayerJoinState.RosterNoticeComplete
                    or PlayerJoinState.MeshJoined
                    or PlayerJoinState.FullMeshReceived)
                {
                    player.State = PlayerJoinState.SourceHandoff;
                    break;
                }

                responses.Add(builder.Ack(PlasmaCommandKind.TextCommand, tid, "ACK"));
                break;
        }

        return responses;
    }

    private static void AddNativeRoster(GameManagerSession game, PlayerSession player, List<PlasmaResponse> responses, GameManagerResponseBuilder builder)
    {
        player.ExpectedRosterNoticeCount = Math.Max(1, game.Players.Count);
        player.ProcessedRosterNoticeCount = 0;
        player.HostRosterAckSent = false;
        responses.Add(builder.NativeRosterHeader((short)player.ExpectedRosterNoticeCount));
        responses.Add(builder.NativeRosterElement());
    }

    private static void ProcessRosterNotice(PlayerSession player, List<PlasmaResponse> responses, GameManagerResponseBuilder builder)
    {
        if (player.HostRosterAckSent)
        {
            player.State = PlayerJoinState.RosterNoticeComplete;
            return;
        }

        player.ProcessedRosterNoticeCount++;
        player.State = PlayerJoinState.RosterNoticeProcessing;
        if (player.ProcessedRosterNoticeCount < Math.Max(1, player.ExpectedRosterNoticeCount))
        {
            return;
        }

        player.State = PlayerJoinState.RosterNoticeComplete;
        player.HostRosterAckSent = true;
        responses.Add(builder.NativeRosterAckToHost(player.PlayerId));
    }

    private static int ReadTransactionId(PlasmaPacket packet, int fallback)
    {
        if (packet.Fields.TryGetValue("TID", out var tid) && int.TryParse(tid, out var parsed))
        {
            return parsed;
        }

        return fallback;
    }
}

public static class GameManagerProfileFactory
{
    public static IGameManagerProfile Create(string profile)
    {
        return profile.ToLowerInvariant() switch
        {
            "bfbc2-r34" or "bfbc2" => new Bfbc2R34Profile(),
            "tf2-ps3" or "tf2" => new Tf2Ps3Profile(),
            _ => throw new ArgumentException($"Unknown profile '{profile}'. Use bfbc2-r34 or tf2-ps3.", nameof(profile))
        };
    }
}
