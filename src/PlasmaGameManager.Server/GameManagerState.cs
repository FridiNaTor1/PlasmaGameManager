using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.Server;

public enum PlayerJoinState
{
    Unknown,
    Connected,
    Reserved,
    Entered,
    RosterSent,
    RosterNoticeProcessing,
    RosterNoticeComplete,
    MeshJoined,
    FullMeshReceived,
    JoinComplete,
    SourceHandoff,
    Left
}

public sealed class GameManagerSession
{
    public long LocalId { get; init; } = 257;

    public long GameId { get; init; } = 800001;

    public int MaxPlayers { get; set; } = 24;

    public string MapName { get; set; } = "ctf_2fort";

    public string Name { get; set; } = "TF2 PS3 Native GM";

    public Dictionary<string, PlayerSession> Players { get; } = new(StringComparer.Ordinal);

    public PlayerSession GetOrAddPlayer(string endpoint)
    {
        if (Players.TryGetValue(endpoint, out var player))
        {
            return player;
        }

        player = new PlayerSession
        {
            Endpoint = endpoint,
            PlayerId = Players.Count + 1,
            Name = $"player{Players.Count + 1}"
        };
        Players.Add(endpoint, player);
        return player;
    }
}

public sealed class PlayerSession
{
    public required string Endpoint { get; init; }

    public int PlayerId { get; init; }

    public string Name { get; set; } = "player";

    public int LastTransactionId { get; set; }

    public PlayerJoinState State { get; set; }

    public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.UtcNow;

    public int ExpectedRosterNoticeCount { get; set; } = 1;

    public int ProcessedRosterNoticeCount { get; set; }

    public bool HostRosterAckSent { get; set; }

    public Ps3SourceGameplaySession SourceGameplay { get; } = new();
}
