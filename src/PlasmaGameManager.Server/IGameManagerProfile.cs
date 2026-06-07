using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.Server;

public interface IGameManagerProfile
{
    string Name { get; }

    IReadOnlyList<PlasmaResponse> Handle(GameManagerSession game, PlayerSession player, PlasmaPacket packet);
}
