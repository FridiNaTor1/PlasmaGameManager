namespace PlasmaGameManager.Protocol;

public enum NativeGameManagerMessageType : byte
{
    RosterHeader = 2,
    RosterElement = 3,
    RosterAckToHost = 4,
    JoinAnnouncement = 5,
    JoinMeshAnnouncement = 8,
    AddressedJoinDetails = 9,
    PeerMeshToHost = 11
}

public static class NativeGameManagerMessage
{
    public static byte EncodedType(NativeGameManagerMessageType type)
    {
        return PlasmaIntegerCodec.WriteBiasedSByte((sbyte)type);
    }

    public static byte[] RosterHeader(short elementCount)
    {
        return GameManagerBinaryMessageBuilder
            .Message((byte)NativeGameManagerMessageType.RosterHeader)
            .WriteBiasedInt16(elementCount)
            .Build();
    }

    public static byte[] RosterElement()
    {
        return TypeOnly(NativeGameManagerMessageType.RosterElement);
    }

    public static byte[] RosterAckToHost(int hostPlayerId)
    {
        return Addressed(NativeGameManagerMessageType.RosterAckToHost, hostPlayerId);
    }

    public static byte[] JoinAnnouncement()
    {
        return TypeOnly(NativeGameManagerMessageType.JoinAnnouncement);
    }

    public static byte[] JoinMeshAnnouncement()
    {
        return TypeOnly(NativeGameManagerMessageType.JoinMeshAnnouncement);
    }

    public static byte[] AddressedJoinDetails(int targetPlayerId)
    {
        return Addressed(NativeGameManagerMessageType.AddressedJoinDetails, targetPlayerId);
    }

    public static byte[] PeerMeshToHost(int hostPlayerId)
    {
        return Addressed(NativeGameManagerMessageType.PeerMeshToHost, hostPlayerId);
    }

    private static byte[] TypeOnly(NativeGameManagerMessageType type)
    {
        return GameManagerBinaryMessageBuilder.Message((byte)type).Build();
    }

    private static byte[] Addressed(NativeGameManagerMessageType type, int playerId)
    {
        return GameManagerBinaryMessageBuilder.Addressed((byte)type, playerId).Build();
    }
}
