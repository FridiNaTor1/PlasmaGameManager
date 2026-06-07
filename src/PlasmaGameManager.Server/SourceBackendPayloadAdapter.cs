namespace PlasmaGameManager.Server;

public static class SourceBackendPayloadAdapter
{
    public static SourceBackendPayloadDecision PrepareClientToBackend(
        SourceBackendProtocol protocol,
        ReadOnlyMemory<byte> payload)
    {
        return protocol switch
        {
            SourceBackendProtocol.Ps3NativePassthrough => SourceBackendPayloadDecision.Forward(payload, "PS3-native Source/gameplay payload passed through unchanged."),
            SourceBackendProtocol.PcSourceConnectionlessOnly when IsClassicSourceConnectionless(payload.Span) =>
                SourceBackendPayloadDecision.Forward(payload, "Classic connectionless Source packet forwarded to PC Source backend."),
            SourceBackendProtocol.PcSourceConnectionlessOnly =>
                SourceBackendPayloadDecision.Drop("PS3 Source/gameplay transport packet is not a classic PC Source connectionless packet; translation is required before forwarding to a PC Source backend."),
            _ => SourceBackendPayloadDecision.Drop($"Unsupported Source backend protocol: {protocol}")
        };
    }

    public static bool IsClassicSourceConnectionless(ReadOnlySpan<byte> payload)
    {
        return payload.Length >= 4
            && payload[0] == 0xff
            && payload[1] == 0xff
            && payload[2] == 0xff
            && payload[3] == 0xff;
    }
}

public sealed record SourceBackendPayloadDecision(
    bool ShouldForward,
    ReadOnlyMemory<byte> Payload,
    string Explanation)
{
    public static SourceBackendPayloadDecision Forward(ReadOnlyMemory<byte> payload, string explanation)
    {
        return new SourceBackendPayloadDecision(true, payload, explanation);
    }

    public static SourceBackendPayloadDecision Drop(string explanation)
    {
        return new SourceBackendPayloadDecision(false, ReadOnlyMemory<byte>.Empty, explanation);
    }
}

public sealed record SourceBackendForwardResult(
    bool Forwarded,
    bool Dropped,
    string Explanation)
{
    public static SourceBackendForwardResult Disabled { get; } = new(false, false, "Source backend proxy is disabled.");
}
