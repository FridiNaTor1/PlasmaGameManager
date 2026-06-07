namespace PlasmaGameManager.Server;

public sealed record SourceBackendOptions(
    string Host,
    int Port,
    bool EnableProxy,
    int TimeoutMilliseconds,
    SourceBackendProtocol Protocol = SourceBackendProtocol.Ps3NativePassthrough)
{
    public static SourceBackendOptions Disabled { get; } = new("127.0.0.1", 0, false, 250);

    public bool IsEnabled => EnableProxy && Port > 0;

    public string Endpoint => $"{Host}:{Port}";

    public string ProtocolName => Protocol switch
    {
        SourceBackendProtocol.Ps3NativePassthrough => "ps3-native-passthrough",
        SourceBackendProtocol.PcSourceConnectionlessOnly => "pc-source-connectionless-only",
        _ => Protocol.ToString()
    };
}

public enum SourceBackendProtocol
{
    Ps3NativePassthrough,
    PcSourceConnectionlessOnly
}
