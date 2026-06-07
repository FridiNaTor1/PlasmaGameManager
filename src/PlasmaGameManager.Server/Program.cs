using System.Net;
using PlasmaGameManager.Server;

var bind = IPAddress.Any;
var port = 27015;
var ports = ParsePorts(Environment.GetEnvironmentVariable("PLASMA_PORTS"));
var profileName = "tf2-ps3";
string? evidenceLog = null;
var sourceHost = Environment.GetEnvironmentVariable("PLASMA_SOURCE_HOST") ?? "127.0.0.1";
var sourcePort = int.TryParse(Environment.GetEnvironmentVariable("PLASMA_SOURCE_PORT"), out var parsedSourcePort)
    ? parsedSourcePort
    : 0;
var sourceTimeoutMs = int.TryParse(Environment.GetEnvironmentVariable("PLASMA_SOURCE_TIMEOUT_MS"), out var parsedSourceTimeout)
    ? parsedSourceTimeout
    : 250;
var sourceProtocol = ParseSourceProtocol(Environment.GetEnvironmentVariable("PLASMA_SOURCE_PROTOCOL"));
var sourceProxyEnabled = sourcePort > 0
    || string.Equals(Environment.GetEnvironmentVariable("PLASMA_SOURCE_PROXY"), "1", StringComparison.OrdinalIgnoreCase)
    || string.Equals(Environment.GetEnvironmentVariable("PLASMA_SOURCE_PROXY"), "true", StringComparison.OrdinalIgnoreCase);

for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--bind" when i + 1 < args.Length:
            bind = IPAddress.Parse(args[++i]);
            break;
        case "--port" when i + 1 < args.Length:
            port = int.Parse(args[++i]);
            ports = Array.Empty<int>();
            break;
        case "--ports" when i + 1 < args.Length:
            ports = ParsePorts(args[++i]);
            break;
        case "--profile" when i + 1 < args.Length:
            profileName = args[++i];
            break;
        case "--evidence-log" when i + 1 < args.Length:
            evidenceLog = args[++i];
            break;
        case "--source-host" when i + 1 < args.Length:
            sourceHost = args[++i];
            break;
        case "--source-port" when i + 1 < args.Length:
            sourcePort = int.Parse(args[++i]);
            sourceProxyEnabled = true;
            break;
        case "--source-timeout-ms" when i + 1 < args.Length:
            sourceTimeoutMs = int.Parse(args[++i]);
            break;
        case "--source-protocol" when i + 1 < args.Length:
            sourceProtocol = ParseSourceProtocol(args[++i]);
            break;
        case "--help":
            Console.WriteLine("Usage: PlasmaGameManager.Server --bind 0.0.0.0 --port 27015 --profile tf2-ps3 [--ports 27015,27016] [--evidence-log logs/gamemanager-events.jsonl] [--source-host 127.0.0.1 --source-port 27016] [--source-protocol ps3-native-passthrough|pc-source-connectionless-only]");
            return;
    }
}

var listenPorts = ports.Length > 0 ? ports : new[] { port };

var profile = GameManagerProfileFactory.Create(profileName);
IGameManagerEventSink? eventSink = null;
if (evidenceLog is not null)
{
    Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(evidenceLog)) ?? ".");
    eventSink = new JsonLineGameManagerEventSink(File.AppendText(evidenceLog));
    Console.WriteLine($"writing GameManager evidence events to {evidenceLog}");
}

using (eventSink)
{
    var sourceBackend = new SourceBackendOptions(sourceHost, sourcePort, sourceProxyEnabled, sourceTimeoutMs, sourceProtocol);
    if (sourceBackend.IsEnabled)
    {
        Console.WriteLine($"proxying post-handoff Source UDP to {sourceBackend.Host}:{sourceBackend.Port} protocol={sourceBackend.ProtocolName} timeout={sourceBackend.TimeoutMilliseconds}ms");
    }

    var server = new UdpGameManagerServer(profile, eventSink, sourceBackend);
    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        cts.Cancel();
    };

    await server.RunAsync(bind, listenPorts, cts.Token);
}

static int[] ParsePorts(string? value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return Array.Empty<int>();
    }

    return value
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(int.Parse)
        .Distinct()
        .OrderBy(static parsed => parsed)
        .ToArray();
}

static SourceBackendProtocol ParseSourceProtocol(string? value)
{
    return value?.Trim().ToLowerInvariant() switch
    {
        null or "" or "ps3-native" or "ps3-native-passthrough" or "passthrough" =>
            SourceBackendProtocol.Ps3NativePassthrough,
        "pc-source" or "pc-source-connectionless-only" or "connectionless-only" =>
            SourceBackendProtocol.PcSourceConnectionlessOnly,
        _ => throw new ArgumentException($"Unsupported Source backend protocol '{value}'. Use ps3-native-passthrough or pc-source-connectionless-only.")
    };
}
