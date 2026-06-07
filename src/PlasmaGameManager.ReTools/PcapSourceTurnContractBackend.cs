using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class PcapSourceTurnContractBackend
{
    private readonly PcapActiveFlowReplayExtractor _extractor = new();

    public async Task RunAsync(
        string pcapPath,
        IPAddress bindAddress,
        int port,
        CancellationToken ct,
        TextWriter? evidenceWriter = null)
    {
        var turns = LoadTurns(pcapPath);
        await RunAsync(turns, bindAddress, port, ct, evidenceWriter);
    }

    public async Task RunAsync(
        IReadOnlyList<PcapSourceTurnContractBackendTurn> turns,
        IPAddress bindAddress,
        int port,
        CancellationToken ct,
        TextWriter? evidenceWriter = null)
    {
        var catalog = PcapSourceTurnContractBackendCatalog.Build(turns);
        using var socket = new UdpClient(new IPEndPoint(bindAddress, port));
        var sessions = new Dictionary<string, PcapSourceTurnContractBackendSession>(StringComparer.Ordinal);

        Console.WriteLine($"PCAP Source turn-contract backend listening on {bindAddress}:{port} turns={turns.Count} exactKeys={catalog.ExactKeyCount} prefixKeys={catalog.PrefixKeyCount}");
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult received;
            try
            {
                received = await socket.ReceiveAsync(ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            var endpoint = received.RemoteEndPoint.ToString();
            if (!sessions.TryGetValue(endpoint, out var session))
            {
                session = new PcapSourceTurnContractBackendSession();
                sessions.Add(endpoint, session);
            }

            var packetSignature = Ps3SourceGameplaySignatures.BodyRunSignature([received.Buffer]);
            var result = session.ObserveClientPacket(packetSignature, catalog);
            var observation = session.SourceGameplay.Observe(Ps3SourceGameplayDirection.ClientToServer, received.Buffer);
            WriteEvidence(
                evidenceWriter,
                new PcapSourceTurnContractBackendEvent(
                    DateTimeOffset.UtcNow,
                    "source-contract-receive",
                    endpoint,
                    received.Buffer.Length,
                    result.Matched,
                    result.WaitingForMorePackets,
                    result.ClientPacketCount,
                    result.PrefixCandidateCount,
                    result.CompleteCandidateCount,
                    result.Explanation,
                    result.Match?.ScriptName ?? "",
                    result.Match?.TurnIndex,
                    result.Match?.ClientBodySignature,
                    result.Match?.ServerBodySignature,
                    result.Match?.TurnBodySignature,
                    Convert.ToHexString(received.Buffer.AsSpan(0, Math.Min(8, received.Buffer.Length))).ToLowerInvariant(),
                    observation.Sequence,
                    observation.BodyLength == 0 ? null : observation.BodyLength,
                    observation.SequenceDeltaFromPreviousSameDirection,
                    observation.Shape.ToString(),
                    observation.DirectionPacketCount,
                    observation.SequenceDecrease,
                    null));
            Console.WriteLine($"{DateTimeOffset.Now:HH:mm:ss.fff} <= {endpoint} contract matched={result.Matched} waiting={result.WaitingForMorePackets} clientPackets={result.ClientPacketCount} candidates={result.PrefixCandidateCount}/{result.CompleteCandidateCount} {result.Explanation}");

            if (!result.Matched || result.Match is null)
            {
                continue;
            }

            foreach (var response in result.Match.ServerResponses)
            {
                await socket.SendAsync(response.Payload, response.Payload.Length, received.RemoteEndPoint);
                var serverObservation = session.SourceGameplay.Observe(Ps3SourceGameplayDirection.ServerToClient, response.Payload);
                WriteEvidence(
                    evidenceWriter,
                    new PcapSourceTurnContractBackendEvent(
                        DateTimeOffset.UtcNow,
                        "source-contract-send",
                        endpoint,
                        response.Payload.Length,
                        true,
                        false,
                        result.ClientPacketCount,
                        result.PrefixCandidateCount,
                        result.CompleteCandidateCount,
                        "Emitted captured server response packet for matched sequence-insensitive client turn contract.",
                        result.Match.ScriptName,
                        result.Match.TurnIndex,
                        result.Match.ClientBodySignature,
                        result.Match.ServerBodySignature,
                        result.Match.TurnBodySignature,
                        Convert.ToHexString(response.Payload.AsSpan(0, Math.Min(8, response.Payload.Length))).ToLowerInvariant(),
                        serverObservation.Sequence,
                        serverObservation.BodyLength == 0 ? null : serverObservation.BodyLength,
                        serverObservation.SequenceDeltaFromPreviousSameDirection,
                        serverObservation.Shape.ToString(),
                        serverObservation.DirectionPacketCount,
                        serverObservation.SequenceDecrease,
                        response.PacketIndex));
                Console.WriteLine($"{DateTimeOffset.Now:HH:mm:ss.fff} => {endpoint} contract script={result.Match.ScriptName} turn={result.Match.TurnIndex} packetIndex={response.PacketIndex} len={response.Payload.Length}");
            }
        }
    }

    private PcapSourceTurnContractBackendTurn[] LoadTurns(string path)
    {
        if (File.Exists(path))
        {
            return LoadTurnsFromFile(path, Path.GetFileName(path));
        }

        if (!Directory.Exists(path))
        {
            throw new FileNotFoundException($"PCAP turn-contract input path does not exist: {path}", path);
        }

        var turns = Directory.EnumerateFiles(path, "*.*", SearchOption.AllDirectories)
            .Where(static file => file.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase)
                || file.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            .OrderBy(static file => file, StringComparer.Ordinal)
            .SelectMany(file => LoadTurnsFromFile(file, Path.GetRelativePath(path, file)))
            .ToArray();

        if (turns.Length == 0)
        {
            throw new InvalidOperationException($"No active Source/gameplay turns were found under {path}.");
        }

        return turns;
    }

    private PcapSourceTurnContractBackendTurn[] LoadTurnsFromFile(string file, string scriptName)
    {
        var replay = _extractor.Extract(file);
        if (replay is null)
        {
            return [];
        }

        var steps = replay.SourcePackets.Select(static packet => new Ps3SourceGameplayReplayStep(
            packet.Direction == PcapActiveFlowDirection.ClientToServer
                ? Ps3SourceGameplayDirection.ClientToServer
                : Ps3SourceGameplayDirection.ServerToClient,
            packet.Payload,
            packet.PacketIndex,
            packet.TimestampMicroseconds))
            .ToArray();

        return Ps3SourceGameplayTurnReplayDriver.BuildTurns(steps)
            .Where(static turn => turn.ClientPackets.Length > 0)
            .Select(turn => BuildTurn(scriptName, turn))
            .ToArray();
    }

    private static PcapSourceTurnContractBackendTurn BuildTurn(string scriptName, Ps3SourceGameplayReplayTurn turn)
    {
        var clientPayloads = turn.ClientPackets.Select(static packet => packet.Payload).ToArray();
        var serverPayloads = turn.ServerResponses.Select(static packet => packet.Payload).ToArray();
        return new PcapSourceTurnContractBackendTurn(
            scriptName,
            turn.TurnIndex,
            clientPayloads.Select(static payload => Ps3SourceGameplaySignatures.BodyRunSignature([payload])).ToArray(),
            Ps3SourceGameplaySignatures.BodyRunSignature(clientPayloads),
            Ps3SourceGameplaySignatures.BodyRunSignature(serverPayloads),
            Ps3SourceGameplaySignatures.TurnBodySignature(clientPayloads, serverPayloads),
            turn.ServerResponses);
    }

    private static void WriteEvidence(TextWriter? writer, PcapSourceTurnContractBackendEvent backendEvent)
    {
        if (writer is null)
        {
            return;
        }

        lock (writer)
        {
            writer.WriteLine(JsonSerializer.Serialize(backendEvent));
            writer.Flush();
        }
    }
}

internal sealed class PcapSourceTurnContractBackendCatalog
{
    private readonly Dictionary<string, PcapSourceTurnContractBackendTurn[]> _prefixMap;
    private readonly Dictionary<string, PcapSourceTurnContractBackendTurn[]> _exactMap;

    private PcapSourceTurnContractBackendCatalog(
        Dictionary<string, PcapSourceTurnContractBackendTurn[]> prefixMap,
        Dictionary<string, PcapSourceTurnContractBackendTurn[]> exactMap)
    {
        _prefixMap = prefixMap;
        _exactMap = exactMap;
    }

    public int PrefixKeyCount => _prefixMap.Count;

    public int ExactKeyCount => _exactMap.Count;

    public static PcapSourceTurnContractBackendCatalog Build(IReadOnlyList<PcapSourceTurnContractBackendTurn> turns)
    {
        var prefix = new Dictionary<string, List<PcapSourceTurnContractBackendTurn>>(StringComparer.Ordinal);
        var exact = new Dictionary<string, List<PcapSourceTurnContractBackendTurn>>(StringComparer.Ordinal);
        foreach (var turn in turns)
        {
            for (var count = 1; count <= turn.ClientPacketBodySignatures.Length; count++)
            {
                Add(prefix, SignatureKey(turn.ClientPacketBodySignatures.Take(count)), turn);
            }

            Add(exact, SignatureKey(turn.ClientPacketBodySignatures), turn);
        }

        return new PcapSourceTurnContractBackendCatalog(
            prefix.ToDictionary(static pair => pair.Key, static pair => pair.Value.ToArray(), StringComparer.Ordinal),
            exact.ToDictionary(static pair => pair.Key, static pair => pair.Value.ToArray(), StringComparer.Ordinal));
    }

    public PcapSourceTurnContractBackendMatchResult Match(IReadOnlyList<string> clientPacketBodySignatures)
    {
        var key = SignatureKey(clientPacketBodySignatures);
        if (!_prefixMap.TryGetValue(key, out var prefixCandidates))
        {
            return PcapSourceTurnContractBackendMatchResult.Unmatched(
                clientPacketBodySignatures.Count,
                $"No PCAP turn-contract prefix matches {clientPacketBodySignatures.Count} client packet(s).");
        }

        _exactMap.TryGetValue(key, out var completeCandidates);
        completeCandidates ??= [];
        if (completeCandidates.Length == 0)
        {
            return PcapSourceTurnContractBackendMatchResult.Waiting(
                clientPacketBodySignatures.Count,
                prefixCandidates.Length,
                $"Matched a PCAP turn-contract prefix; waiting for more client packet(s).");
        }

        var longerCandidates = prefixCandidates.Count(candidate => candidate.ClientPacketBodySignatures.Length > clientPacketBodySignatures.Count);
        if (longerCandidates > 0)
        {
            return PcapSourceTurnContractBackendMatchResult.Waiting(
                clientPacketBodySignatures.Count,
                prefixCandidates.Length,
                completeCandidates.Length,
                $"Matched {completeCandidates.Length} complete turn(s), but {longerCandidates} longer turn prefix candidate(s) also match; waiting to avoid early response.");
        }

        if (completeCandidates.Length != 1)
        {
            return PcapSourceTurnContractBackendMatchResult.Ambiguous(
                clientPacketBodySignatures.Count,
                prefixCandidates.Length,
                completeCandidates.Length,
                $"Matched {completeCandidates.Length} complete PCAP turn contracts for the same client packet body-signature sequence.");
        }

        return PcapSourceTurnContractBackendMatchResult.Success(
            clientPacketBodySignatures.Count,
            prefixCandidates.Length,
            completeCandidates.Length,
            completeCandidates[0],
            $"Matched PCAP turn contract {completeCandidates[0].ScriptName} turn {completeCandidates[0].TurnIndex}.");
    }

    private static void Add(
        Dictionary<string, List<PcapSourceTurnContractBackendTurn>> map,
        string key,
        PcapSourceTurnContractBackendTurn turn)
    {
        if (!map.TryGetValue(key, out var values))
        {
            values = [];
            map.Add(key, values);
        }

        values.Add(turn);
    }

    private static string SignatureKey(IEnumerable<string> signatures)
    {
        return string.Join('\n', signatures);
    }
}

internal sealed class PcapSourceTurnContractBackendSession
{
    private readonly List<string> _clientPacketBodySignatures = [];

    public Ps3SourceGameplaySession SourceGameplay { get; } = new();

    public PcapSourceTurnContractBackendMatchResult ObserveClientPacket(
        string packetBodySignature,
        PcapSourceTurnContractBackendCatalog catalog)
    {
        _clientPacketBodySignatures.Add(packetBodySignature);
        var result = catalog.Match(_clientPacketBodySignatures);
        if (!result.Matched && !result.WaitingForMorePackets)
        {
            _clientPacketBodySignatures.Clear();
            _clientPacketBodySignatures.Add(packetBodySignature);
            result = catalog.Match(_clientPacketBodySignatures);
        }

        if (result.Matched)
        {
            _clientPacketBodySignatures.Clear();
        }

        return result;
    }
}

public sealed record PcapSourceTurnContractBackendTurn(
    string ScriptName,
    int TurnIndex,
    string[] ClientPacketBodySignatures,
    string ClientBodySignature,
    string ServerBodySignature,
    string TurnBodySignature,
    Ps3SourceGameplayReplayStep[] ServerResponses);

public sealed record PcapSourceTurnContractBackendMatchResult(
    bool Matched,
    bool WaitingForMorePackets,
    int ClientPacketCount,
    int PrefixCandidateCount,
    int CompleteCandidateCount,
    PcapSourceTurnContractBackendTurn? Match,
    string Explanation)
{
    public static PcapSourceTurnContractBackendMatchResult Unmatched(int clientPacketCount, string explanation)
    {
        return new(false, false, clientPacketCount, 0, 0, null, explanation);
    }

    public static PcapSourceTurnContractBackendMatchResult Waiting(
        int clientPacketCount,
        int prefixCandidateCount,
        string explanation)
    {
        return new(false, true, clientPacketCount, prefixCandidateCount, 0, null, explanation);
    }

    public static PcapSourceTurnContractBackendMatchResult Waiting(
        int clientPacketCount,
        int prefixCandidateCount,
        int completeCandidateCount,
        string explanation)
    {
        return new(false, true, clientPacketCount, prefixCandidateCount, completeCandidateCount, null, explanation);
    }

    public static PcapSourceTurnContractBackendMatchResult Ambiguous(
        int clientPacketCount,
        int prefixCandidateCount,
        int completeCandidateCount,
        string explanation)
    {
        return new(false, false, clientPacketCount, prefixCandidateCount, completeCandidateCount, null, explanation);
    }

    public static PcapSourceTurnContractBackendMatchResult Success(
        int clientPacketCount,
        int prefixCandidateCount,
        int completeCandidateCount,
        PcapSourceTurnContractBackendTurn match,
        string explanation)
    {
        return new(true, false, clientPacketCount, prefixCandidateCount, completeCandidateCount, match, explanation);
    }
}

public sealed record PcapSourceTurnContractBackendEvent(
    DateTimeOffset Timestamp,
    string Event,
    string Endpoint,
    int PayloadLength,
    bool Matched,
    bool WaitingForMorePackets,
    int ClientPacketCount,
    int PrefixCandidateCount,
    int CompleteCandidateCount,
    string Explanation,
    string ReplayScript,
    int? TurnIndex,
    string? ClientBodySignature,
    string? ServerBodySignature,
    string? TurnBodySignature,
    string HexPrefix,
    int? SourceSequence,
    int? SourceBodyLength,
    int? SourceSequenceDelta,
    string? SourcePacketShape,
    int? SourceDirectionPacketCount,
    bool? SourceSequenceDecrease,
    long? PacketIndex);
