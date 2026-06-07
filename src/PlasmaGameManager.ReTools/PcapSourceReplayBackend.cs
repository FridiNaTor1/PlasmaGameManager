using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class PcapSourceReplayBackend
{
    private readonly PcapActiveFlowReplayExtractor _extractor = new();

    public async Task RunAsync(
        string pcapPath,
        IPAddress bindAddress,
        int port,
        CancellationToken ct,
        TextWriter? evidenceWriter = null,
        Ps3SourceGameplayReplayMatchMode matchMode = Ps3SourceGameplayReplayMatchMode.ExactPayload,
        int clientSearchWindow = 0,
        PcapSourceReplayPacingMode pacingMode = PcapSourceReplayPacingMode.None,
        int maxReplayDelayMilliseconds = 250,
        PcapSourceReplayBackendMode backendMode = PcapSourceReplayBackendMode.Packet)
    {
        var scripts = LoadReplayScripts(pcapPath);
        await RunAsync(scripts, bindAddress, port, ct, evidenceWriter, matchMode, clientSearchWindow, pacingMode, maxReplayDelayMilliseconds, backendMode);
    }

    public async Task RunAsync(
        IEnumerable<Ps3SourceGameplayReplayStep> steps,
        IPAddress bindAddress,
        int port,
        CancellationToken ct,
        TextWriter? evidenceWriter = null,
        Ps3SourceGameplayReplayMatchMode matchMode = Ps3SourceGameplayReplayMatchMode.ExactPayload,
        int clientSearchWindow = 0,
        PcapSourceReplayPacingMode pacingMode = PcapSourceReplayPacingMode.None,
        int maxReplayDelayMilliseconds = 250,
        PcapSourceReplayBackendMode backendMode = PcapSourceReplayBackendMode.Packet)
    {
        var script = new PcapSourceReplayScript("inline-script", steps.ToArray());
        await RunAsync([script], bindAddress, port, ct, evidenceWriter, matchMode, clientSearchWindow, pacingMode, maxReplayDelayMilliseconds, backendMode);
    }

    public async Task RunAsync(
        IReadOnlyList<PcapSourceReplayScript> scripts,
        IPAddress bindAddress,
        int port,
        CancellationToken ct,
        TextWriter? evidenceWriter = null,
        Ps3SourceGameplayReplayMatchMode matchMode = Ps3SourceGameplayReplayMatchMode.ExactPayload,
        int clientSearchWindow = 0,
        PcapSourceReplayPacingMode pacingMode = PcapSourceReplayPacingMode.None,
        int maxReplayDelayMilliseconds = 250,
        PcapSourceReplayBackendMode backendMode = PcapSourceReplayBackendMode.Packet)
    {
        using var socket = new UdpClient(new IPEndPoint(bindAddress, port));
        var drivers = new Dictionary<string, Ps3SourceGameplayReplayDriver>(StringComparer.Ordinal);
        var turnDrivers = new Dictionary<string, Ps3SourceGameplayTurnReplayDriver>(StringComparer.Ordinal);
        var driverScripts = new Dictionary<string, string>(StringComparer.Ordinal);
        var sessions = new Dictionary<string, Ps3SourceGameplaySession>(StringComparer.Ordinal);
        var scriptSet = scripts.Where(static script => script.Steps.Length > 0).ToArray();
        if (scriptSet.Length == 0)
        {
            throw new InvalidOperationException("Source replay script set has no packets.");
        }

        maxReplayDelayMilliseconds = Math.Max(0, maxReplayDelayMilliseconds);
        Console.WriteLine($"PCAP Source replay backend listening on {bindAddress}:{port} scripts={scriptSet.Length} packets={scriptSet.Sum(static script => script.Steps.Length)} backendMode={backendMode} matchMode={matchMode} clientSearchWindow={clientSearchWindow} pacingMode={pacingMode} maxReplayDelayMs={maxReplayDelayMilliseconds}");
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
                session = new Ps3SourceGameplaySession();
                sessions.Add(endpoint, session);
            }

            var clientObservation = session.Observe(Ps3SourceGameplayDirection.ClientToServer, received.Buffer);
            var selection = SelectReplayDriver(
                endpoint,
                received.Buffer,
                scriptSet,
                drivers,
                turnDrivers,
                driverScripts,
                matchMode,
                clientSearchWindow,
                backendMode);
            var result = selection.Result;
            WriteEvidence(
                evidenceWriter,
                new PcapSourceReplayBackendEvent(
                    DateTimeOffset.UtcNow,
                    "source-replay-receive",
                    endpoint,
                    received.Buffer.Length,
                    null,
                    Ps3SourceGameplayDirection.ClientToServer.ToString(),
                    result.Matched,
                    result.Cursor,
                    result.ServerResponses.Length,
                    result.Explanation,
                    backendMode.ToString(),
                    result.MatchKind.ToString(),
                    selection.ScriptName,
                    result.TurnCursor,
                    result.ClientCursor,
                    result.ExpectedClientPacketsInTurn,
                    result.ClientBodySignature,
                    result.ServerBodySignature,
                    result.TurnBodySignature,
                    Convert.ToHexString(received.Buffer.AsSpan(0, Math.Min(8, received.Buffer.Length))).ToLowerInvariant(),
                    clientObservation.Sequence,
                    clientObservation.BodyLength == 0 ? null : clientObservation.BodyLength,
                    clientObservation.SequenceDeltaFromPreviousSameDirection,
                    clientObservation.Shape.ToString(),
                    clientObservation.DirectionPacketCount,
                    clientObservation.SequenceDecrease,
                    null));
            Console.WriteLine($"{DateTimeOffset.Now:HH:mm:ss.fff} <= {endpoint} replay script={selection.ScriptName} matched={result.Matched} responses={result.ServerResponses.Length} cursor={result.Cursor} {result.Explanation}");
            if (!result.Matched)
            {
                continue;
            }

            long? previousReplayTimestamp = result.MatchedClientTimestampMicroseconds;
            foreach (var response in result.ServerResponses)
            {
                var replayDelay = ReplayDelay(previousReplayTimestamp, response.TimestampMicroseconds, pacingMode, maxReplayDelayMilliseconds);
                if (replayDelay > TimeSpan.Zero)
                {
                    await Task.Delay(replayDelay, ct);
                }

                await socket.SendAsync(response.Payload, response.Payload.Length, received.RemoteEndPoint);
                var serverObservation = session.Observe(Ps3SourceGameplayDirection.ServerToClient, response.Payload);
                WriteEvidence(
                    evidenceWriter,
                    new PcapSourceReplayBackendEvent(
                        DateTimeOffset.UtcNow,
                        "source-replay-send",
                        endpoint,
                        response.Payload.Length,
                        response.PacketIndex,
                        Ps3SourceGameplayDirection.ServerToClient.ToString(),
                        true,
                        result.Cursor,
                        0,
                        "Emitted captured server Source/gameplay packet.",
                        backendMode.ToString(),
                        Ps3SourceGameplayReplayMatchKind.None.ToString(),
                        selection.ScriptName,
                        result.TurnCursor,
                        result.ClientCursor,
                        result.ExpectedClientPacketsInTurn,
                        result.ClientBodySignature,
                        result.ServerBodySignature,
                        result.TurnBodySignature,
                        Convert.ToHexString(response.Payload.AsSpan(0, Math.Min(8, response.Payload.Length))).ToLowerInvariant(),
                        serverObservation.Sequence,
                        serverObservation.BodyLength == 0 ? null : serverObservation.BodyLength,
                        serverObservation.SequenceDeltaFromPreviousSameDirection,
                        serverObservation.Shape.ToString(),
                        serverObservation.DirectionPacketCount,
                        serverObservation.SequenceDecrease,
                        replayDelay.TotalMilliseconds == 0 ? null : replayDelay.TotalMilliseconds));
                Console.WriteLine($"{DateTimeOffset.Now:HH:mm:ss.fff} => {endpoint} replay script={selection.ScriptName} packetIndex={response.PacketIndex} len={response.Payload.Length} delayMs={replayDelay.TotalMilliseconds:0.###}");
                previousReplayTimestamp = response.TimestampMicroseconds;
            }
        }
    }

    private PcapSourceReplayScript[] LoadReplayScripts(string path)
    {
        if (File.Exists(path))
        {
            return [LoadReplayScript(path, Path.GetFileName(path))];
        }

        if (!Directory.Exists(path))
        {
            throw new FileNotFoundException($"PCAP replay input path does not exist: {path}", path);
        }

        var scripts = Directory.EnumerateFiles(path, "*.*", SearchOption.AllDirectories)
            .Where(static p => p.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            .OrderBy(static p => p, StringComparer.Ordinal)
            .Select(file =>
            {
                try
                {
                    return LoadReplayScript(file, Path.GetRelativePath(path, file));
                }
                catch (InvalidOperationException)
                {
                    return null;
                }
            })
            .OfType<PcapSourceReplayScript>()
            .ToArray();

        if (scripts.Length == 0)
        {
            throw new InvalidOperationException($"No active Source/gameplay replay flows were found under {path}.");
        }

        return scripts;
    }

    private PcapSourceReplayScript LoadReplayScript(string file, string name)
    {
        var replay = _extractor.Extract(file)
            ?? throw new InvalidOperationException($"PCAP does not contain an active Source/gameplay flow: {file}");
        var steps = replay.SourcePackets.Select(static packet =>
            new Ps3SourceGameplayReplayStep(
                packet.Direction == PcapActiveFlowDirection.ClientToServer
                    ? Ps3SourceGameplayDirection.ClientToServer
                    : Ps3SourceGameplayDirection.ServerToClient,
                packet.Payload,
                packet.PacketIndex,
                packet.TimestampMicroseconds))
            .ToArray();

        return new PcapSourceReplayScript(name, steps);
    }

    private static PcapSourceReplaySelection SelectReplayDriver(
        string endpoint,
        byte[] payload,
        IReadOnlyList<PcapSourceReplayScript> scripts,
        Dictionary<string, Ps3SourceGameplayReplayDriver> drivers,
        Dictionary<string, Ps3SourceGameplayTurnReplayDriver> turnDrivers,
        Dictionary<string, string> driverScripts,
        Ps3SourceGameplayReplayMatchMode matchMode,
        int clientSearchWindow,
        PcapSourceReplayBackendMode backendMode)
    {
        if (backendMode == PcapSourceReplayBackendMode.Turn)
        {
            return SelectTurnReplayDriver(endpoint, payload, scripts, turnDrivers, driverScripts, matchMode);
        }

        if (drivers.TryGetValue(endpoint, out var existing))
        {
            var result = existing.HandleClientPacket(payload);
            return new PcapSourceReplaySelection(
                driverScripts.GetValueOrDefault(endpoint, ""),
                PcapSourceReplayBackendStepResult.FromPacket(result));
        }

        Ps3SourceGameplayReplayResult? firstFailure = null;
        PcapSourceReplaySelection? bestMatched = null;
        var bestRank = 0;
        foreach (var script in scripts)
        {
            var driver = new Ps3SourceGameplayReplayDriver(script.Steps, matchMode, clientSearchWindow);
            var result = driver.HandleClientPacket(payload);
            firstFailure ??= result;
            if (!result.Matched)
            {
                continue;
            }

            var selection = new PcapSourceReplaySelection(script.Name, PcapSourceReplayBackendStepResult.FromPacket(result), PacketDriver: driver);
            var rank = ReplayMatchRank(result);
            if (rank > bestRank)
            {
                bestMatched = selection;
                bestRank = rank;
            }

            if (rank == ReplayMatchRank(Ps3SourceGameplayReplayMatchKind.ExactPayload))
            {
                break;
            }
        }

        if (bestMatched is not null)
        {
            drivers.Add(endpoint, bestMatched.PacketDriver!);
            driverScripts.Add(endpoint, bestMatched.ScriptName);
            return bestMatched;
        }

        return new PcapSourceReplaySelection(
            "",
            PcapSourceReplayBackendStepResult.FromPacket(firstFailure ?? new Ps3SourceGameplayReplayResult(
                false,
                false,
                0,
                null,
                null,
                [],
                Ps3SourceGameplayReplayMatchKind.None,
                "No replay scripts were available.")));
    }

    private static PcapSourceReplaySelection SelectTurnReplayDriver(
        string endpoint,
        byte[] payload,
        IReadOnlyList<PcapSourceReplayScript> scripts,
        Dictionary<string, Ps3SourceGameplayTurnReplayDriver> turnDrivers,
        Dictionary<string, string> driverScripts,
        Ps3SourceGameplayReplayMatchMode matchMode)
    {
        if (turnDrivers.TryGetValue(endpoint, out var existing))
        {
            var result = existing.HandleClientPacket(payload);
            return new PcapSourceReplaySelection(
                driverScripts.GetValueOrDefault(endpoint, ""),
                PcapSourceReplayBackendStepResult.FromTurn(result));
        }

        Ps3SourceGameplayTurnReplayResult? firstFailure = null;
        PcapSourceReplaySelection? bestMatched = null;
        Ps3SourceGameplayTurnReplayDriver? bestDriver = null;
        var bestRank = 0;
        foreach (var script in scripts)
        {
            var driver = new Ps3SourceGameplayTurnReplayDriver(script.Steps, matchMode);
            var result = driver.HandleClientPacket(payload);
            firstFailure ??= result;
            if (!result.Matched)
            {
                continue;
            }

            var selection = new PcapSourceReplaySelection(script.Name, PcapSourceReplayBackendStepResult.FromTurn(result), TurnDriver: driver);
            var rank = ReplayMatchRank(result.MatchKind);
            if (rank > bestRank)
            {
                bestMatched = selection;
                bestDriver = driver;
                bestRank = rank;
            }

            if (rank == ReplayMatchRank(Ps3SourceGameplayReplayMatchKind.ExactPayload))
            {
                break;
            }
        }

        if (bestMatched is not null)
        {
            turnDrivers.Add(endpoint, bestDriver!);
            driverScripts.Add(endpoint, bestMatched.ScriptName);
            return bestMatched;
        }

        return new PcapSourceReplaySelection(
            "",
            PcapSourceReplayBackendStepResult.FromTurn(firstFailure ?? new Ps3SourceGameplayTurnReplayResult(
                false,
                false,
                0,
                0,
                0,
                null,
                null,
                [],
                Ps3SourceGameplaySignatures.BodyRunSignature([]),
                Ps3SourceGameplaySignatures.BodyRunSignature([]),
                Ps3SourceGameplaySignatures.TurnBodySignature([], []),
                Ps3SourceGameplayReplayMatchKind.None,
                "No replay scripts were available.")));
    }

    private static int ReplayMatchRank(Ps3SourceGameplayReplayResult result)
    {
        return result.Matched ? ReplayMatchRank(result.MatchKind) : 0;
    }

    private static int ReplayMatchRank(Ps3SourceGameplayReplayMatchKind matchKind)
    {
        return matchKind switch
        {
            Ps3SourceGameplayReplayMatchKind.ExactPayload => 3,
            Ps3SourceGameplayReplayMatchKind.ExactTransportBody => 2,
            Ps3SourceGameplayReplayMatchKind.TransportShape => 1,
            _ => 0
        };
    }

    private static TimeSpan ReplayDelay(
        long? previousReplayTimestampMicroseconds,
        long currentReplayTimestampMicroseconds,
        PcapSourceReplayPacingMode pacingMode,
        int maxReplayDelayMilliseconds)
    {
        if (pacingMode != PcapSourceReplayPacingMode.CaptureTiming
            || previousReplayTimestampMicroseconds is null
            || currentReplayTimestampMicroseconds <= previousReplayTimestampMicroseconds.Value)
        {
            return TimeSpan.Zero;
        }

        var delayMilliseconds = (currentReplayTimestampMicroseconds - previousReplayTimestampMicroseconds.Value) / 1000.0;
        delayMilliseconds = Math.Min(delayMilliseconds, maxReplayDelayMilliseconds);
        return TimeSpan.FromMilliseconds(delayMilliseconds);
    }

    private static void WriteEvidence(TextWriter? writer, PcapSourceReplayBackendEvent replayEvent)
    {
        if (writer is null)
        {
            return;
        }

        lock (writer)
        {
            writer.WriteLine(JsonSerializer.Serialize(replayEvent));
            writer.Flush();
        }
    }
}

public sealed record PcapSourceReplayBackendEvent(
    DateTimeOffset Timestamp,
    string Event,
    string Endpoint,
    int PayloadLength,
    long? PacketIndex,
    string Direction,
    bool Matched,
    int Cursor,
    int ServerResponseCount,
    string Explanation,
    string ReplayBackendMode,
    string ReplayMatchKind,
    string ReplayScript,
    int? TurnCursor,
    int? ClientCursor,
    int? ExpectedClientPacketsInTurn,
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
    double? ReplayDelayMilliseconds);

public sealed record PcapSourceReplayScript(
    string Name,
    Ps3SourceGameplayReplayStep[] Steps);

internal sealed record PcapSourceReplaySelection(
    string ScriptName,
    PcapSourceReplayBackendStepResult Result,
    Ps3SourceGameplayReplayDriver? PacketDriver = null,
    Ps3SourceGameplayTurnReplayDriver? TurnDriver = null);

internal sealed record PcapSourceReplayBackendStepResult(
    bool Matched,
    bool IsComplete,
    int Cursor,
    int? TurnCursor,
    int? ClientCursor,
    int? ExpectedClientPacketsInTurn,
    string? ClientBodySignature,
    string? ServerBodySignature,
    string? TurnBodySignature,
    long? MatchedClientPacketIndex,
    long? MatchedClientTimestampMicroseconds,
    Ps3SourceGameplayReplayStep[] ServerResponses,
    Ps3SourceGameplayReplayMatchKind MatchKind,
    string Explanation)
{
    public static PcapSourceReplayBackendStepResult FromPacket(Ps3SourceGameplayReplayResult result)
    {
        return new PcapSourceReplayBackendStepResult(
            result.Matched,
            result.IsComplete,
            result.Cursor,
            null,
            null,
            null,
            null,
            null,
            null,
            result.MatchedClientPacketIndex,
            result.MatchedClientTimestampMicroseconds,
            result.ServerResponses,
            result.MatchKind,
            result.Explanation);
    }

    public static PcapSourceReplayBackendStepResult FromTurn(Ps3SourceGameplayTurnReplayResult result)
    {
        return new PcapSourceReplayBackendStepResult(
            result.Matched,
            result.IsComplete,
            result.TurnCursor,
            result.TurnCursor,
            result.ClientCursor,
            result.ExpectedClientPacketsInTurn,
            result.ClientBodySignature,
            result.ServerBodySignature,
            result.TurnBodySignature,
            result.MatchedClientPacketIndex,
            result.MatchedClientTimestampMicroseconds,
            result.ServerResponses,
            result.MatchKind,
            result.Explanation);
    }
}

public enum PcapSourceReplayPacingMode
{
    None,
    CaptureTiming
}

public enum PcapSourceReplayBackendMode
{
    Packet,
    Turn
}
