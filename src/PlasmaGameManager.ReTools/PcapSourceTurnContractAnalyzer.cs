using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class PcapSourceTurnContractAnalyzer
{
    private readonly PcapActiveFlowReplayExtractor _extractor = new();

    public async Task<PcapSourceTurnContractReport> AnalyzeDirectoryAsync(
        string inputDirectory,
        string outputPath)
    {
        var report = AnalyzeDirectory(inputDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
        return report;
    }

    public PcapSourceTurnContractReport AnalyzeDirectory(string inputDirectory)
    {
        var files = Directory.EnumerateFiles(inputDirectory, "*.*", SearchOption.AllDirectories)
            .Where(static p => p.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            .OrderBy(static p => p, StringComparer.Ordinal)
            .ToArray();

        var fileReports = files.Select(file => AnalyzeFile(inputDirectory, file)).ToArray();
        return new PcapSourceTurnContractReport(
            BuildSummary(fileReports),
            fileReports.Select(static report => report.File).ToArray());
    }

    private PcapSourceTurnContractFileAnalysis AnalyzeFile(string inputDirectory, string file)
    {
        var relativePath = Path.GetRelativePath(inputDirectory, file);
        var replay = _extractor.Extract(file);
        if (replay is null)
        {
            return new PcapSourceTurnContractFileAnalysis(
                new PcapSourceTurnContractFile(
                    relativePath,
                    false,
                    "",
                    "",
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    "no-active-source-flow",
                    "No active Source/gameplay flow was found.",
                    [],
                    []),
                []);
        }

        var steps = replay.SourcePackets
            .Select(static packet => new Ps3SourceGameplayReplayStep(
                packet.Direction == PcapActiveFlowDirection.ClientToServer
                    ? Ps3SourceGameplayDirection.ClientToServer
                    : Ps3SourceGameplayDirection.ServerToClient,
                packet.Payload,
                packet.PacketIndex,
                packet.TimestampMicroseconds))
            .ToArray();
        var turns = Ps3SourceGameplayTurnReplayDriver.BuildTurns(steps);
        var entries = turns.Select(BuildEntry).ToArray();
        var collisions = BuildCollisionGroups(entries);
        var ambiguous = collisions.Where(static group => group.DistinctServerBodySignatureCount > 1).ToArray();
        var repeatedDeterministic = collisions.Where(static group => group.DistinctServerBodySignatureCount == 1).ToArray();

        return new PcapSourceTurnContractFileAnalysis(
            new PcapSourceTurnContractFile(
                relativePath,
                true,
                replay.ClientEndpoint,
                replay.ServerEndpoint,
                replay.SourcePackets.Length,
                turns.Length,
                turns.Count(static turn => turn.ServerResponses.Length > 0),
                entries.Select(static entry => entry.ClientBodySignature).Distinct(StringComparer.Ordinal).Count(),
                entries.Select(static entry => entry.TurnBodySignature).Distinct(StringComparer.Ordinal).Count(),
                repeatedDeterministic.Length,
                ambiguous.Length,
                turns.Length == 0 ? 0 : turns.Max(static turn => turn.ClientPackets.Length),
                turns.Length == 0 ? 0 : turns.Max(static turn => turn.ServerResponses.Length),
                ContractStatus(turns.Length, ambiguous.Length),
                ContractConclusion(turns.Length, ambiguous.Length),
                entries,
                collisions.Take(32).ToArray()),
            entries);
    }

    private static PcapSourceTurnContractEntry BuildEntry(Ps3SourceGameplayReplayTurn turn)
    {
        var clientPayloads = turn.ClientPackets.Select(static packet => packet.Payload).ToArray();
        var serverPayloads = turn.ServerResponses.Select(static packet => packet.Payload).ToArray();
        return new PcapSourceTurnContractEntry(
            turn.TurnIndex,
            turn.ClientPackets.Length,
            turn.ServerResponses.Length,
            turn.ClientPackets[0].PacketIndex,
            (serverPayloads.Length > 0 ? turn.ServerResponses[^1] : turn.ClientPackets[^1]).PacketIndex,
            FirstSequence(turn.ClientPackets),
            LastSequence(turn.ClientPackets),
            FirstSequence(turn.ServerResponses),
            LastSequence(turn.ServerResponses),
            Ps3SourceGameplaySignatures.BodyRunSignature(clientPayloads),
            Ps3SourceGameplaySignatures.BodyRunSignature(serverPayloads),
            Ps3SourceGameplaySignatures.TurnBodySignature(clientPayloads, serverPayloads),
            Ps3SourceGameplaySignatures.ShapeRunSignature(clientPayloads),
            Ps3SourceGameplaySignatures.ShapeRunSignature(serverPayloads),
            clientPayloads.Select(static payload => Ps3SourceGameplaySignatures.BodyRunSignature([payload])).ToArray(),
            serverPayloads.Select(static payload => Ps3SourceGameplaySignatures.BodyRunSignature([payload])).ToArray());
    }

    private static PcapSourceTurnContractCollision[] BuildCollisionGroups(PcapSourceTurnContractEntry[] entries)
    {
        return entries
            .GroupBy(static entry => entry.ClientBodySignature, StringComparer.Ordinal)
            .Where(static group => group.Count() > 1)
            .Select(static group => new PcapSourceTurnContractCollision(
                group.Key,
                group.Count(),
                group.Select(static entry => entry.ServerBodySignature).Distinct(StringComparer.Ordinal).Count(),
                group.Select(static entry => entry.TurnBodySignature).Distinct(StringComparer.Ordinal).Count(),
                group.Select(static entry => entry.TurnIndex).Take(16).ToArray(),
                group
                    .GroupBy(static entry => entry.ServerBodySignature, StringComparer.Ordinal)
                    .OrderByDescending(static serverGroup => serverGroup.Count())
                    .ThenBy(static serverGroup => serverGroup.Key, StringComparer.Ordinal)
                    .Take(8)
                    .Select(static serverGroup => new PcapSourceTurnContractCount(serverGroup.Key, serverGroup.Count()))
                    .ToArray()))
            .OrderByDescending(static group => group.DistinctServerBodySignatureCount)
            .ThenByDescending(static group => group.OccurrenceCount)
            .ThenBy(static group => group.ClientBodySignature, StringComparer.Ordinal)
            .ToArray();
    }

    private static PcapSourceTurnContractSummary BuildSummary(PcapSourceTurnContractFileAnalysis[] analyses)
    {
        var active = analyses.Where(static analysis => analysis.File.HasActiveSourceFlow).ToArray();
        var activeFiles = active.Select(static analysis => analysis.File).ToArray();
        var globalEntries = active.SelectMany(static analysis => analysis.AllTurns).ToArray();
        var globalCollisions = BuildCollisionGroups(globalEntries);
        var globalAmbiguous = globalCollisions.Count(static group => group.DistinctServerBodySignatureCount > 1);
        var status = globalAmbiguous == 0
            ? "deterministic-within-all-captured-turns"
            : "ambiguous-client-turn-signatures-present";

        return new PcapSourceTurnContractSummary(
            analyses.Length,
            active.Length,
            activeFiles.Sum(static file => file.SourcePacketCount),
            activeFiles.Sum(static file => file.TurnCount),
            activeFiles.Sum(static file => file.RespondedTurnCount),
            activeFiles.Length == 0 ? 0 : activeFiles.Max(static file => file.MaxClientBurstPacketCount),
            activeFiles.Length == 0 ? 0 : activeFiles.Max(static file => file.MaxServerResponsePacketCount),
            activeFiles.Sum(static file => file.UniqueClientBodySignatureCount),
            activeFiles.Sum(static file => file.UniqueTurnBodySignatureCount),
            activeFiles.Sum(static file => file.RepeatedDeterministicClientSignatureCount),
            activeFiles.Sum(static file => file.AmbiguousClientSignatureCount),
            globalEntries.Select(static entry => entry.ClientBodySignature).Distinct(StringComparer.Ordinal).Count(),
            globalEntries.Select(static entry => entry.TurnBodySignature).Distinct(StringComparer.Ordinal).Count(),
            globalAmbiguous,
            status,
            globalAmbiguous == 0
                ? "All captured PCAP client turn signatures map to one captured server response signature. This is enough for stable fixture matching, but a native backend still needs semantic packet decoding."
                : "Some captured client turn signatures map to multiple captured server response signatures. A native backend must include session/state context, not only the client burst body signature.");
    }

    private static string ContractStatus(int turnCount, int ambiguousCount)
    {
        if (turnCount == 0)
        {
            return "no-turns";
        }

        return ambiguousCount == 0
            ? "deterministic-client-burst-response-map"
            : "ambiguous-client-burst-response-map";
    }

    private static string ContractConclusion(int turnCount, int ambiguousCount)
    {
        if (turnCount == 0)
        {
            return "No Source/gameplay turns were available.";
        }

        return ambiguousCount == 0
            ? "Within this active flow, each repeated sequence-insensitive client burst signature maps to one captured server response signature."
            : "Within this active flow, at least one sequence-insensitive client burst signature maps to multiple server response signatures; preserve more state when using this as a backend contract.";
    }

    private static int? FirstSequence(IReadOnlyList<Ps3SourceGameplayReplayStep> packets)
    {
        return packets.Count > 0 && Ps3SourceTransportPacket.TryDecode(packets[0].Payload, out var packet)
            ? packet.CandidateSequence
            : null;
    }

    private static int? LastSequence(IReadOnlyList<Ps3SourceGameplayReplayStep> packets)
    {
        return packets.Count > 0 && Ps3SourceTransportPacket.TryDecode(packets[^1].Payload, out var packet)
            ? packet.CandidateSequence
            : null;
    }
}

public sealed record PcapSourceTurnContractReport(
    PcapSourceTurnContractSummary Summary,
    PcapSourceTurnContractFile[] Files);

internal sealed record PcapSourceTurnContractFileAnalysis(
    PcapSourceTurnContractFile File,
    PcapSourceTurnContractEntry[] AllTurns);

public sealed record PcapSourceTurnContractSummary(
    int FileCount,
    int ActiveSourceFlowCount,
    int SourcePacketCount,
    int TurnCount,
    int RespondedTurnCount,
    int MaxClientBurstPacketCount,
    int MaxServerResponsePacketCount,
    int PerFileUniqueClientBodySignatureTotal,
    int PerFileUniqueTurnBodySignatureTotal,
    int PerFileRepeatedDeterministicClientSignatureTotal,
    int PerFileAmbiguousClientSignatureTotal,
    int GlobalUniqueClientBodySignatureCount,
    int GlobalUniqueTurnBodySignatureCount,
    int GlobalAmbiguousClientSignatureCount,
    string Status,
    string Conclusion);

public sealed record PcapSourceTurnContractFile(
    string File,
    bool HasActiveSourceFlow,
    string ClientEndpoint,
    string ServerEndpoint,
    int SourcePacketCount,
    int TurnCount,
    int RespondedTurnCount,
    int UniqueClientBodySignatureCount,
    int UniqueTurnBodySignatureCount,
    int RepeatedDeterministicClientSignatureCount,
    int AmbiguousClientSignatureCount,
    int MaxClientBurstPacketCount,
    int MaxServerResponsePacketCount,
    string ContractStatus,
    string ContractConclusion,
    PcapSourceTurnContractEntry[] SampleTurns,
    PcapSourceTurnContractCollision[] ClientSignatureCollisions);

public sealed record PcapSourceTurnContractEntry(
    int TurnIndex,
    int ClientPacketCount,
    int ServerResponsePacketCount,
    long FirstPacketIndex,
    long LastPacketIndex,
    int? FirstClientSequence,
    int? LastClientSequence,
    int? FirstServerSequence,
    int? LastServerSequence,
    string ClientBodySignature,
    string ServerBodySignature,
    string TurnBodySignature,
    string ClientShapeSignature,
    string ServerShapeSignature,
    string[] ClientPacketBodySignatures,
    string[] ServerResponseBodySignatures);

public sealed record PcapSourceTurnContractCollision(
    string ClientBodySignature,
    int OccurrenceCount,
    int DistinctServerBodySignatureCount,
    int DistinctTurnBodySignatureCount,
    int[] SampleTurnIndexes,
    PcapSourceTurnContractCount[] ServerBodySignatureCounts);

public sealed record PcapSourceTurnContractCount(
    string Value,
    int Count);
