using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class PcapSourceTransportSemanticsAnalyzer
{
    private const int AckWindow = 128;
    private readonly PcapActiveFlowReplayExtractor _extractor = new();

    public async Task<PcapSourceTransportSemanticsReport> AnalyzeDirectoryAsync(string inputDirectory, string outputPath)
    {
        var report = AnalyzeDirectory(inputDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
        return report;
    }

    public PcapSourceTransportSemanticsReport AnalyzeDirectory(string inputDirectory)
    {
        var files = Directory.EnumerateFiles(inputDirectory, "*.*", SearchOption.AllDirectories)
            .Where(static p => p.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            .OrderBy(static p => p, StringComparer.Ordinal)
            .ToArray();
        var fileReports = files.Select(file => AnalyzeFile(inputDirectory, file)).ToArray();
        return new PcapSourceTransportSemanticsReport(BuildSummary(fileReports), fileReports);
    }

    private PcapSourceTransportSemanticsFile AnalyzeFile(string inputDirectory, string file)
    {
        var relativePath = Path.GetRelativePath(inputDirectory, file);
        var replay = _extractor.Extract(file);
        if (replay is null)
        {
            return new PcapSourceTransportSemanticsFile(
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
                EmptySequence(PcapActiveFlowDirection.ClientToServer),
                EmptySequence(PcapActiveFlowDirection.ServerToClient),
                Array.Empty<PcapSourceAckCandidate>(),
                Array.Empty<PcapSourceTransportSample>());
        }

        var packets = replay.SourcePackets;
        var parsed = packets
            .Where(static packet => Ps3SourceTransportPacket.TryDecode(packet.Payload, out _))
            .ToArray();
        return new PcapSourceTransportSemanticsFile(
            relativePath,
            true,
            replay.ClientEndpoint,
            replay.ServerEndpoint,
            replay.ServerPort,
            replay.FirstSourceClientPacketIndex,
            packets.Length,
            parsed.Length,
            packets.Count(static packet => packet.Direction == PcapActiveFlowDirection.ClientToServer),
            packets.Count(static packet => packet.Direction == PcapActiveFlowDirection.ServerToClient),
            BuildSequenceStats(packets, PcapActiveFlowDirection.ClientToServer),
            BuildSequenceStats(packets, PcapActiveFlowDirection.ServerToClient),
            BuildAckCandidates(packets),
            BuildSamples(packets));
    }

    private static PcapSourceTransportSemanticsSummary BuildSummary(PcapSourceTransportSemanticsFile[] files)
    {
        var active = files.Where(static file => file.HasActiveSourceFlow).ToArray();
        var ackCandidates = active.SelectMany(static file => file.AckCandidates).ToArray();
        return new PcapSourceTransportSemanticsSummary(
            files.Length,
            active.Length,
            active.Sum(static file => file.SourcePacketCount),
            active.Sum(static file => file.ParsedTransportPacketCount),
            active.Count(static file => file.ClientSequence.DecreaseCount <= 2 && file.ClientSequence.PacketCount > 0),
            active.Count(static file => file.ServerSequence.DecreaseCount <= 2 && file.ServerSequence.PacketCount > 0),
            active.Max(static file => file.ClientSequence.MaxDelta),
            active.Max(static file => file.ServerSequence.MaxDelta),
            ackCandidates.Length == 0 ? 0 : ackCandidates.Max(static candidate => candidate.ExactLatestOppositeSequenceMatches),
            ackCandidates.Length == 0 ? 0 : ackCandidates.Max(static candidate => candidate.WithinWindowLatestOppositeSequenceMatches));
    }

    private static PcapSourceSequenceStats EmptySequence(PcapActiveFlowDirection direction)
    {
        return new PcapSourceSequenceStats(direction.ToString(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, Array.Empty<int>());
    }

    private static PcapSourceSequenceStats BuildSequenceStats(
        IReadOnlyList<PcapActiveFlowDatagram> packets,
        PcapActiveFlowDirection direction)
    {
        var values = packets
            .Where(packet => packet.Direction == direction)
            .Select(static packet => Ps3SourceTransportPacket.TryDecode(packet.Payload, out var decoded)
                ? (int?)decoded.CandidateSequence
                : null)
            .Where(static value => value is not null)
            .Select(static value => value!.Value)
            .ToArray();
        if (values.Length == 0)
        {
            return EmptySequence(direction);
        }

        var increaseCount = 0;
        var sameCount = 0;
        var decreaseCount = 0;
        var wrapCount = 0;
        var deltaTotal = 0.0;
        var maxDelta = 0;
        for (var i = 1; i < values.Length; i++)
        {
            var previous = (ushort)values[i - 1];
            var current = (ushort)values[i];
            var delta = Ps3SourceTransportPacket.SequenceDelta(previous, current);
            maxDelta = Math.Max(maxDelta, delta);
            deltaTotal += delta;

            if (values[i] > values[i - 1])
            {
                increaseCount++;
            }
            else if (values[i] == values[i - 1])
            {
                sameCount++;
            }
            else
            {
                decreaseCount++;
                if (delta > 0)
                {
                    wrapCount++;
                }
            }
        }

        return new PcapSourceSequenceStats(
            direction.ToString(),
            values.Length,
            values.Distinct().Count(),
            values[0],
            values[^1],
            values.Min(),
            values.Max(),
            increaseCount,
            sameCount,
            decreaseCount,
            wrapCount,
            values.Length < 2 ? 0 : Math.Round(deltaTotal / (values.Length - 1), 3),
            maxDelta,
            values.Take(16).ToArray());
    }

    private static PcapSourceAckCandidate[] BuildAckCandidates(IReadOnlyList<PcapActiveFlowDatagram> packets)
    {
        var candidates = new List<PcapSourceAckCandidate>();
        foreach (var direction in Enum.GetValues<PcapActiveFlowDirection>())
        {
            foreach (var offset in Enumerable.Range(2, 10))
            {
                if (offset + 2 > 12)
                {
                    continue;
                }

                candidates.Add(BuildAckCandidate(packets, direction, offset, "be"));
                candidates.Add(BuildAckCandidate(packets, direction, offset, "le"));
            }
        }

        return candidates
            .Where(static candidate => candidate.ComparedPacketCount >= 4)
            .OrderByDescending(static candidate => candidate.ExactLatestOppositeSequenceMatches)
            .ThenByDescending(static candidate => candidate.WithinWindowLatestOppositeSequenceMatches)
            .ThenBy(static candidate => candidate.Direction, StringComparer.Ordinal)
            .ThenBy(static candidate => candidate.Offset)
            .ThenBy(static candidate => candidate.Endian, StringComparer.Ordinal)
            .Take(32)
            .ToArray();
    }

    private static PcapSourceAckCandidate BuildAckCandidate(
        IReadOnlyList<PcapActiveFlowDatagram> packets,
        PcapActiveFlowDirection direction,
        int offset,
        string endian)
    {
        ushort? latestClient = null;
        ushort? latestServer = null;
        var compared = 0;
        var exact = 0;
        var withinWindow = 0;
        var nonZero = 0;
        var distinctValues = new HashSet<int>();
        var sampleValues = new List<int>();
        var sampleOpposite = new List<int>();

        foreach (var packet in packets)
        {
            if (!Ps3SourceTransportPacket.TryDecode(packet.Payload, out var decoded))
            {
                continue;
            }

            var opposite = packet.Direction == PcapActiveFlowDirection.ClientToServer ? latestServer : latestClient;
            if (packet.Direction == direction && opposite is not null && packet.Payload.Length >= offset + 2)
            {
                var value = ReadUInt16(packet.Payload, offset, endian);
                compared++;
                if (value != 0)
                {
                    nonZero++;
                }

                distinctValues.Add(value);
                if (value == opposite.Value)
                {
                    exact++;
                }

                if (Ps3SourceTransportPacket.SequenceDelta((ushort)value, opposite.Value) <= AckWindow)
                {
                    withinWindow++;
                }

                if (sampleValues.Count < 12)
                {
                    sampleValues.Add(value);
                    sampleOpposite.Add(opposite.Value);
                }
            }

            if (packet.Direction == PcapActiveFlowDirection.ClientToServer)
            {
                latestClient = decoded.CandidateSequence;
            }
            else
            {
                latestServer = decoded.CandidateSequence;
            }
        }

        return new PcapSourceAckCandidate(
            direction.ToString(),
            offset,
            endian,
            compared,
            exact,
            withinWindow,
            nonZero,
            distinctValues.Count,
            sampleValues.ToArray(),
            sampleOpposite.ToArray());
    }

    private static int ReadUInt16(byte[] payload, int offset, string endian)
    {
        return endian == "le"
            ? payload[offset] | (payload[offset + 1] << 8)
            : (payload[offset] << 8) | payload[offset + 1];
    }

    private static PcapSourceTransportSample[] BuildSamples(IReadOnlyList<PcapActiveFlowDatagram> packets)
    {
        ushort? latestClient = null;
        ushort? latestServer = null;
        var samples = new List<PcapSourceTransportSample>();
        foreach (var packet in packets)
        {
            if (!Ps3SourceTransportPacket.TryDecode(packet.Payload, out var decoded))
            {
                continue;
            }

            if (samples.Count < 32)
            {
                var previousOpposite = packet.Direction == PcapActiveFlowDirection.ClientToServer ? latestServer : latestClient;
                samples.Add(new PcapSourceTransportSample(
                    packet.PacketIndex,
                    packet.TimestampMicroseconds,
                    packet.Direction.ToString(),
                    packet.Payload.Length,
                    decoded.CandidateSequence,
                    previousOpposite,
                    decoded.Body.Length,
                    packet.HexPrefix,
                    packet.AsciiPreview));
            }

            if (packet.Direction == PcapActiveFlowDirection.ClientToServer)
            {
                latestClient = decoded.CandidateSequence;
            }
            else
            {
                latestServer = decoded.CandidateSequence;
            }
        }

        return samples.ToArray();
    }
}

public sealed record PcapSourceTransportSemanticsReport(
    PcapSourceTransportSemanticsSummary Summary,
    PcapSourceTransportSemanticsFile[] Files);

public sealed record PcapSourceTransportSemanticsSummary(
    int FileCount,
    int ActiveSourceFlowCount,
    int SourcePacketCount,
    int ParsedTransportPacketCount,
    int FilesWithMostlyMonotonicClientSequence,
    int FilesWithMostlyMonotonicServerSequence,
    int MaxClientSequenceDelta,
    int MaxServerSequenceDelta,
    int MaxExactLatestOppositeSequenceAckMatches,
    int MaxWithinWindowLatestOppositeSequenceAckMatches);

public sealed record PcapSourceTransportSemanticsFile(
    string File,
    bool HasActiveSourceFlow,
    string ClientEndpoint,
    string ServerEndpoint,
    int ServerPort,
    long FirstSourceClientPacketIndex,
    int SourcePacketCount,
    int ParsedTransportPacketCount,
    int ClientToServerPacketCount,
    int ServerToClientPacketCount,
    PcapSourceSequenceStats ClientSequence,
    PcapSourceSequenceStats ServerSequence,
    PcapSourceAckCandidate[] AckCandidates,
    PcapSourceTransportSample[] Samples);

public sealed record PcapSourceSequenceStats(
    string Direction,
    int PacketCount,
    int DistinctCount,
    int FirstValue,
    int LastValue,
    int MinValue,
    int MaxValue,
    int IncreaseCount,
    int SameCount,
    int DecreaseCount,
    int WrapCount,
    double AverageDelta,
    int MaxDelta,
    int[] SampleValues);

public sealed record PcapSourceAckCandidate(
    string Direction,
    int Offset,
    string Endian,
    int ComparedPacketCount,
    int ExactLatestOppositeSequenceMatches,
    int WithinWindowLatestOppositeSequenceMatches,
    int NonZeroCount,
    int DistinctCount,
    int[] SampleValues,
    int[] SampleLatestOppositeSequences);

public sealed record PcapSourceTransportSample(
    long PacketIndex,
    long TimestampMicroseconds,
    string Direction,
    int Length,
    int CandidateSequence,
    int? PreviousOppositeSequence,
    int CandidateBodyLength,
    string HexPrefix,
    string AsciiPreview);
