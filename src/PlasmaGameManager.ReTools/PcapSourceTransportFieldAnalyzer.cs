using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class PcapSourceTransportFieldAnalyzer
{
    private readonly PcapActiveFlowReplayExtractor _extractor = new();

    public async Task<PcapSourceTransportFieldReport> AnalyzeDirectoryAsync(string inputDirectory, string outputPath)
    {
        var report = AnalyzeDirectory(inputDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, JsonOptions));
        return report;
    }

    public PcapSourceTransportFieldReport AnalyzeDirectory(string inputDirectory)
    {
        var files = Directory.EnumerateFiles(inputDirectory, "*.*", SearchOption.AllDirectories)
            .Where(static path => path.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            .OrderBy(static path => path, StringComparer.Ordinal)
            .ToArray();
        var reports = files.Select(file => AnalyzeFile(inputDirectory, file)).ToArray();
        return new PcapSourceTransportFieldReport(
            "pcap-source-transport-fields",
            BuildSummary(reports),
            BuildAggregates(reports),
            reports);
    }

    private PcapSourceTransportFieldFile AnalyzeFile(string inputDirectory, string file)
    {
        var relativePath = Path.GetRelativePath(inputDirectory, file);
        var replay = _extractor.Extract(file);
        if (replay is null)
        {
            return new PcapSourceTransportFieldFile(
                relativePath,
                false,
                "",
                "",
                0,
                0,
                0,
                [],
                [],
                []);
        }

        var packets = replay.SourcePackets
            .Where(static packet => Ps3SourceTransportPacket.TryDecode(packet.Payload, out _))
            .Select(packet =>
            {
                Ps3SourceTransportPacket.TryDecode(packet.Payload, out var decoded);
                return new SourcePacket(packet, decoded);
            })
            .ToArray();

        return new PcapSourceTransportFieldFile(
            relativePath,
            true,
            replay.ClientEndpoint,
            replay.ServerEndpoint,
            packets.Length,
            packets.Count(static packet => packet.Packet.Direction == PcapActiveFlowDirection.ClientToServer),
            packets.Count(static packet => packet.Packet.Direction == PcapActiveFlowDirection.ServerToClient),
            BuildFieldCandidates(packets),
            BuildShortControlPrefixes(packets),
            BuildFragmentRuns(packets));
    }

    private static PcapSourceTransportFieldSummary BuildSummary(PcapSourceTransportFieldFile[] files)
    {
        var active = files.Where(static file => file.HasActiveSourceFlow).ToArray();
        var offset0Client = active
            .SelectMany(static file => file.FieldCandidates)
            .Where(static candidate => candidate.Field == "u16-be@0" && candidate.Direction == PcapActiveFlowDirection.ClientToServer.ToString())
            .ToArray();
        var offset0Server = active
            .SelectMany(static file => file.FieldCandidates)
            .Where(static candidate => candidate.Field == "u16-be@0" && candidate.Direction == PcapActiveFlowDirection.ServerToClient.ToString())
            .ToArray();
        var aggregates = BuildAggregates(files);
        return new PcapSourceTransportFieldSummary(
            files.Length,
            active.Length,
            active.Sum(static file => file.SourcePacketCount),
            active.Sum(static file => file.ClientToServerPacketCount),
            active.Sum(static file => file.ServerToClientPacketCount),
            offset0Client.Count(static candidate => candidate.MostlyMonotonic),
            offset0Server.Count(static candidate => candidate.MostlyMonotonic),
            aggregates.FirstOrDefault(static aggregate => aggregate.Direction == PcapActiveFlowDirection.ClientToServer.ToString())?.Field ?? "",
            aggregates.FirstOrDefault(static aggregate => aggregate.Direction == PcapActiveFlowDirection.ServerToClient.ToString())?.Field ?? "",
            active.Sum(static file => file.ShortControlPrefixes.Sum(static prefix => prefix.Count)),
            active.Sum(static file => file.FragmentRuns.Length),
            active.Length == 0 ? 0 : active.Max(static file => file.FragmentRuns.Length == 0 ? 0 : file.FragmentRuns.Max(static run => run.PacketCount)),
            offset0Client.Length > 0
                && offset0Server.Length > 0
                && offset0Client.Count(static candidate => candidate.MostlyMonotonic) >= active.Length - 1
                && offset0Server.Count(static candidate => candidate.MostlyMonotonic) >= active.Length - 1
                ? "offset-0-u16-be-sequence-established"
                : "sequence-field-not-established");
    }

    private static PcapSourceTransportFieldAggregate[] BuildAggregates(PcapSourceTransportFieldFile[] files)
    {
        return files
            .Where(static file => file.HasActiveSourceFlow)
            .SelectMany(static file => file.FieldCandidates)
            .GroupBy(static candidate => new { candidate.Field, candidate.Direction })
            .Select(static group =>
            {
                var candidates = group.ToArray();
                var totalPacketCount = candidates.Sum(static candidate => candidate.PacketCount);
                var averageMonotonic = Math.Round(candidates.Average(static candidate => candidate.MonotonicStepRatio), 4);
                var averageDistinct = Math.Round(candidates.Average(static candidate => candidate.DistinctRatio), 4);
                var score = Math.Round((averageMonotonic * 0.7) + (averageDistinct * 0.3), 4);
                return new PcapSourceTransportFieldAggregate(
                    group.Key.Field,
                    group.Key.Direction,
                    candidates.Length,
                    totalPacketCount,
                    candidates.Count(static candidate => candidate.MostlyMonotonic),
                    candidates.Sum(static candidate => candidate.DecreaseCount),
                    candidates.Max(static candidate => candidate.MaxDelta),
                    averageMonotonic,
                    averageDistinct,
                    score);
            })
            .OrderByDescending(static aggregate => aggregate.MostlyMonotonicFileCount)
            .ThenByDescending(static aggregate => aggregate.Score)
            .ThenByDescending(static aggregate => aggregate.AverageDistinctRatio)
            .ThenBy(static aggregate => aggregate.Field, StringComparer.Ordinal)
            .Take(48)
            .ToArray();
    }

    private static PcapSourceTransportFieldCandidate[] BuildFieldCandidates(SourcePacket[] packets)
    {
        var result = new List<PcapSourceTransportFieldCandidate>();
        foreach (var direction in Enum.GetValues<PcapActiveFlowDirection>())
        {
            var directionPackets = packets.Where(packet => packet.Packet.Direction == direction).ToArray();
            foreach (var offset in Enumerable.Range(0, 12))
            {
                result.Add(BuildU16Candidate(directionPackets, direction, offset, "be"));
                result.Add(BuildU16Candidate(directionPackets, direction, offset, "le"));
            }
        }

        return result
            .OrderByDescending(static candidate => candidate.MostlyMonotonic)
            .ThenByDescending(static candidate => candidate.MonotonicStepRatio)
            .ThenByDescending(static candidate => candidate.DistinctRatio)
            .ThenBy(static candidate => candidate.Offset)
            .ThenBy(static candidate => candidate.Endian, StringComparer.Ordinal)
            .ToArray();
    }

    private static PcapSourceTransportFieldCandidate BuildU16Candidate(
        SourcePacket[] packets,
        PcapActiveFlowDirection direction,
        int offset,
        string endian)
    {
        var values = packets
            .Where(packet => packet.Packet.Payload.Length >= offset + 2)
            .Select(packet => ReadUInt16(packet.Packet.Payload, offset, endian))
            .ToArray();
        if (values.Length == 0)
        {
            return new PcapSourceTransportFieldCandidate(
                $"u16-{endian}@{offset}",
                offset,
                2,
                endian,
                direction.ToString(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                []);
        }

        var increase = 0;
        var same = 0;
        var decrease = 0;
        var wrap = 0;
        var maxDelta = 0;
        for (var i = 1; i < values.Length; i++)
        {
            var delta = Ps3SourceTransportPacket.SequenceDelta((ushort)values[i - 1], (ushort)values[i]);
            maxDelta = Math.Max(maxDelta, delta);
            if (values[i] > values[i - 1])
            {
                increase++;
            }
            else if (values[i] == values[i - 1])
            {
                same++;
            }
            else
            {
                decrease++;
                if (delta > 0)
                {
                    wrap++;
                }
            }
        }

        var comparisons = Math.Max(0, values.Length - 1);
        var monotonicRatio = comparisons == 0 ? 1.0 : (increase + same) / (double)comparisons;
        var distinctRatio = values.Distinct().Count() / (double)values.Length;
        var mostlyMonotonic = values.Length >= 4
            && monotonicRatio >= 0.95
            && distinctRatio >= 0.5
            && decrease <= Math.Max(2, comparisons / 20);
        return new PcapSourceTransportFieldCandidate(
            $"u16-{endian}@{offset}",
            offset,
            2,
            endian,
            direction.ToString(),
            values.Length,
            values.Distinct().Count(),
            values[0],
            values[^1],
            increase,
            same,
            decrease,
            wrap,
            Math.Round(monotonicRatio, 4),
            Math.Round(distinctRatio, 4),
            maxDelta,
            mostlyMonotonic,
            values.Take(16).ToArray());
    }

    private static PcapSourceTransportShortControlPrefix[] BuildShortControlPrefixes(SourcePacket[] packets)
    {
        return packets
            .Where(static packet => packet.Decoded.Body.Length < 32)
            .GroupBy(static packet => new
            {
                Direction = packet.Packet.Direction.ToString(),
                BodyLength = packet.Decoded.Body.Length,
                Prefix = Prefix(packet.Decoded.Body, 4)
            })
            .OrderByDescending(static group => group.Count())
            .ThenBy(static group => group.Key.Direction, StringComparer.Ordinal)
            .ThenBy(static group => group.Key.BodyLength)
            .ThenBy(static group => group.Key.Prefix, StringComparer.Ordinal)
            .Take(32)
            .Select(static group => new PcapSourceTransportShortControlPrefix(
                group.Key.Direction,
                group.Key.BodyLength,
                group.Key.Prefix,
                group.Count(),
                group.Select(static packet => packet.Decoded.CandidateSequence).Take(12).Select(static value => (int)value).ToArray()))
            .ToArray();
    }

    private static PcapSourceTransportFragmentRun[] BuildFragmentRuns(SourcePacket[] packets)
    {
        var runs = new List<PcapSourceTransportFragmentRun>();
        var index = 0;
        while (index < packets.Length)
        {
            if (!IsNearMtu(packets[index]))
            {
                index++;
                continue;
            }

            var start = index;
            var direction = packets[index].Packet.Direction;
            while (index < packets.Length
                && packets[index].Packet.Direction == direction
                && IsNearMtu(packets[index]))
            {
                index++;
            }

            var runPackets = packets[start..index];
            runs.Add(new PcapSourceTransportFragmentRun(
                direction.ToString(),
                runPackets.Length,
                runPackets[0].Packet.PacketIndex,
                runPackets[^1].Packet.PacketIndex,
                runPackets[0].Decoded.CandidateSequence,
                runPackets[^1].Decoded.CandidateSequence,
                runPackets.Min(static packet => packet.Packet.Payload.Length),
                runPackets.Max(static packet => packet.Packet.Payload.Length),
                Math.Round((runPackets[^1].Packet.TimestampMicroseconds - runPackets[0].Packet.TimestampMicroseconds) / 1000.0, 3)));
        }

        return runs
            .OrderByDescending(static run => run.PacketCount)
            .ThenBy(static run => run.FirstPacketIndex)
            .Take(32)
            .ToArray();
    }

    private static bool IsNearMtu(SourcePacket packet)
    {
        return packet.Packet.Payload.Length >= 1000 || packet.Decoded.Body.Length >= 998;
    }

    private static int ReadUInt16(byte[] payload, int offset, string endian)
    {
        return endian == "le"
            ? payload[offset] | (payload[offset + 1] << 8)
            : (payload[offset] << 8) | payload[offset + 1];
    }

    private static string Prefix(byte[] payload, int length)
    {
        return payload.Length == 0
            ? ""
            : Convert.ToHexString(payload.AsSpan(0, Math.Min(length, payload.Length))).ToLowerInvariant();
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private sealed record SourcePacket(
        PcapActiveFlowDatagram Packet,
        Ps3SourceTransportPacket Decoded);
}

public sealed record PcapSourceTransportFieldReport(
    string Status,
    PcapSourceTransportFieldSummary Summary,
    PcapSourceTransportFieldAggregate[] TopFieldCandidates,
    PcapSourceTransportFieldFile[] Files);

public sealed record PcapSourceTransportFieldSummary(
    int FileCount,
    int ActiveSourceFlowCount,
    int SourcePacketCount,
    int ClientToServerPacketCount,
    int ServerToClientPacketCount,
    int Offset0BigEndianClientMostlyMonotonicFileCount,
    int Offset0BigEndianServerMostlyMonotonicFileCount,
    string TopClientField,
    string TopServerField,
    int ShortControlPacketCount,
    int NearMtuFragmentRunCount,
    int LongestNearMtuFragmentRun,
    string EstablishedFieldConclusion);

public sealed record PcapSourceTransportFieldAggregate(
    string Field,
    string Direction,
    int ActiveFileCount,
    int PacketCount,
    int MostlyMonotonicFileCount,
    int TotalDecreaseCount,
    int MaxDelta,
    double AverageMonotonicStepRatio,
    double AverageDistinctRatio,
    double Score);

public sealed record PcapSourceTransportFieldFile(
    string File,
    bool HasActiveSourceFlow,
    string ClientEndpoint,
    string ServerEndpoint,
    int SourcePacketCount,
    int ClientToServerPacketCount,
    int ServerToClientPacketCount,
    PcapSourceTransportFieldCandidate[] FieldCandidates,
    PcapSourceTransportShortControlPrefix[] ShortControlPrefixes,
    PcapSourceTransportFragmentRun[] FragmentRuns);

public sealed record PcapSourceTransportFieldCandidate(
    string Field,
    int Offset,
    int Width,
    string Endian,
    string Direction,
    int PacketCount,
    int DistinctCount,
    int FirstValue,
    int LastValue,
    int IncreaseCount,
    int SameCount,
    int DecreaseCount,
    int WrapCount,
    double MonotonicStepRatio,
    double DistinctRatio,
    int MaxDelta,
    bool MostlyMonotonic,
    int[] SampleValues);

public sealed record PcapSourceTransportShortControlPrefix(
    string Direction,
    int BodyLength,
    string BodyPrefix,
    int Count,
    int[] SampleSequences);

public sealed record PcapSourceTransportFragmentRun(
    string Direction,
    int PacketCount,
    long FirstPacketIndex,
    long LastPacketIndex,
    int FirstSequence,
    int LastSequence,
    int MinPayloadLength,
    int MaxPayloadLength,
    double DurationMilliseconds);
