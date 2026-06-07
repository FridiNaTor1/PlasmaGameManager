using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class PcapSourcePacketShapeAnalyzer
{
    private readonly PcapActiveFlowReplayExtractor _extractor = new();

    public async Task<PcapSourcePacketShapeReport> AnalyzeDirectoryAsync(string inputDirectory, string outputPath)
    {
        var report = AnalyzeDirectory(inputDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
        return report;
    }

    public PcapSourcePacketShapeReport AnalyzeDirectory(string inputDirectory)
    {
        var files = Directory.EnumerateFiles(inputDirectory, "*.*", SearchOption.AllDirectories)
            .Where(static p => p.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            .OrderBy(static p => p, StringComparer.Ordinal)
            .ToArray();
        var fileReports = files.Select(file => AnalyzeFile(inputDirectory, file)).ToArray();
        return new PcapSourcePacketShapeReport(BuildSummary(fileReports), fileReports);
    }

    private PcapSourcePacketShapeFile AnalyzeFile(string inputDirectory, string file)
    {
        var relativePath = Path.GetRelativePath(inputDirectory, file);
        var replay = _extractor.Extract(file);
        if (replay is null)
        {
            return new PcapSourcePacketShapeFile(
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
                [],
                [],
                [],
                [],
                [],
                []);
        }

        var packets = replay.SourcePackets
            .Where(static packet => Ps3SourceTransportPacket.TryDecode(packet.Payload, out _))
            .Select(packet =>
            {
                Ps3SourceTransportPacket.TryDecode(packet.Payload, out var decoded);
                return new PacketWithBody(packet, decoded);
            })
            .ToArray();

        return new PcapSourcePacketShapeFile(
            relativePath,
            true,
            replay.ClientEndpoint,
            replay.ServerEndpoint,
            packets.Length,
            packets.Count(static packet => packet.Packet.Direction == PcapActiveFlowDirection.ClientToServer),
            packets.Count(static packet => packet.Packet.Direction == PcapActiveFlowDirection.ServerToClient),
            packets.Count(static packet => PacketShape(packet) == "short-control"),
            packets.Count(static packet => PacketShape(packet) == "medium-binary"),
            packets.Count(static packet => PacketShape(packet) == "large-binary"),
            packets.Count(static packet => PacketShape(packet) == "near-mtu-fragment"),
            packets.Count(static packet => PacketShape(packet) == "high-entropy-binary"),
            packets.Select(static packet => BodyPrefix(packet.Decoded.Body, 2)).Where(static prefix => prefix.Length > 0).Distinct(StringComparer.Ordinal).Count(),
            TopCounts(packets, static packet => PacketShape(packet)),
            TopCounts(packets, static packet => packet.Decoded.ClassifyNativeFrame().Kind.ToString()),
            TopCounts(packets, static packet => packet.Decoded.Body.Length.ToString()),
            TopCounts(packets, static packet => BodyPrefix(packet.Decoded.Body, 2)),
            BuildDirectionRuns(packets),
            BuildSamples(packets));
    }

    private static PcapSourcePacketShapeSummary BuildSummary(PcapSourcePacketShapeFile[] files)
    {
        var active = files.Where(static file => file.HasActiveSourceFlow).ToArray();
        return new PcapSourcePacketShapeSummary(
            files.Length,
            active.Length,
            active.Sum(static file => file.SourcePacketCount),
            active.Sum(static file => file.ClientToServerPacketCount),
            active.Sum(static file => file.ServerToClientPacketCount),
            active.Sum(static file => file.ShortControlPacketCount),
            active.Sum(static file => file.MediumBinaryPacketCount),
            active.Sum(static file => file.LargeBinaryPacketCount),
            active.Sum(static file => file.NearMtuFragmentPacketCount),
            active.Sum(static file => file.HighEntropyBinaryPacketCount),
            active.Length == 0 ? 0 : active.Max(static file => file.DistinctBodyPrefixCount),
            active.Length == 0 ? 0 : active.Max(static file => file.DirectionRuns.Length == 0 ? 0 : file.DirectionRuns.Max(static run => run.PacketCount)));
    }

    private static PcapSourcePacketShapeCount[] TopCounts(
        IEnumerable<PacketWithBody> packets,
        Func<PacketWithBody, string> selector)
    {
        return packets
            .Select(selector)
            .Where(static value => value.Length > 0)
            .GroupBy(static value => value, StringComparer.Ordinal)
            .OrderByDescending(static group => group.Count())
            .ThenBy(static group => group.Key, StringComparer.Ordinal)
            .Take(24)
            .Select(static group => new PcapSourcePacketShapeCount(group.Key, group.Count()))
            .ToArray();
    }

    private static PcapSourcePacketShapeRun[] BuildDirectionRuns(PacketWithBody[] packets)
    {
        if (packets.Length == 0)
        {
            return [];
        }

        var runs = new List<PcapSourcePacketShapeRun>();
        var start = 0;
        for (var i = 1; i <= packets.Length; i++)
        {
            if (i < packets.Length && packets[i].Packet.Direction == packets[start].Packet.Direction)
            {
                continue;
            }

            var runPackets = packets[start..i];
            runs.Add(new PcapSourcePacketShapeRun(
                runPackets[0].Packet.Direction.ToString(),
                runPackets.Length,
                runPackets[0].Packet.PacketIndex,
                runPackets[^1].Packet.PacketIndex,
                runPackets[0].Decoded.CandidateSequence,
                runPackets[^1].Decoded.CandidateSequence,
                Math.Round((runPackets[^1].Packet.TimestampMicroseconds - runPackets[0].Packet.TimestampMicroseconds) / 1000.0, 3),
                runPackets.Min(static packet => packet.Decoded.Body.Length),
                runPackets.Max(static packet => packet.Decoded.Body.Length),
                TopCounts(runPackets, static packet => PacketShape(packet)).Take(8).ToArray()));
            start = i;
        }

        return runs
            .OrderByDescending(static run => run.PacketCount)
            .ThenBy(static run => run.FirstPacketIndex)
            .Take(32)
            .ToArray();
    }

    private static PcapSourcePacketShapeSample[] BuildSamples(PacketWithBody[] packets)
    {
        var previousClient = new Dictionary<PcapActiveFlowDirection, ushort>();
        return packets
            .Take(96)
            .Select(packet =>
            {
                var previous = previousClient.GetValueOrDefault(packet.Packet.Direction);
                var hasPrevious = previousClient.ContainsKey(packet.Packet.Direction);
                previousClient[packet.Packet.Direction] = packet.Decoded.CandidateSequence;
                return new PcapSourcePacketShapeSample(
                    packet.Packet.PacketIndex,
                    packet.Packet.TimestampMicroseconds,
                    packet.Packet.Direction.ToString(),
                    packet.Decoded.CandidateSequence,
                    hasPrevious ? Ps3SourceTransportPacket.SequenceDelta(previous, packet.Decoded.CandidateSequence) : null,
                    packet.Packet.Payload.Length,
                    packet.Decoded.Body.Length,
                    PacketShape(packet),
                    packet.Decoded.ClassifyNativeFrame().Kind.ToString(),
                    Math.Round(Entropy(packet.Decoded.Body), 3),
                    BodyPrefix(packet.Decoded.Body, 16),
                    AsciiPreview(packet.Decoded.Body, 48));
            })
            .ToArray();
    }

    private static string PacketShape(PacketWithBody packet)
    {
        var body = packet.Decoded.Body;
        if (body.Length < 32)
        {
            return "short-control";
        }

        if (packet.Packet.Payload.Length >= 1000 || body.Length >= 998)
        {
            return "near-mtu-fragment";
        }

        if (Entropy(body) >= 7.0)
        {
            return "high-entropy-binary";
        }

        if (body.Length >= 256)
        {
            return "large-binary";
        }

        return "medium-binary";
    }

    private static string BodyPrefix(byte[] body, int bytes)
    {
        return body.Length == 0
            ? ""
            : Convert.ToHexString(body.AsSpan(0, Math.Min(bytes, body.Length))).ToLowerInvariant();
    }

    private static string AsciiPreview(byte[] body, int bytes)
    {
        var count = Math.Min(bytes, body.Length);
        return new string(body.AsSpan(0, count)
            .ToArray()
            .Select(static b => b is >= 32 and <= 126 ? (char)b : '.')
            .ToArray());
    }

    private static double Entropy(byte[] body)
    {
        if (body.Length == 0)
        {
            return 0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (var b in body)
        {
            counts[b]++;
        }

        var entropy = 0.0;
        foreach (var count in counts)
        {
            if (count == 0)
            {
                continue;
            }

            var p = count / (double)body.Length;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private sealed record PacketWithBody(
        PcapActiveFlowDatagram Packet,
        Ps3SourceTransportPacket Decoded);
}

public sealed record PcapSourcePacketShapeReport(
    PcapSourcePacketShapeSummary Summary,
    PcapSourcePacketShapeFile[] Files);

public sealed record PcapSourcePacketShapeSummary(
    int FileCount,
    int ActiveSourceFlowCount,
    int SourcePacketCount,
    int ClientToServerPacketCount,
    int ServerToClientPacketCount,
    int ShortControlPacketCount,
    int MediumBinaryPacketCount,
    int LargeBinaryPacketCount,
    int NearMtuFragmentPacketCount,
    int HighEntropyBinaryPacketCount,
    int MaxDistinctBodyPrefixCount,
    int LongestDirectionRun);

public sealed record PcapSourcePacketShapeFile(
    string File,
    bool HasActiveSourceFlow,
    string ClientEndpoint,
    string ServerEndpoint,
    int SourcePacketCount,
    int ClientToServerPacketCount,
    int ServerToClientPacketCount,
    int ShortControlPacketCount,
    int MediumBinaryPacketCount,
    int LargeBinaryPacketCount,
    int NearMtuFragmentPacketCount,
    int HighEntropyBinaryPacketCount,
    int DistinctBodyPrefixCount,
    PcapSourcePacketShapeCount[] TopShapeCounts,
    PcapSourcePacketShapeCount[] TopNativeFrameKindCounts,
    PcapSourcePacketShapeCount[] TopBodyLengthCounts,
    PcapSourcePacketShapeCount[] TopBodyPrefixCounts,
    PcapSourcePacketShapeRun[] DirectionRuns,
    PcapSourcePacketShapeSample[] Samples);

public sealed record PcapSourcePacketShapeCount(
    string Value,
    int Count);

public sealed record PcapSourcePacketShapeRun(
    string Direction,
    int PacketCount,
    long FirstPacketIndex,
    long LastPacketIndex,
    int FirstSequence,
    int LastSequence,
    double DurationMilliseconds,
    int MinBodyLength,
    int MaxBodyLength,
    PcapSourcePacketShapeCount[] ShapeCounts);

public sealed record PcapSourcePacketShapeSample(
    long PacketIndex,
    long TimestampMicroseconds,
    string Direction,
    int Sequence,
    int? SequenceDeltaFromPreviousSameDirection,
    int PayloadLength,
    int BodyLength,
    string Shape,
    string NativeFrameKind,
    double BodyEntropy,
    string BodyHexPrefix,
    string BodyAsciiPreview);
