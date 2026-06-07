using System.Text;
using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class PcapSourceTranslationReadinessAnalyzer
{
    private readonly PcapActiveFlowReplayExtractor _extractor = new();

    public async Task<PcapSourceTranslationReadinessReport> AnalyzeDirectoryAsync(string inputDirectory, string outputPath)
    {
        var report = AnalyzeDirectory(inputDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
        return report;
    }

    public PcapSourceTranslationReadinessReport AnalyzeDirectory(string inputDirectory)
    {
        var files = Directory.EnumerateFiles(inputDirectory, "*.*", SearchOption.AllDirectories)
            .Where(static p => p.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            .OrderBy(static p => p, StringComparer.Ordinal)
            .ToArray();
        var fileReports = files.Select(file => AnalyzeFile(inputDirectory, file)).ToArray();
        return new PcapSourceTranslationReadinessReport(BuildSummary(fileReports), fileReports);
    }

    private PcapSourceTranslationReadinessFile AnalyzeFile(string inputDirectory, string file)
    {
        var relativePath = Path.GetRelativePath(inputDirectory, file);
        var replay = _extractor.Extract(file);
        if (replay is null)
        {
            return new PcapSourceTranslationReadinessFile(
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
                0,
                "no-active-source-flow",
                "No active Source/gameplay flow was found.",
                [],
                [],
                [],
                []);
        }

        var packets = replay.SourcePackets
            .Where(static packet => Ps3SourceTransportPacket.TryDecode(packet.Payload, out _))
            .ToArray();
        var bodies = packets
            .Select(packet =>
            {
                Ps3SourceTransportPacket.TryDecode(packet.Payload, out var decoded);
                return new BodyPacket(packet, decoded);
            })
            .ToArray();
        var classicConnectionless = packets.Count(static packet => IsClassicSourceConnectionless(packet.Payload));
        var sourceMarkers = bodies.Count(static packet => ContainsPcSourceMarker(packet.Decoded.Body));
        var printableBodies = bodies.Count(static packet => PrintableRatio(packet.Decoded.Body) >= 0.85 && packet.Decoded.Body.Length >= 8);
        var highEntropyBodies = bodies.Count(static packet => packet.Decoded.Body.Length >= 32 && Entropy(packet.Decoded.Body) >= 7.0);
        var shortBinaryBodies = bodies.Count(static packet => packet.Decoded.Body.Length < 32);

        return new PcapSourceTranslationReadinessFile(
            relativePath,
            true,
            replay.ClientEndpoint,
            replay.ServerEndpoint,
            packets.Length,
            packets.Count(static packet => packet.Direction == PcapActiveFlowDirection.ClientToServer),
            packets.Count(static packet => packet.Direction == PcapActiveFlowDirection.ServerToClient),
            packets.Length,
            classicConnectionless,
            sourceMarkers,
            printableBodies,
            highEntropyBodies,
            shortBinaryBodies,
            bodies.Length == 0 ? 0 : Math.Round(bodies.Average(static packet => Entropy(packet.Decoded.Body)), 3),
            ClassifyReadiness(packets.Length, classicConnectionless, sourceMarkers, printableBodies),
            BuildConclusion(packets.Length, classicConnectionless, sourceMarkers, printableBodies),
            TopBodyPrefixes(bodies, PcapActiveFlowDirection.ClientToServer, bytes: 2),
            TopBodyPrefixes(bodies, PcapActiveFlowDirection.ServerToClient, bytes: 2),
            TopBodyLengths(bodies),
            BuildSamples(bodies));
    }

    private static PcapSourceTranslationReadinessSummary BuildSummary(PcapSourceTranslationReadinessFile[] files)
    {
        var active = files.Where(static file => file.HasActiveSourceFlow).ToArray();
        return new PcapSourceTranslationReadinessSummary(
            files.Length,
            active.Length,
            active.Sum(static file => file.SourcePacketCount),
            active.Sum(static file => file.ClassicConnectionlessPacketCount),
            active.Sum(static file => file.BodyContainsPcSourceMarkerCount),
            active.Sum(static file => file.MostlyPrintableBodyCount),
            active.Sum(static file => file.HighEntropyBodyCount),
            active.Count(static file => file.Readiness == "needs-ps3-source-transport-translator"),
            active.Count(static file => file.Readiness == "pc-source-connectionless-compatible"),
            active
                .GroupBy(static file => file.Readiness, StringComparer.Ordinal)
                .OrderBy(static group => group.Key, StringComparer.Ordinal)
                .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.Ordinal));
    }

    private static string ClassifyReadiness(
        int packetCount,
        int classicConnectionless,
        int sourceMarkers,
        int printableBodies)
    {
        if (packetCount == 0)
        {
            return "no-active-source-flow";
        }

        if (classicConnectionless == packetCount || sourceMarkers > packetCount / 2)
        {
            return "pc-source-connectionless-compatible";
        }

        if (classicConnectionless > 0 || sourceMarkers > 0 || printableBodies > packetCount / 2)
        {
            return "mixed-review-required";
        }

        return "needs-ps3-source-transport-translator";
    }

    private static string BuildConclusion(
        int packetCount,
        int classicConnectionless,
        int sourceMarkers,
        int printableBodies)
    {
        return ClassifyReadiness(packetCount, classicConnectionless, sourceMarkers, printableBodies) switch
        {
            "pc-source-connectionless-compatible" =>
                "Active packets already look like classic PC Source connectionless traffic.",
            "mixed-review-required" =>
                "Some active bodies contain printable or PC Source-like markers, but the flow is not consistently PC Source connectionless.",
            "needs-ps3-source-transport-translator" =>
                "Active packets use the PS3 Source/gameplay transport envelope and do not expose PC Source connectionless markers after the recovered sequence field. A semantic translator or PS3-native backend is required.",
            _ =>
                "No active Source/gameplay flow was available."
        };
    }

    private static PcapSourceTranslationCount[] TopBodyPrefixes(BodyPacket[] packets, PcapActiveFlowDirection direction, int bytes)
    {
        return packets
            .Where(packet => packet.Packet.Direction == direction && packet.Decoded.Body.Length >= bytes)
            .GroupBy(packet => Convert.ToHexString(packet.Decoded.Body.AsSpan(0, bytes)).ToLowerInvariant(), StringComparer.Ordinal)
            .OrderByDescending(static group => group.Count())
            .ThenBy(static group => group.Key, StringComparer.Ordinal)
            .Take(16)
            .Select(static group => new PcapSourceTranslationCount(group.Key, group.Count()))
            .ToArray();
    }

    private static PcapSourceTranslationCount[] TopBodyLengths(BodyPacket[] packets)
    {
        return packets
            .GroupBy(static packet => packet.Decoded.Body.Length)
            .OrderByDescending(static group => group.Count())
            .ThenBy(static group => group.Key)
            .Take(16)
            .Select(static group => new PcapSourceTranslationCount(group.Key.ToString(), group.Count()))
            .ToArray();
    }

    private static PcapSourceTranslationSample[] BuildSamples(BodyPacket[] packets)
    {
        return packets
            .Take(32)
            .Select(static packet => new PcapSourceTranslationSample(
                packet.Packet.PacketIndex,
                packet.Packet.Direction.ToString(),
                packet.Decoded.CandidateSequence,
                packet.Packet.Payload.Length,
                packet.Decoded.Body.Length,
                BodyShape(packet.Decoded.Body),
                Math.Round(Entropy(packet.Decoded.Body), 3),
                Convert.ToHexString(packet.Decoded.Body.AsSpan(0, Math.Min(8, packet.Decoded.Body.Length))).ToLowerInvariant(),
                AsciiPreview(packet.Decoded.Body, 48)))
            .ToArray();
    }

    private static string BodyShape(byte[] body)
    {
        if (IsClassicSourceConnectionless(body))
        {
            return "pc-source-connectionless-body";
        }

        if (ContainsPcSourceMarker(body))
        {
            return "pc-source-marker-body";
        }

        if (body.Length < 32)
        {
            return "short-binary-control";
        }

        if (PrintableRatio(body) >= 0.85)
        {
            return "mostly-printable";
        }

        if (Entropy(body) >= 7.0)
        {
            return "high-entropy-binary";
        }

        return "binary";
    }

    private static bool ContainsPcSourceMarker(byte[] body)
    {
        var text = Encoding.ASCII.GetString(body);
        return text.Contains("Source Engine Query", StringComparison.OrdinalIgnoreCase)
            || text.Contains("MOTD", StringComparison.OrdinalIgnoreCase)
            || text.Contains("connect", StringComparison.OrdinalIgnoreCase)
            || text.Contains("challenge", StringComparison.OrdinalIgnoreCase)
            || text.Contains("status", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsClassicSourceConnectionless(ReadOnlySpan<byte> payload)
    {
        return payload.Length >= 4
            && payload[0] == 0xff
            && payload[1] == 0xff
            && payload[2] == 0xff
            && payload[3] == 0xff;
    }

    private static string AsciiPreview(byte[] body, int bytes)
    {
        var count = Math.Min(bytes, body.Length);
        return new string(body.AsSpan(0, count)
            .ToArray()
            .Select(static b => b is >= 32 and <= 126 ? (char)b : '.')
            .ToArray());
    }

    private static double PrintableRatio(byte[] body)
    {
        if (body.Length == 0)
        {
            return 0;
        }

        var printable = body.Count(static b => b is >= 32 and <= 126 or 0x09 or 0x0a or 0x0d);
        return printable / (double)body.Length;
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

    private sealed record BodyPacket(
        PcapActiveFlowDatagram Packet,
        Ps3SourceTransportPacket Decoded);
}

public sealed record PcapSourceTranslationReadinessReport(
    PcapSourceTranslationReadinessSummary Summary,
    PcapSourceTranslationReadinessFile[] Files);

public sealed record PcapSourceTranslationReadinessSummary(
    int FileCount,
    int ActiveSourceFlowCount,
    int SourcePacketCount,
    int ClassicConnectionlessPacketCount,
    int BodyContainsPcSourceMarkerCount,
    int MostlyPrintableBodyCount,
    int HighEntropyBodyCount,
    int NeedsPs3TransportTranslatorFileCount,
    int PcSourceConnectionlessCompatibleFileCount,
    IReadOnlyDictionary<string, int> ReadinessCounts);

public sealed record PcapSourceTranslationReadinessFile(
    string File,
    bool HasActiveSourceFlow,
    string ClientEndpoint,
    string ServerEndpoint,
    int SourcePacketCount,
    int ClientToServerPacketCount,
    int ServerToClientPacketCount,
    int ParsedTransportPacketCount,
    int ClassicConnectionlessPacketCount,
    int BodyContainsPcSourceMarkerCount,
    int MostlyPrintableBodyCount,
    int HighEntropyBodyCount,
    int ShortBinaryBodyCount,
    double AverageBodyEntropy,
    string Readiness,
    string Conclusion,
    PcapSourceTranslationCount[] TopClientBodyPrefixes,
    PcapSourceTranslationCount[] TopServerBodyPrefixes,
    PcapSourceTranslationCount[] TopBodyLengths,
    PcapSourceTranslationSample[] Samples);

public sealed record PcapSourceTranslationCount(
    string Value,
    int Count);

public sealed record PcapSourceTranslationSample(
    long PacketIndex,
    string Direction,
    int Sequence,
    int PayloadLength,
    int BodyLength,
    string BodyShape,
    double BodyEntropy,
    string BodyHexPrefix,
    string BodyAsciiPreview);
