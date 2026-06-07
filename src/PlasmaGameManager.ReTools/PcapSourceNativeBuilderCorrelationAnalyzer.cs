using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class PcapSourceNativeBuilderCorrelationAnalyzer
{
    private const int TransportHeaderBytes = Ps3SourceTransportPacket.HeaderBytes;
    private const int InlineQueuePayloadLimit = 0x800;
    private const int NativeQueuePayloadCeiling = 96000;
    private const int NearMtuPayloadLength = 1000;
    private readonly PcapActiveFlowReplayExtractor _extractor = new();

    public async Task<PcapSourceNativeBuilderCorrelationReport> AnalyzeDirectoryAsync(
        string inputDirectory,
        string outputPath,
        string sourceNetworkAnchorMapPath)
    {
        var report = AnalyzeDirectory(inputDirectory, sourceNetworkAnchorMapPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
        return report;
    }

    public PcapSourceNativeBuilderCorrelationReport AnalyzeDirectory(
        string inputDirectory,
        string sourceNetworkAnchorMapPath)
    {
        var files = Directory.EnumerateFiles(inputDirectory, "*.*", SearchOption.AllDirectories)
            .Where(static p => p.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            .OrderBy(static p => p, StringComparer.Ordinal)
            .ToArray();
        var fileReports = files.Select(file => AnalyzeFile(inputDirectory, file)).ToArray();
        var nativeEvidence = LoadNativeEvidence(sourceNetworkAnchorMapPath);
        return new PcapSourceNativeBuilderCorrelationReport(
            "pcap-source-native-builder-correlation",
            nativeEvidence,
            BuildSummary(fileReports, nativeEvidence),
            fileReports);
    }

    private PcapSourceNativeBuilderCorrelationFile AnalyzeFile(string inputDirectory, string file)
    {
        var relativePath = Path.GetRelativePath(inputDirectory, file);
        var replay = _extractor.Extract(file);
        if (replay is null)
        {
            return new PcapSourceNativeBuilderCorrelationFile(
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
                false,
                false,
                "no-active-source-flow",
                "No active Source/gameplay flow was found.",
                [],
                []);
        }

        var packets = replay.SourcePackets
            .Where(static packet => Ps3SourceTransportPacket.TryDecode(packet.Payload, out _))
            .Select(packet =>
            {
                Ps3SourceTransportPacket.TryDecode(packet.Payload, out var decoded);
                return new PacketWithTransport(packet, decoded);
            })
            .ToArray();
        var inlineQueue = packets.Count(static packet => packet.Packet.Payload.Length <= InlineQueuePayloadLimit);
        var heapQueue = packets.Count(static packet => packet.Packet.Payload.Length > InlineQueuePayloadLimit
            && packet.Packet.Payload.Length <= NativeQueuePayloadCeiling);
        var exceedsLimit = packets.Count(static packet => packet.Packet.Payload.Length > NativeQueuePayloadCeiling);
        var nearMtu = packets.Count(static packet => packet.Packet.Payload.Length >= NearMtuPayloadLength);
        var shortControls = packets.Count(static packet => packet.Decoded.Body.Length < 32);
        var maxPayloadLength = packets.Length == 0 ? 0 : packets.Max(static packet => packet.Packet.Payload.Length);
        var maxBodyLength = packets.Length == 0 ? 0 : packets.Max(static packet => packet.Decoded.Body.Length);

        return new PcapSourceNativeBuilderCorrelationFile(
            relativePath,
            true,
            replay.ClientEndpoint,
            replay.ServerEndpoint,
            packets.Length,
            packets.Count(static packet => packet.Packet.Direction == PcapActiveFlowDirection.ClientToServer),
            packets.Count(static packet => packet.Packet.Direction == PcapActiveFlowDirection.ServerToClient),
            inlineQueue,
            heapQueue,
            nearMtu,
            shortControls,
            exceedsLimit,
            maxPayloadLength,
            maxBodyLength,
            packets.Length > 0 && packets.Length == inlineQueue + heapQueue,
            exceedsLimit == 0,
            ClassifyFile(packets.Length, exceedsLimit),
            BuildConclusion(packets.Length, inlineQueue, heapQueue, nearMtu, shortControls, exceedsLimit),
            TopCounts(packets, static packet => QueueClass(packet.Packet.Payload.Length)),
            BuildSamples(packets));
    }

    private static PcapSourceNativeBuilderCorrelationSummary BuildSummary(
        PcapSourceNativeBuilderCorrelationFile[] files,
        PcapSourceNativeBuilderEvidence nativeEvidence)
    {
        var active = files.Where(static file => file.HasActiveSourceFlow).ToArray();
        return new PcapSourceNativeBuilderCorrelationSummary(
            files.Length,
            active.Length,
            active.Sum(static file => file.SourcePacketCount),
            active.Sum(static file => file.InlineQueueCompatiblePacketCount),
            active.Sum(static file => file.HeapQueueCompatiblePacketCount),
            active.Sum(static file => file.NearMtuCandidatePacketCount),
            active.Sum(static file => file.ShortConnectedControlCandidateCount),
            active.Sum(static file => file.ExceedsNativeQueueLimitPacketCount),
            active.Length == 0 ? 0 : active.Max(static file => file.MaxPayloadLength),
            active.Count(static file => file.AllPacketsFitNativeQueueLimits),
            active.Count(static file => file.NativeQueueCompatible),
            nativeEvidence.HasNativeSourceSendBuilder && nativeEvidence.HasNativePayloadQueue
                ? "native-builder-evidence-present"
                : "native-builder-evidence-missing-or-incomplete",
            active.Length > 0
                && active.All(static file => file.NativeQueueCompatible)
                && active.All(static file => file.ExceedsNativeQueueLimitPacketCount == 0)
                && nativeEvidence.HasNativeSourceSendBuilder
                && nativeEvidence.HasNativePayloadQueue);
    }

    private static PcapSourceNativeBuilderEvidence LoadNativeEvidence(string sourceNetworkAnchorMapPath)
    {
        if (!File.Exists(sourceNetworkAnchorMapPath))
        {
            return new PcapSourceNativeBuilderEvidence(
                sourceNetworkAnchorMapPath,
                false,
                false,
                false,
                [],
                "source-network-anchor-map-missing");
        }

        using var document = JsonDocument.Parse(File.ReadAllBytes(sourceNetworkAnchorMapPath));
        var root = document.RootElement;
        var summary = root.GetProperty("summary");
        var hasSendBuilder = summary.GetProperty("HasNativeSourceSendBuilder").GetBoolean();
        var hasPayloadQueue = summary.GetProperty("HasNativePayloadQueue").GetBoolean();
        var hasUdpCluster = summary.GetProperty("HasUdpGameplaySocketCluster").GetBoolean();
        var entries = root.GetProperty("functions")
            .EnumerateArray()
            .Where(static function => function.GetProperty("Conclusion").GetString() is
                "native-ps3-source-send-path" or
                "native-ps3-source-payload-queue" or
                "primary-post-handoff-udp-anchor")
            .Select(static function => function.GetProperty("Entry").GetString() ?? "")
            .Where(static entry => entry.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();

        return new PcapSourceNativeBuilderEvidence(
            sourceNetworkAnchorMapPath,
            hasSendBuilder,
            hasPayloadQueue,
            hasUdpCluster,
            entries,
            hasSendBuilder && hasPayloadQueue && hasUdpCluster
                ? "source-network-anchor-map-confirms-native-source-send-and-queue"
                : "source-network-anchor-map-incomplete");
    }

    private static string ClassifyFile(int packetCount, int exceedsLimit)
    {
        if (packetCount == 0)
        {
            return "no-active-source-flow";
        }

        return exceedsLimit == 0
            ? "fits-tf2ps3-native-builder-envelope"
            : "exceeds-tf2ps3-native-builder-envelope";
    }

    private static string BuildConclusion(
        int packetCount,
        int inlineQueue,
        int heapQueue,
        int nearMtu,
        int shortControls,
        int exceedsLimit)
    {
        if (packetCount == 0)
        {
            return "No active Source/gameplay flow was available for native builder checks.";
        }

        if (exceedsLimit > 0)
        {
            return "At least one active Source/gameplay packet exceeds the recovered TF.elf queue ceiling.";
        }

        return $"All active Source/gameplay packets fit the recovered TF.elf queue ceiling. {inlineQueue} packets fit the inline <=0x800 path, {heapQueue} require the heap-backed path, {nearMtu} are near-MTU send candidates, and {shortControls} match the connected short-control shape.";
    }

    private static PcapSourceNativeBuilderCorrelationCount[] TopCounts(
        IEnumerable<PacketWithTransport> packets,
        Func<PacketWithTransport, string> selector)
    {
        return packets
            .Select(selector)
            .Where(static value => value.Length > 0)
            .GroupBy(static value => value, StringComparer.Ordinal)
            .OrderByDescending(static group => group.Count())
            .ThenBy(static group => group.Key, StringComparer.Ordinal)
            .Take(16)
            .Select(static group => new PcapSourceNativeBuilderCorrelationCount(group.Key, group.Count()))
            .ToArray();
    }

    private static PcapSourceNativeBuilderCorrelationSample[] BuildSamples(PacketWithTransport[] packets)
    {
        return packets
            .Take(64)
            .Select(static packet => new PcapSourceNativeBuilderCorrelationSample(
                packet.Packet.PacketIndex,
                packet.Packet.Direction.ToString(),
                packet.Decoded.CandidateSequence,
                packet.Packet.Payload.Length,
                packet.Decoded.Body.Length,
                QueueClass(packet.Packet.Payload.Length),
                packet.Packet.Payload.Length >= NearMtuPayloadLength,
                packet.Decoded.Body.Length < 32,
                Convert.ToHexString(packet.Packet.Payload.AsSpan(0, Math.Min(16, packet.Packet.Payload.Length))).ToLowerInvariant()))
            .ToArray();
    }

    private static string QueueClass(int payloadLength)
    {
        if (payloadLength <= InlineQueuePayloadLimit)
        {
            return "inline-queue-compatible";
        }

        if (payloadLength <= NativeQueuePayloadCeiling)
        {
            return "heap-queue-compatible";
        }

        return "exceeds-native-queue-limit";
    }

    private sealed record PacketWithTransport(
        PcapActiveFlowDatagram Packet,
        Ps3SourceTransportPacket Decoded);
}

public sealed record PcapSourceNativeBuilderCorrelationReport(
    string Status,
    PcapSourceNativeBuilderEvidence NativeEvidence,
    PcapSourceNativeBuilderCorrelationSummary Summary,
    PcapSourceNativeBuilderCorrelationFile[] Files);

public sealed record PcapSourceNativeBuilderEvidence(
    string SourceNetworkAnchorMap,
    bool HasNativeSourceSendBuilder,
    bool HasNativePayloadQueue,
    bool HasUdpGameplaySocketCluster,
    string[] NativeFunctionEntries,
    string Assessment);

public sealed record PcapSourceNativeBuilderCorrelationSummary(
    int FileCount,
    int ActiveSourceFlowCount,
    int SourcePacketCount,
    int InlineQueueCompatiblePacketCount,
    int HeapQueueCompatiblePacketCount,
    int NearMtuCandidatePacketCount,
    int ShortConnectedControlCandidateCount,
    int ExceedsNativeQueueLimitPacketCount,
    int MaxPayloadLength,
    int FilesFittingNativeQueueLimits,
    int NativeQueueCompatibleFileCount,
    string NativeEvidenceAssessment,
    bool CorpusFitsNativeBuilderEnvelope);

public sealed record PcapSourceNativeBuilderCorrelationFile(
    string File,
    bool HasActiveSourceFlow,
    string ClientEndpoint,
    string ServerEndpoint,
    int SourcePacketCount,
    int ClientToServerPacketCount,
    int ServerToClientPacketCount,
    int InlineQueueCompatiblePacketCount,
    int HeapQueueCompatiblePacketCount,
    int NearMtuCandidatePacketCount,
    int ShortConnectedControlCandidateCount,
    int ExceedsNativeQueueLimitPacketCount,
    int MaxPayloadLength,
    int MaxBodyLength,
    bool NativeQueueCompatible,
    bool AllPacketsFitNativeQueueLimits,
    string NativeBuilderCompatibility,
    string Conclusion,
    PcapSourceNativeBuilderCorrelationCount[] QueueClassCounts,
    PcapSourceNativeBuilderCorrelationSample[] Samples);

public sealed record PcapSourceNativeBuilderCorrelationCount(
    string Value,
    int Count);

public sealed record PcapSourceNativeBuilderCorrelationSample(
    long PacketIndex,
    string Direction,
    int Sequence,
    int PayloadLength,
    int BodyLength,
    string QueueClass,
    bool IsNearMtuCandidate,
    bool IsShortConnectedControlCandidate,
    string PayloadHexPrefix);
