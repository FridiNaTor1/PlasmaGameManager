using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class PcapCorpusCoverageAnalyzer
{
    private readonly PlasmaPacketClassifier _classifier = new();
    private readonly GameManagerCommandDecoder _commandDecoder = new();

    public async Task<PcapCorpusCoverageReport> AnalyzeDirectoryAsync(
        string inputDirectory,
        string outputPath,
        string? tf2DispatcherMapPath = null)
    {
        var report = AnalyzeDirectory(inputDirectory, tf2DispatcherMapPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
        return report;
    }

    public PcapCorpusCoverageReport AnalyzeDirectory(string inputDirectory, string? tf2DispatcherMapPath = null)
    {
        var semanticCatalog = Tf2Ps3PcapSemanticCatalog.LoadOrDefault(tf2DispatcherMapPath);
        var files = Directory.EnumerateFiles(inputDirectory, "*.*", SearchOption.AllDirectories)
            .Where(static p => p.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            .OrderBy(static p => p, StringComparer.Ordinal)
            .Select(file => AnalyzeFile(inputDirectory, file, semanticCatalog))
            .ToArray();

        return new PcapCorpusCoverageReport(
            "seeded-from-tf2-ps3-pcap-corpus-semantic-analysis",
            "Corpus-level audit for TF2 PS3 GameManager PCAP coverage. Unknown/opaque payload shapes remain explicit so they can drive the next TF.elf/BFBC2 reverse-engineering pass.",
            BuildSummary(files),
            files);
    }

    private PcapCorpusFileCoverage AnalyzeFile(string inputDirectory, string file, Tf2Ps3PcapSemanticCatalog semanticCatalog)
    {
        var packets = CaptureUdpPacketParser.ReadUdpPackets(file)
            .Where(static packet => packet.Payload.Length > 0)
            .Select(packet => AnalyzePacket(packet, semanticCatalog))
            .ToArray();

        var nativeTypes = packets
            .Where(static packet => packet.NativeType is not null)
            .Select(static packet => packet.NativeType!.Value)
            .Distinct()
            .Order()
            .ToArray();
        var candidateRoles = packets
            .SelectMany(static packet => packet.CandidateDispatcherRoles)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();

        return new PcapCorpusFileCoverage(
            Path.GetRelativePath(inputDirectory, file),
            ScenarioFamily(Path.GetRelativePath(inputDirectory, file)),
            packets.Length,
            packets.Count(static packet => packet.Kind != PlasmaCommandKind.Unknown),
            packets.Count(static packet => packet.Kind == PlasmaCommandKind.Unknown),
            packets.Count(static packet => packet.Kind == PlasmaCommandKind.Unknown && IsGameManagerScope(packet.Phase)),
            packets.Count(static packet => packet.Kind == PlasmaCommandKind.Unknown && packet.Phase == GameManagerScenarioPhase.DiscoveryNoise),
            packets.Count(static packet => packet.Kind == PlasmaCommandKind.Unknown && packet.Phase == GameManagerScenarioPhase.SourceTraffic),
            packets.Count(static packet => packet.Kind == PlasmaCommandKind.OpaqueControl),
            packets.Count(static packet => packet.Kind == PlasmaCommandKind.OpaqueControl && IsGameManagerScope(packet.Phase)),
            packets.Count(static packet => packet.Kind == PlasmaCommandKind.OpaqueControl && packet.Phase == GameManagerScenarioPhase.SourceTraffic),
            packets.Any(static packet => packet.Kind == PlasmaCommandKind.ClientHello),
            packets.Any(static packet => packet.Kind == PlasmaCommandKind.ServerHello),
            packets.Any(static packet => packet.Kind == PlasmaCommandKind.ClientHello) && packets.Any(static packet => packet.Kind == PlasmaCommandKind.ServerHello),
            packets.Any(static packet => packet.Kind == PlasmaCommandKind.Roster),
            packets.Any(static packet => packet.Kind == PlasmaCommandKind.SourceProbe),
            packets.Count(static packet => packet.IsTransportWrapped),
            nativeTypes,
            candidateRoles,
            CountBy(packets, static packet => packet.Phase.ToString()),
            CountBy(packets, static packet => packet.SemanticRole),
            CountBy(packets, static packet => packet.Kind.ToString()),
            UnknownShapes(packets, 8));
    }

    private PcapCorpusPacketCoverage AnalyzePacket(CaptureUdpPacket packet, Tf2Ps3PcapSemanticCatalog semanticCatalog)
    {
        var hasTransportFrame = PlasmaTransportFrame.TryDecode(packet.Payload, out var transportFrame);
        var semanticPayload = hasTransportFrame ? transportFrame.Payload : packet.Payload;
        var decoded = _classifier.Decode(semanticPayload, enableNativeBinary: hasTransportFrame);
        var command = _commandDecoder.Decode(decoded);
        var phase = GameManagerScenarioPhaseClassifier.Classify(command, packet.SourcePort, packet.DestinationPort);
        var markerOffset = PcapPacketConfidence.FindMarkerOffset(semanticPayload, decoded.Marker);
        var confidence = PcapPacketConfidence.Classify(semanticPayload, decoded, hasTransportFrame, markerOffset);
        var semantic = semanticCatalog.Explain(command, decoded.Marker, confidence, hasTransportFrame);
        return new PcapCorpusPacketCoverage(
            packet.PacketIndex,
            packet.SourcePort,
            packet.DestinationPort,
            semanticPayload.Length,
            decoded.Kind,
            phase,
            semantic.Role,
            semantic.NativeType,
            semantic.CandidateDispatcherRoles,
            semantic.IsTransportWrapped,
            semanticPayload.Length == 0 ? "" : Convert.ToHexString(semanticPayload.AsSpan(0, Math.Min(8, semanticPayload.Length))).ToLowerInvariant());
    }

    private static PcapCorpusSummary BuildSummary(PcapCorpusFileCoverage[] files)
    {
        var nonEmpty = files.Where(static file => file.UdpPacketCount > 0).ToArray();
        return new PcapCorpusSummary(
            files.Length,
            nonEmpty.Length,
            files.Length - nonEmpty.Length,
            nonEmpty.Count(static file => file.HasCompleteHelloFlow),
            nonEmpty.Count(static file => file.HasRoster),
            nonEmpty.Count(static file => file.HasSourceProbe),
            nonEmpty.Sum(static file => file.UdpPacketCount),
            nonEmpty.Sum(static file => file.GameManagerLikeCount),
            nonEmpty.Sum(static file => file.UnknownCount),
            nonEmpty.Sum(static file => file.UnknownGameManagerScopeCount),
            nonEmpty.Sum(static file => file.UnknownDiscoveryNoiseCount),
            nonEmpty.Sum(static file => file.UnknownSourceTrafficCount),
            nonEmpty.Sum(static file => file.OpaqueControlCount),
            nonEmpty.Sum(static file => file.OpaqueGameManagerScopeCount),
            nonEmpty.Sum(static file => file.OpaqueSourceTrafficCount),
            nonEmpty.Select(static file => file.ScenarioFamily).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
            nonEmpty.SelectMany(static file => file.NativeTypes).Distinct().Order().ToArray(),
            nonEmpty.SelectMany(static file => file.CandidateDispatcherRoles).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
            UnknownShapes(nonEmpty.SelectMany(static file => file.TopUnknownShapes), 16));
    }

    private static Dictionary<string, int> CountBy<T>(IEnumerable<T> items, Func<T, string> keySelector)
    {
        return items
            .GroupBy(keySelector, StringComparer.Ordinal)
            .OrderBy(static group => group.Key, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.Ordinal);
    }

    private static PcapUnknownShape[] UnknownShapes(IEnumerable<PcapCorpusPacketCoverage> packets, int limit)
    {
        return packets
            .Where(static packet => packet.Kind == PlasmaCommandKind.Unknown && IsGameManagerScope(packet.Phase))
            .GroupBy(static packet => new { packet.Length, packet.HexPrefix })
            .Select(static group => new PcapUnknownShape(
                group.Key.Length,
                group.Key.HexPrefix,
                group.Count(),
                group.Select(static packet => packet.SourcePort).Distinct().Order().Take(8).ToArray(),
                group.Select(static packet => packet.DestinationPort).Distinct().Order().Take(8).ToArray(),
                group.Select(static packet => packet.PacketIndex).Take(5).ToArray()))
            .OrderByDescending(static shape => shape.Count)
            .ThenBy(static shape => shape.Length)
            .ThenBy(static shape => shape.HexPrefix, StringComparer.Ordinal)
            .Take(limit)
            .ToArray();
    }

    private static bool IsGameManagerScope(GameManagerScenarioPhase phase)
    {
        return phase is not GameManagerScenarioPhase.DiscoveryNoise and not GameManagerScenarioPhase.SourceTraffic;
    }

    private static PcapUnknownShape[] UnknownShapes(IEnumerable<PcapUnknownShape> shapes, int limit)
    {
        return shapes
            .GroupBy(static shape => new { shape.Length, shape.HexPrefix })
            .Select(static group => new PcapUnknownShape(
                group.Key.Length,
                group.Key.HexPrefix,
                group.Sum(static shape => shape.Count),
                group.SelectMany(static shape => shape.SourcePorts).Distinct().Order().Take(8).ToArray(),
                group.SelectMany(static shape => shape.DestinationPorts).Distinct().Order().Take(8).ToArray(),
                group.SelectMany(static shape => shape.SamplePacketIndexes).Take(5).ToArray()))
            .OrderByDescending(static shape => shape.Count)
            .ThenBy(static shape => shape.Length)
            .ThenBy(static shape => shape.HexPrefix, StringComparer.Ordinal)
            .Take(limit)
            .ToArray();
    }

    private static string ScenarioFamily(string relativePath)
    {
        var path = relativePath.Replace('\\', '/').ToLowerInvariant();
        if (path.Contains("quick_match_to_motd", StringComparison.Ordinal))
        {
            return "quick-match-to-motd";
        }

        if (path.Contains("custom_match_joining", StringComparison.Ordinal))
        {
            return "custom-match-join-to-motd";
        }

        if (path.Contains("creating_and_join", StringComparison.Ordinal))
        {
            return "create-and-join";
        }

        if (path.Contains("creating_only", StringComparison.Ordinal))
        {
            return "create-only";
        }

        if (path.Contains("dustbowl", StringComparison.Ordinal) || path.Contains("cp_db", StringComparison.Ordinal))
        {
            return "dustbowl-play";
        }

        if (path.Contains("2fort", StringComparison.Ordinal))
        {
            return "2fort-play";
        }

        if (path.Contains("connect", StringComparison.Ordinal) || path.Contains("connection", StringComparison.Ordinal))
        {
            return "connection";
        }

        if (path.Contains("lookup", StringComparison.Ordinal) || path.Contains("serverbrowser", StringComparison.Ordinal))
        {
            return "server-lookup";
        }

        if (path.Contains("ranking", StringComparison.Ordinal) || path.Contains("leaderboard", StringComparison.Ordinal))
        {
            return "ranking";
        }

        if (path.Contains("menu", StringComparison.Ordinal) || path.Contains("signin", StringComparison.Ordinal))
        {
            return "menu-signin";
        }

        return "other";
    }
}

public sealed record PcapCorpusCoverageReport(
    string Status,
    string Note,
    PcapCorpusSummary Summary,
    PcapCorpusFileCoverage[] Files);

public sealed record PcapCorpusSummary(
    int FileCount,
    int NonEmptyFileCount,
    int EmptyFileCount,
    int FilesWithCompleteHelloFlow,
    int FilesWithRoster,
    int FilesWithSourceProbe,
    int UdpPacketCount,
    int GameManagerLikeCount,
    int UnknownCount,
    int UnknownGameManagerScopeCount,
    int UnknownDiscoveryNoiseCount,
    int UnknownSourceTrafficCount,
    int OpaqueControlCount,
    int OpaqueGameManagerScopeCount,
    int OpaqueSourceTrafficCount,
    string[] ScenarioFamilies,
    int[] NativeTypes,
    string[] CandidateDispatcherRoles,
    PcapUnknownShape[] TopUnknownShapes);

public sealed record PcapCorpusFileCoverage(
    string File,
    string ScenarioFamily,
    int UdpPacketCount,
    int GameManagerLikeCount,
    int UnknownCount,
    int UnknownGameManagerScopeCount,
    int UnknownDiscoveryNoiseCount,
    int UnknownSourceTrafficCount,
    int OpaqueControlCount,
    int OpaqueGameManagerScopeCount,
    int OpaqueSourceTrafficCount,
    bool HasClientHello,
    bool HasServerHello,
    bool HasCompleteHelloFlow,
    bool HasRoster,
    bool HasSourceProbe,
    int TransportWrappedPacketCount,
    int[] NativeTypes,
    string[] CandidateDispatcherRoles,
    Dictionary<string, int> PhaseCounts,
    Dictionary<string, int> SemanticRoleCounts,
    Dictionary<string, int> KindCounts,
    PcapUnknownShape[] TopUnknownShapes);

public sealed record PcapUnknownShape(
    int Length,
    string HexPrefix,
    int Count,
    int[] SourcePorts,
    int[] DestinationPorts,
    long[] SamplePacketIndexes);

public sealed record PcapCorpusPacketCoverage(
    long PacketIndex,
    int SourcePort,
    int DestinationPort,
    int Length,
    PlasmaCommandKind Kind,
    GameManagerScenarioPhase Phase,
    string SemanticRole,
    int? NativeType,
    string[] CandidateDispatcherRoles,
    bool IsTransportWrapped,
    string HexPrefix);
