using System.Security.Cryptography;
using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class PcapSourceReplayCorpusAnalyzer
{
    private readonly PcapActiveFlowReplayExtractor _extractor = new();

    public async Task<PcapSourceReplayCorpusReport> AnalyzeDirectoryAsync(string inputDirectory, string outputPath)
    {
        var report = AnalyzeDirectory(inputDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
        return report;
    }

    public PcapSourceReplayCorpusReport AnalyzeDirectory(string inputDirectory)
    {
        var files = Directory.EnumerateFiles(inputDirectory, "*.*", SearchOption.AllDirectories)
            .Where(static p => p.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            .OrderBy(static p => p, StringComparer.Ordinal)
            .ToArray();
        var scripts = files
            .Select(file => AnalyzeFile(inputDirectory, file))
            .OfType<PcapSourceReplayScriptManifest>()
            .ToArray();

        return new PcapSourceReplayCorpusReport(
            "pcap-source-replay-corpus",
            BuildSummary(files.Length, scripts),
            BuildCollisionGroups(scripts, static script => script.FirstClientExactSignature)
                .Select(static group => new PcapSourceReplayCollisionGroup(group.Signature, group.Files))
                .ToArray(),
            BuildCollisionGroups(scripts, static script => script.FirstClientBodySignature)
                .Select(static group => new PcapSourceReplayCollisionGroup(group.Signature, group.Files))
                .ToArray(),
            BuildCollisionGroups(scripts, static script => script.FirstClientShapeSignature)
                .Select(static group => new PcapSourceReplayCollisionGroup(group.Signature, group.Files))
                .ToArray(),
            scripts);
    }

    private PcapSourceReplayScriptManifest? AnalyzeFile(string inputDirectory, string file)
    {
        var replay = _extractor.Extract(file);
        if (replay is null)
        {
            return null;
        }

        var firstClient = replay.SourcePackets.FirstOrDefault(static packet => packet.Direction == PcapActiveFlowDirection.ClientToServer);
        if (firstClient is null)
        {
            return null;
        }

        if (!Ps3SourceTransportPacket.TryDecode(firstClient.Payload, out var transport))
        {
            return null;
        }

        var shape = Ps3SourceGameplaySession.ClassifyShape(transport).ToString();
        var firstRunServerPackets = replay.SourcePackets
            .SkipWhile(static packet => packet.Direction != PcapActiveFlowDirection.ClientToServer)
            .Skip(1)
            .TakeWhile(static packet => packet.Direction == PcapActiveFlowDirection.ServerToClient)
            .Count();

        return new PcapSourceReplayScriptManifest(
            Path.GetRelativePath(inputDirectory, file),
            replay.ClientEndpoint,
            replay.ServerEndpoint,
            replay.SourcePackets.Length,
            replay.SourcePackets.Count(static packet => packet.Direction == PcapActiveFlowDirection.ClientToServer),
            replay.SourcePackets.Count(static packet => packet.Direction == PcapActiveFlowDirection.ServerToClient),
            firstRunServerPackets,
            firstClient.PacketIndex,
            firstClient.TimestampMicroseconds,
            transport.CandidateSequence,
            transport.PayloadLength,
            transport.Body.Length,
            shape,
            ExactSignature(firstClient.Payload),
            BodySignature(transport.Body),
            ShapeSignature(transport.PayloadLength, transport.Body.Length, shape),
            Convert.ToHexString(firstClient.Payload.AsSpan(0, Math.Min(16, firstClient.Payload.Length))).ToLowerInvariant());
    }

    private static PcapSourceReplayCorpusSummary BuildSummary(int fileCount, PcapSourceReplayScriptManifest[] scripts)
    {
        var exactCollisions = BuildCollisionGroups(scripts, static script => script.FirstClientExactSignature).ToArray();
        var bodyCollisions = BuildCollisionGroups(scripts, static script => script.FirstClientBodySignature).ToArray();
        var shapeCollisions = BuildCollisionGroups(scripts, static script => script.FirstClientShapeSignature).ToArray();
        return new PcapSourceReplayCorpusSummary(
            fileCount,
            scripts.Length,
            scripts.Sum(static script => script.SourcePacketCount),
            scripts.Sum(static script => script.ClientToServerPacketCount),
            scripts.Sum(static script => script.ServerToClientPacketCount),
            scripts.Length == 0 ? 0 : scripts.Max(static script => script.FirstClientPayloadLength),
            scripts.Select(static script => script.FirstClientExactSignature).Distinct(StringComparer.Ordinal).Count(),
            scripts.Select(static script => script.FirstClientBodySignature).Distinct(StringComparer.Ordinal).Count(),
            scripts.Select(static script => script.FirstClientShapeSignature).Distinct(StringComparer.Ordinal).Count(),
            exactCollisions.Length,
            bodyCollisions.Length,
            shapeCollisions.Length,
            exactCollisions.Sum(static group => group.Files.Length),
            bodyCollisions.Sum(static group => group.Files.Length),
            shapeCollisions.Sum(static group => group.Files.Length),
            bodyCollisions.Length == 0
                ? "directory-replay-selection-can-prefer-sequence-insensitive-body-before-shape"
                : "directory-replay-selection-needs-more-than-body-signature-disambiguation");
    }

    private static PcapSourceReplayCollision[] BuildCollisionGroups(
        PcapSourceReplayScriptManifest[] scripts,
        Func<PcapSourceReplayScriptManifest, string> selector)
    {
        return scripts
            .GroupBy(selector, StringComparer.Ordinal)
            .Where(static group => group.Count() > 1)
            .Select(static group => new PcapSourceReplayCollision(
                group.Key,
                group.Select(static script => script.File).Order(StringComparer.Ordinal).ToArray()))
            .OrderByDescending(static group => group.Files.Length)
            .ThenBy(static group => group.Signature, StringComparer.Ordinal)
            .ToArray();
    }

    private static string ExactSignature(byte[] payload)
    {
        return Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
    }

    private static string BodySignature(ReadOnlySpan<byte> body)
    {
        return Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();
    }

    private static string ShapeSignature(int payloadLength, int bodyLength, string shape)
    {
        return $"{payloadLength}:{bodyLength}:{shape}";
    }

    private sealed record PcapSourceReplayCollision(string Signature, string[] Files);
}

public sealed record PcapSourceReplayCorpusReport(
    string Status,
    PcapSourceReplayCorpusSummary Summary,
    PcapSourceReplayCollisionGroup[] ExactSignatureCollisions,
    PcapSourceReplayCollisionGroup[] BodySignatureCollisions,
    PcapSourceReplayCollisionGroup[] ShapeSignatureCollisions,
    PcapSourceReplayScriptManifest[] Scripts);

public sealed record PcapSourceReplayCorpusSummary(
    int FileCount,
    int ActiveReplayScriptCount,
    int SourcePacketCount,
    int ClientToServerPacketCount,
    int ServerToClientPacketCount,
    int MaxFirstClientPayloadLength,
    int UniqueExactSignatureCount,
    int UniqueBodySignatureCount,
    int UniqueShapeSignatureCount,
    int ExactSignatureCollisionGroupCount,
    int BodySignatureCollisionGroupCount,
    int ShapeSignatureCollisionGroupCount,
    int ScriptsInExactSignatureCollisionGroups,
    int ScriptsInBodySignatureCollisionGroups,
    int ScriptsInShapeSignatureCollisionGroups,
    string DirectorySelectionConclusion);

public sealed record PcapSourceReplayCollisionGroup(
    string Signature,
    string[] Files);

public sealed record PcapSourceReplayScriptManifest(
    string File,
    string ClientEndpoint,
    string ServerEndpoint,
    int SourcePacketCount,
    int ClientToServerPacketCount,
    int ServerToClientPacketCount,
    int ImmediateServerResponseCount,
    long FirstClientPacketIndex,
    long FirstClientTimestampMicroseconds,
    int FirstClientSequence,
    int FirstClientPayloadLength,
    int FirstClientBodyLength,
    string FirstClientShape,
    string FirstClientExactSignature,
    string FirstClientBodySignature,
    string FirstClientShapeSignature,
    string FirstClientHexPrefix);
