using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class LiveHandoffEvidenceAnalyzer
{
    private readonly PlasmaPacketClassifier _classifier = new();

    public async Task<LiveHandoffEvidenceReport> AnalyzeAsync(
        string eventLogPath,
        string outputPath,
        IReadOnlyList<string> sourceEvidencePaths)
    {
        var report = Analyze(eventLogPath, sourceEvidencePaths);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, JsonOptions));
        return report;
    }

    public LiveHandoffEvidenceReport Analyze(string eventLogPath, IReadOnlyList<string> sourceEvidencePaths)
    {
        var eventLog = AnalyzeEventLog(eventLogPath);
        var sourceEvidence = sourceEvidencePaths
            .Select(AnalyzeSourceEvidence)
            .ToArray();
        var hasSourceMotdTraffic = eventLog.HasSourceTrafficEvent
            || sourceEvidence.Any(static evidence => evidence.HasSourceOrMotdTraffic);
        var status = eventLog.HasSourceHandoffEvent && hasSourceMotdTraffic ? "passed" : "missing-evidence";

        return new LiveHandoffEvidenceReport(
            "live-rpcs3-source-handoff-evidence",
            status,
            eventLog,
            sourceEvidence,
            eventLog.HasSourceHandoffEvent,
            hasSourceMotdTraffic,
            status == "passed"
                ? Array.Empty<string>()
                : MissingReasons(eventLog, sourceEvidence));
    }

    private static LiveGameManagerEventEvidence AnalyzeEventLog(string path)
    {
        if (!File.Exists(path))
        {
            return new LiveGameManagerEventEvidence(path, false, 0, false, 0, false, 0, "", "", "");
        }

        var eventCount = 0;
        var handoffCount = 0;
        var sourceTrafficCount = 0;
        var firstEndpoint = "";
        var firstKind = "";
        var firstTimestamp = "";
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            eventCount++;
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            var eventName = ReadString(root, "Event");
            var stateAfter = ReadString(root, "StateAfter");
            if (eventName is "source-traffic" or "source-send" or "source-proxy-forward" or "source-proxy-send")
            {
                sourceTrafficCount++;
            }

            if (eventName != "source-handoff" || stateAfter != "SourceHandoff")
            {
                continue;
            }

            handoffCount++;
            if (firstEndpoint.Length == 0)
            {
                firstEndpoint = ReadString(root, "Endpoint");
                firstKind = ReadString(root, "Kind");
                firstTimestamp = ReadString(root, "Timestamp");
            }
        }

        return new LiveGameManagerEventEvidence(
            path,
            true,
            eventCount,
            handoffCount > 0,
            handoffCount,
            sourceTrafficCount > 0,
            sourceTrafficCount,
            firstEndpoint,
            firstKind,
            firstTimestamp);
    }

    private LiveSourceEvidence AnalyzeSourceEvidence(string path)
    {
        if (!File.Exists(path))
        {
            return new LiveSourceEvidence(path, false, "missing", false, 0, 0, Array.Empty<string>());
        }

        if (path.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
        {
            return AnalyzeSourcePcap(path);
        }

        return AnalyzeSourceText(path);
    }

    private LiveSourceEvidence AnalyzeSourcePcap(string path)
    {
        var packets = CaptureUdpPacketParser.ReadUdpPackets(path)
            .Where(static packet => packet.Payload.Length > 0)
            .ToArray();
        var sourceLike = 0;
        var sampleRoles = new List<string>();

        foreach (var packet in packets)
        {
            var decoded = _classifier.Decode(packet.Payload, enableNativeBinary: true);
            var preview = decoded.AsciiPreview(128);
            if (decoded.Kind == PlasmaCommandKind.SourceProbe
                || ContainsSourceMotdToken(preview)
                || packet.SourcePort is 27015 or 27016 or >= 3076 and <= 3105
                || packet.DestinationPort is 27015 or 27016 or >= 3076 and <= 3105)
            {
                sourceLike++;
                if (sampleRoles.Count < 8)
                {
                    sampleRoles.Add(decoded.Kind == PlasmaCommandKind.SourceProbe ? "source-probe" : $"udp:{packet.SourcePort}->{packet.DestinationPort}");
                }
            }
        }

        return new LiveSourceEvidence(
            path,
            true,
            "pcap",
            sourceLike > 0,
            packets.Length,
            sourceLike,
            sampleRoles.Distinct(StringComparer.Ordinal).ToArray());
    }

    private static LiveSourceEvidence AnalyzeSourceText(string path)
    {
        var lines = File.ReadLines(path).ToArray();
        var sourceLike = lines.Count(static line => ContainsSourceMotdToken(line));
        var samples = lines
            .Where(static line => ContainsSourceMotdToken(line))
            .Take(8)
            .Select(static line => line.Trim())
            .ToArray();

        return new LiveSourceEvidence(
            path,
            true,
            "text",
            sourceLike > 0,
            lines.Length,
            sourceLike,
            samples);
    }

    private static bool ContainsSourceMotdToken(string text)
    {
        return text.Contains("motd", StringComparison.OrdinalIgnoreCase)
            || text.Contains("source", StringComparison.OrdinalIgnoreCase)
            || text.Contains("A2S_", StringComparison.OrdinalIgnoreCase)
            || text.Contains("ff ff ff ff", StringComparison.OrdinalIgnoreCase)
            || text.Contains("ffffffff", StringComparison.OrdinalIgnoreCase)
            || text.Contains("client->backend", StringComparison.OrdinalIgnoreCase)
            || text.Contains("backend->client", StringComparison.OrdinalIgnoreCase);
    }

    private static string[] MissingReasons(LiveGameManagerEventEvidence eventLog, LiveSourceEvidence[] sourceEvidence)
    {
        var reasons = new List<string>();
        if (!eventLog.Exists)
        {
            reasons.Add("Missing live GameManager JSONL event log.");
        }
        else if (!eventLog.HasSourceHandoffEvent)
        {
            reasons.Add("GameManager event log has no source-handoff event.");
        }

        if (sourceEvidence.Length == 0)
        {
            reasons.Add("No Source/MOTD evidence files were supplied and the GameManager event log has no source-traffic/source-send events.");
        }
        else if (!eventLog.HasSourceTrafficEvent && !sourceEvidence.Any(static evidence => evidence.HasSourceOrMotdTraffic))
        {
            reasons.Add("Supplied Source/MOTD evidence files do not show Source/MOTD traffic.");
        }

        return reasons.ToArray();
    }

    private static string ReadString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) ? value.ToString() : "";
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}

public sealed record LiveHandoffEvidenceReport(
    string Status,
    string GateStatus,
    LiveGameManagerEventEvidence GameManagerEvents,
    LiveSourceEvidence[] SourceEvidence,
    bool HasSourceHandoffEvent,
    bool HasSourceMotdTraffic,
    string[] MissingReasons);

public sealed record LiveGameManagerEventEvidence(
    string Path,
    bool Exists,
    int EventCount,
    bool HasSourceHandoffEvent,
    int SourceHandoffEventCount,
    bool HasSourceTrafficEvent,
    int SourceTrafficEventCount,
    string FirstSourceHandoffEndpoint,
    string FirstSourceHandoffKind,
    string FirstSourceHandoffTimestamp);

public sealed record LiveSourceEvidence(
    string Path,
    bool Exists,
    string Kind,
    bool HasSourceOrMotdTraffic,
    int ObservedItemCount,
    int SourceOrMotdItemCount,
    string[] SampleEvidence);
