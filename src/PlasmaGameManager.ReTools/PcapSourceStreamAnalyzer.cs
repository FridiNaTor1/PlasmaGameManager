using System.Text.Json;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.ReTools;

public sealed class PcapSourceStreamAnalyzer
{
    private readonly PcapActiveFlowReplayExtractor _extractor = new();

    public async Task<PcapSourceStreamReport> AnalyzeDirectoryAsync(string inputDirectory, string outputPath)
    {
        var report = AnalyzeDirectory(inputDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
        return report;
    }

    public PcapSourceStreamReport AnalyzeDirectory(string inputDirectory)
    {
        var files = Directory.EnumerateFiles(inputDirectory, "*.*", SearchOption.AllDirectories)
            .Where(static p => p.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            .OrderBy(static p => p, StringComparer.Ordinal)
            .ToArray();
        var fileReports = files.Select(file => AnalyzeFile(inputDirectory, file)).ToArray();
        return new PcapSourceStreamReport(BuildSummary(fileReports), fileReports);
    }

    private PcapSourceStreamFile AnalyzeFile(string inputDirectory, string file)
    {
        var relativePath = Path.GetRelativePath(inputDirectory, file);
        var replay = _extractor.Extract(file);
        if (replay is null)
        {
            return new PcapSourceStreamFile(
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
                0,
                0,
                0,
                0,
                0,
                Array.Empty<PcapSourceFieldCandidate>(),
                Array.Empty<PcapSourceStreamCount>(),
                Array.Empty<PcapSourceStreamCount>(),
                Array.Empty<PcapSourceStreamCount>(),
                Array.Empty<PcapSourceStreamCount>(),
                Array.Empty<PcapSourceStreamTurn>(),
                Array.Empty<PcapSourceStreamSample>());
        }

        var packets = replay.SourcePackets;
        var clientPackets = packets.Where(static packet => packet.Direction == PcapActiveFlowDirection.ClientToServer).ToArray();
        var serverPackets = packets.Where(static packet => packet.Direction == PcapActiveFlowDirection.ServerToClient).ToArray();
        var turns = BuildTurns(packets);
        return new PcapSourceStreamFile(
            relativePath,
            true,
            replay.ClientEndpoint,
            replay.ServerEndpoint,
            replay.ServerPort,
            replay.ClientHelloPacketIndex,
            replay.ServerHelloPacketIndex,
            replay.FirstSourceClientPacketIndex,
            packets.Length,
            clientPackets.Length,
            serverPackets.Length,
            packets.Length == 0 ? 0 : packets.Min(static packet => packet.Payload.Length),
            packets.Length == 0 ? 0 : packets.Max(static packet => packet.Payload.Length),
            packets.Length == 0 ? 0 : Math.Round(packets.Average(static packet => packet.Payload.Length), 2),
            LongestDirectionRun(packets),
            packets.FirstOrDefault()?.PacketIndex ?? 0,
            packets.LastOrDefault()?.PacketIndex ?? 0,
            packets.FirstOrDefault()?.TimestampMicroseconds ?? 0,
            packets.LastOrDefault()?.TimestampMicroseconds ?? 0,
            DurationMilliseconds(packets),
            AverageInterArrivalMilliseconds(packets),
            MaxInterArrivalMilliseconds(packets),
            CountDirectionSwitches(packets),
            turns.Length,
            turns.Count(static turn => turn.ServerPacketCount > 0),
            turns.Length == 0 ? 0 : turns.Max(static turn => turn.ClientPacketCount),
            turns.Length == 0 ? 0 : turns.Max(static turn => turn.ServerPacketCount),
            AverageResponseDelayMilliseconds(turns),
            turns.Length == 0 ? 0 : turns.Max(static turn => turn.ResponseDelayMilliseconds),
            turns.Length == 0 ? 0 : turns.Max(static turn => turn.DurationMilliseconds),
            CandidateFields(packets),
            TopLengthCounts(packets),
            TopPrefixCounts(packets, bytes: 2),
            TopPrefixCounts(clientPackets, bytes: 2),
            TopPrefixCounts(serverPackets, bytes: 2),
            turns.Take(64).ToArray(),
            packets.Take(24)
                .Select(static packet => new PcapSourceStreamSample(
                    packet.PacketIndex,
                    packet.TimestampMicroseconds,
                    packet.Direction.ToString(),
                    packet.Payload.Length,
                    packet.Kind.ToString(),
                    DecodeCandidateSequence(packet.Payload),
                    CandidateBodyLength(packet.Payload),
                    packet.HexPrefix,
                    packet.AsciiPreview))
                .ToArray());
    }

    private static PcapSourceStreamSummary BuildSummary(PcapSourceStreamFile[] files)
    {
        var activeFiles = files.Where(static file => file.HasActiveSourceFlow).ToArray();
        return new PcapSourceStreamSummary(
            files.Length,
            activeFiles.Length,
            activeFiles.Sum(static file => file.SourcePacketCount),
            activeFiles.Sum(static file => file.ClientToServerPacketCount),
            activeFiles.Sum(static file => file.ServerToClientPacketCount),
            activeFiles.Length == 0 ? 0 : activeFiles.Min(static file => file.MinPayloadLength),
            activeFiles.Length == 0 ? 0 : activeFiles.Max(static file => file.MaxPayloadLength),
            activeFiles.Length == 0 ? 0 : Math.Round(activeFiles.Average(static file => file.AveragePayloadLength), 2),
            activeFiles.Length == 0 ? 0 : activeFiles.Max(static file => file.DurationMilliseconds),
            activeFiles.Length == 0 ? 0 : Math.Round(activeFiles.Average(static file => file.AverageInterArrivalMilliseconds), 3),
            activeFiles.Length == 0 ? 0 : activeFiles.Max(static file => file.MaxInterArrivalMilliseconds),
            activeFiles.Length == 0 ? 0 : activeFiles.Max(static file => file.LongestSameDirectionRun),
            activeFiles.Length == 0 ? 0 : activeFiles.Max(static file => file.DirectionSwitchCount),
            activeFiles.Sum(static file => file.TurnCount),
            activeFiles.Sum(static file => file.RespondedTurnCount),
            activeFiles.Length == 0 ? 0 : activeFiles.Max(static file => file.MaxClientBurstPacketCount),
            activeFiles.Length == 0 ? 0 : activeFiles.Max(static file => file.MaxServerResponsePacketCount),
            activeFiles.Length == 0 ? 0 : activeFiles.Max(static file => file.MaxTurnDurationMilliseconds),
            activeFiles.Length == 0 ? 0 : activeFiles.Max(static file => file.MaxResponseDelayMilliseconds));
    }

    private static double DurationMilliseconds(IReadOnlyList<PcapActiveFlowDatagram> packets)
    {
        if (packets.Count < 2)
        {
            return 0;
        }

        return Math.Round((packets[^1].TimestampMicroseconds - packets[0].TimestampMicroseconds) / 1000.0, 3);
    }

    private static double AverageInterArrivalMilliseconds(IReadOnlyList<PcapActiveFlowDatagram> packets)
    {
        if (packets.Count < 2)
        {
            return 0;
        }

        var total = 0L;
        for (var i = 1; i < packets.Count; i++)
        {
            total += Math.Max(0, packets[i].TimestampMicroseconds - packets[i - 1].TimestampMicroseconds);
        }

        return Math.Round((total / (double)(packets.Count - 1)) / 1000.0, 3);
    }

    private static double MaxInterArrivalMilliseconds(IReadOnlyList<PcapActiveFlowDatagram> packets)
    {
        if (packets.Count < 2)
        {
            return 0;
        }

        var max = 0L;
        for (var i = 1; i < packets.Count; i++)
        {
            max = Math.Max(max, packets[i].TimestampMicroseconds - packets[i - 1].TimestampMicroseconds);
        }

        return Math.Round(max / 1000.0, 3);
    }

    private static int CountDirectionSwitches(IReadOnlyList<PcapActiveFlowDatagram> packets)
    {
        var count = 0;
        for (var i = 1; i < packets.Count; i++)
        {
            if (packets[i].Direction != packets[i - 1].Direction)
            {
                count++;
            }
        }

        return count;
    }

    private static int LongestDirectionRun(IReadOnlyList<PcapActiveFlowDatagram> packets)
    {
        if (packets.Count == 0)
        {
            return 0;
        }

        var longest = 1;
        var current = 1;
        for (var i = 1; i < packets.Count; i++)
        {
            if (packets[i].Direction == packets[i - 1].Direction)
            {
                current++;
            }
            else
            {
                longest = Math.Max(longest, current);
                current = 1;
            }
        }

        return Math.Max(longest, current);
    }

    private static PcapSourceStreamTurn[] BuildTurns(IReadOnlyList<PcapActiveFlowDatagram> packets)
    {
        var turns = new List<PcapSourceStreamTurn>();
        var index = 0;
        while (index < packets.Count)
        {
            while (index < packets.Count && packets[index].Direction != PcapActiveFlowDirection.ClientToServer)
            {
                index++;
            }

            if (index >= packets.Count)
            {
                break;
            }

            var clientStart = index;
            while (index < packets.Count && packets[index].Direction == PcapActiveFlowDirection.ClientToServer)
            {
                index++;
            }

            var serverStart = index;
            while (index < packets.Count && packets[index].Direction == PcapActiveFlowDirection.ServerToClient)
            {
                index++;
            }

            var clientRun = packets.Skip(clientStart).Take(serverStart - clientStart).ToArray();
            var serverRun = packets.Skip(serverStart).Take(index - serverStart).ToArray();
            turns.Add(BuildTurn(turns.Count, clientRun, serverRun));
        }

        return turns.ToArray();
    }

    private static PcapSourceStreamTurn BuildTurn(
        int turnIndex,
        PcapActiveFlowDatagram[] clientRun,
        PcapActiveFlowDatagram[] serverRun)
    {
        var all = clientRun.Concat(serverRun).ToArray();
        return new PcapSourceStreamTurn(
            turnIndex,
            clientRun.Length,
            serverRun.Length,
            all[0].PacketIndex,
            all[^1].PacketIndex,
            all[0].TimestampMicroseconds,
            all[^1].TimestampMicroseconds,
            Math.Round((all[^1].TimestampMicroseconds - all[0].TimestampMicroseconds) / 1000.0, 3),
            serverRun.Length == 0 ? 0 : Math.Round((serverRun[0].TimestampMicroseconds - clientRun[^1].TimestampMicroseconds) / 1000.0, 3),
            FirstSequence(clientRun),
            LastSequence(clientRun),
            FirstSequence(serverRun),
            LastSequence(serverRun),
            MinBodyLength(clientRun),
            MaxBodyLength(clientRun),
            MinBodyLength(serverRun),
            MaxBodyLength(serverRun),
            Ps3SourceGameplaySignatures.BodyRunSignature(clientRun.Select(static packet => packet.Payload)),
            Ps3SourceGameplaySignatures.BodyRunSignature(serverRun.Select(static packet => packet.Payload)),
            Ps3SourceGameplaySignatures.TurnBodySignature(
                clientRun.Select(static packet => packet.Payload),
                serverRun.Select(static packet => packet.Payload)),
            Ps3SourceGameplaySignatures.ShapeRunSignature(clientRun.Select(static packet => packet.Payload)),
            Ps3SourceGameplaySignatures.ShapeRunSignature(serverRun.Select(static packet => packet.Payload)),
            TopShapeCounts(clientRun),
            TopShapeCounts(serverRun));
    }

    private static double AverageResponseDelayMilliseconds(PcapSourceStreamTurn[] turns)
    {
        var responded = turns.Where(static turn => turn.ServerPacketCount > 0).ToArray();
        return responded.Length == 0 ? 0 : Math.Round(responded.Average(static turn => turn.ResponseDelayMilliseconds), 3);
    }

    private static int? FirstSequence(PcapActiveFlowDatagram[] packets)
    {
        return packets.Length > 0 && Ps3SourceTransportPacket.TryDecode(packets[0].Payload, out var packet)
            ? packet.CandidateSequence
            : null;
    }

    private static int? LastSequence(PcapActiveFlowDatagram[] packets)
    {
        return packets.Length > 0 && Ps3SourceTransportPacket.TryDecode(packets[^1].Payload, out var packet)
            ? packet.CandidateSequence
            : null;
    }

    private static int MinBodyLength(PcapActiveFlowDatagram[] packets)
    {
        return packets.Length == 0 ? 0 : packets.Min(static packet => CandidateBodyLength(packet.Payload));
    }

    private static int MaxBodyLength(PcapActiveFlowDatagram[] packets)
    {
        return packets.Length == 0 ? 0 : packets.Max(static packet => CandidateBodyLength(packet.Payload));
    }

    private static PcapSourceStreamCount[] TopShapeCounts(PcapActiveFlowDatagram[] packets)
    {
        return packets
            .Select(static packet => Ps3SourceTransportPacket.TryDecode(packet.Payload, out var decoded)
                ? Ps3SourceGameplaySession.ClassifyShape(decoded).ToString()
                : Ps3SourceGameplayPacketShape.Invalid.ToString())
            .GroupBy(static shape => shape, StringComparer.Ordinal)
            .OrderByDescending(static group => group.Count())
            .ThenBy(static group => group.Key, StringComparer.Ordinal)
            .Select(static group => new PcapSourceStreamCount(group.Key, group.Count()))
            .ToArray();
    }

    private static int? DecodeCandidateSequence(byte[] payload)
    {
        return Ps3SourceTransportPacket.TryDecode(payload, out var packet)
            ? packet.CandidateSequence
            : null;
    }

    private static int CandidateBodyLength(byte[] payload)
    {
        return Ps3SourceTransportPacket.TryDecode(payload, out var packet)
            ? packet.Body.Length
            : 0;
    }

    private static PcapSourceFieldCandidate[] CandidateFields(IReadOnlyList<PcapActiveFlowDatagram> packets)
    {
        return Enum.GetValues<PcapActiveFlowDirection>()
            .SelectMany(direction => CandidateFieldsForDirection(
                packets.Where(packet => packet.Direction == direction).ToArray(),
                direction))
            .ToArray();
    }

    private static IEnumerable<PcapSourceFieldCandidate> CandidateFieldsForDirection(
        IReadOnlyList<PcapActiveFlowDatagram> packets,
        PcapActiveFlowDirection direction)
    {
        foreach (var width in new[] { 1, 2, 4 })
        {
            foreach (var offset in Enumerable.Range(0, 8))
            {
                if (offset + width > 12)
                {
                    continue;
                }

                foreach (var candidate in BuildCandidates(packets, direction, offset, width))
                {
                    yield return candidate;
                }
            }
        }
    }

    private static PcapSourceFieldCandidate[] BuildCandidates(
        IReadOnlyList<PcapActiveFlowDatagram> packets,
        PcapActiveFlowDirection direction,
        int offset,
        int width)
    {
        var endians = width == 1 ? new[] { "u8" } : new[] { "be", "le" };
        return endians
            .Select(endian => BuildCandidate(packets, direction, offset, width, endian))
            .OfType<PcapSourceFieldCandidate>()
            .OrderBy(static candidate => candidate.DecreaseCount)
            .ThenByDescending(static candidate => candidate.DistinctCount)
            .ThenBy(static candidate => candidate.Offset)
            .ThenBy(static candidate => candidate.Width)
            .ToArray();
    }

    private static PcapSourceFieldCandidate? BuildCandidate(
        IReadOnlyList<PcapActiveFlowDatagram> packets,
        PcapActiveFlowDirection direction,
        int offset,
        int width,
        string endian)
    {
        var values = packets
            .Where(packet => packet.Payload.Length >= offset + width)
            .Select(packet => ReadUnsigned(packet.Payload, offset, width, endian))
            .ToArray();
        if (values.Length < 4)
        {
            return null;
        }

        var increaseCount = 0;
        var sameCount = 0;
        var decreaseCount = 0;
        var absoluteDeltaTotal = 0.0;
        for (var i = 1; i < values.Length; i++)
        {
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
            }

            absoluteDeltaTotal += Math.Abs((double)values[i] - values[i - 1]);
        }

        return new PcapSourceFieldCandidate(
            direction.ToString(),
            offset,
            width,
            endian,
            values.Length,
            values.Distinct().Count(),
            values[0],
            values[^1],
            values.Min(),
            values.Max(),
            increaseCount,
            sameCount,
            decreaseCount,
            Math.Round(absoluteDeltaTotal / Math.Max(1, values.Length - 1), 3),
            values.Take(12).ToArray());
    }

    private static ulong ReadUnsigned(byte[] payload, int offset, int width, string endian)
    {
        return width switch
        {
            1 => payload[offset],
            2 when endian == "le" => (ulong)(payload[offset] | (payload[offset + 1] << 8)),
            2 => (ulong)((payload[offset] << 8) | payload[offset + 1]),
            4 when endian == "le" => (uint)(payload[offset]
                | ((uint)payload[offset + 1] << 8)
                | ((uint)payload[offset + 2] << 16)
                | ((uint)payload[offset + 3] << 24)),
            4 => (uint)(((uint)payload[offset] << 24)
                | ((uint)payload[offset + 1] << 16)
                | ((uint)payload[offset + 2] << 8)
                | payload[offset + 3]),
            _ => 0
        };
    }

    private static PcapSourceStreamCount[] TopLengthCounts(IEnumerable<PcapActiveFlowDatagram> packets)
    {
        return packets
            .GroupBy(static packet => packet.Payload.Length)
            .OrderByDescending(static group => group.Count())
            .ThenBy(static group => group.Key)
            .Take(16)
            .Select(static group => new PcapSourceStreamCount(group.Key.ToString(), group.Count()))
            .ToArray();
    }

    private static PcapSourceStreamCount[] TopPrefixCounts(IEnumerable<PcapActiveFlowDatagram> packets, int bytes)
    {
        return packets
            .Where(packet => packet.Payload.Length >= bytes)
            .GroupBy(packet => Convert.ToHexString(packet.Payload.AsSpan(0, bytes)).ToLowerInvariant(), StringComparer.Ordinal)
            .OrderByDescending(static group => group.Count())
            .ThenBy(static group => group.Key, StringComparer.Ordinal)
            .Take(16)
            .Select(static group => new PcapSourceStreamCount(group.Key, group.Count()))
            .ToArray();
    }
}

public sealed record PcapSourceStreamReport(
    PcapSourceStreamSummary Summary,
    PcapSourceStreamFile[] Files);

public sealed record PcapSourceStreamSummary(
    int FileCount,
    int ActiveSourceFlowCount,
    int SourcePacketCount,
    int ClientToServerPacketCount,
    int ServerToClientPacketCount,
    int MinPayloadLength,
    int MaxPayloadLength,
    double AveragePayloadLength,
    double MaxDurationMilliseconds,
    double AverageInterArrivalMilliseconds,
    double MaxInterArrivalMilliseconds,
    int MaxLongestSameDirectionRun,
    int MaxDirectionSwitchCount,
    int TotalTurnCount,
    int TotalRespondedTurnCount,
    int MaxClientBurstPacketCount,
    int MaxServerResponsePacketCount,
    double MaxTurnDurationMilliseconds,
    double MaxResponseDelayMilliseconds);

public sealed record PcapSourceStreamFile(
    string File,
    bool HasActiveSourceFlow,
    string ClientEndpoint,
    string ServerEndpoint,
    int ServerPort,
    long ClientHelloPacketIndex,
    long ServerHelloPacketIndex,
    long FirstSourceClientPacketIndex,
    int SourcePacketCount,
    int ClientToServerPacketCount,
    int ServerToClientPacketCount,
    int MinPayloadLength,
    int MaxPayloadLength,
    double AveragePayloadLength,
    int LongestSameDirectionRun,
    long FirstSourcePacketIndex,
    long LastSourcePacketIndex,
    long FirstSourceTimestampMicroseconds,
    long LastSourceTimestampMicroseconds,
    double DurationMilliseconds,
    double AverageInterArrivalMilliseconds,
    double MaxInterArrivalMilliseconds,
    int DirectionSwitchCount,
    int TurnCount,
    int RespondedTurnCount,
    int MaxClientBurstPacketCount,
    int MaxServerResponsePacketCount,
    double AverageResponseDelayMilliseconds,
    double MaxResponseDelayMilliseconds,
    double MaxTurnDurationMilliseconds,
    PcapSourceFieldCandidate[] CandidateFields,
    PcapSourceStreamCount[] TopLengthCounts,
    PcapSourceStreamCount[] TopPrefixCounts,
    PcapSourceStreamCount[] ClientToServerTopPrefixCounts,
    PcapSourceStreamCount[] ServerToClientTopPrefixCounts,
    PcapSourceStreamTurn[] TurnSamples,
    PcapSourceStreamSample[] Samples);

public sealed record PcapSourceStreamCount(
    string Value,
    int Count);

public sealed record PcapSourceStreamTurn(
    int TurnIndex,
    int ClientPacketCount,
    int ServerPacketCount,
    long FirstPacketIndex,
    long LastPacketIndex,
    long FirstTimestampMicroseconds,
    long LastTimestampMicroseconds,
    double DurationMilliseconds,
    double ResponseDelayMilliseconds,
    int? FirstClientSequence,
    int? LastClientSequence,
    int? FirstServerSequence,
    int? LastServerSequence,
    int MinClientBodyLength,
    int MaxClientBodyLength,
    int MinServerBodyLength,
    int MaxServerBodyLength,
    string ClientBodySignature,
    string ServerBodySignature,
    string TurnBodySignature,
    string ClientShapeSignature,
    string ServerShapeSignature,
    PcapSourceStreamCount[] ClientShapeCounts,
    PcapSourceStreamCount[] ServerShapeCounts);

public sealed record PcapSourceStreamSample(
    long PacketIndex,
    long TimestampMicroseconds,
    string Direction,
    int Length,
    string Kind,
    int? CandidateSequence,
    int CandidateBodyLength,
    string HexPrefix,
    string AsciiPreview);

public sealed record PcapSourceFieldCandidate(
    string Direction,
    int Offset,
    int Width,
    string Endian,
    int PacketCount,
    int DistinctCount,
    ulong FirstValue,
    ulong LastValue,
    ulong MinValue,
    ulong MaxValue,
    int IncreaseCount,
    int SameCount,
    int DecreaseCount,
    double AverageAbsoluteDelta,
    ulong[] SampleValues);
