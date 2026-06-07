using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public sealed class LiveSourceTurnContractMatcher
{
    public async Task<LiveSourceTurnContractMatchReport> MatchAsync(
        string eventLogPath,
        string contractPath,
        string outputPath)
    {
        var report = Match(eventLogPath, contractPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, JsonOptions));
        return report;
    }

    public LiveSourceTurnContractMatchReport Match(string eventLogPath, string contractPath)
    {
        var contract = JsonSerializer.Deserialize<PcapSourceTurnContractReport>(File.ReadAllText(contractPath))
            ?? throw new InvalidOperationException($"Unable to read source turn contract: {contractPath}");
        var candidates = BuildCandidateMap(contract);
        var events = ReadEvents(eventLogPath);
        var turns = BuildLiveTurns(events);
        var matches = turns.Select(turn => MatchTurn(turn, candidates)).ToArray();
        var exact = matches.Count(static match => match.MatchStatus == "matched");
        var ambiguous = matches.Count(static match => match.MatchStatus == "ambiguous");
        var unmatched = matches.Count(static match => match.MatchStatus == "unmatched");

        return new LiveSourceTurnContractMatchReport(
            "live-source-turn-contract-match",
            eventLogPath,
            contractPath,
            contract.Summary.TurnCount,
            candidates.Count,
            turns.Length,
            exact,
            ambiguous,
            unmatched,
            unmatched == 0 && ambiguous == 0 && turns.Length > 0 ? "matched" : "needs-investigation",
            matches);
    }

    private static Dictionary<string, PcapSourceTurnContractCandidate[]> BuildCandidateMap(PcapSourceTurnContractReport contract)
    {
        return contract.Files
            .Where(static file => file.HasActiveSourceFlow)
            .SelectMany(static file => file.SampleTurns.Select(turn => new PcapSourceTurnContractCandidate(
                file.File,
                turn.TurnIndex,
                turn.ClientPacketCount,
                turn.ServerResponsePacketCount,
                turn.ClientBodySignature,
                turn.ServerBodySignature,
                turn.TurnBodySignature,
                turn.ClientPacketBodySignatures,
                turn.ServerResponseBodySignatures)))
            .GroupBy(static candidate => SignatureKey(candidate.ClientPacketBodySignatures), StringComparer.Ordinal)
            .ToDictionary(
                static group => group.Key,
                static group => group.ToArray(),
                StringComparer.Ordinal);
    }

    private static LiveSourceTurnContractMatch MatchTurn(
        LiveSourceTurn turn,
        IReadOnlyDictionary<string, PcapSourceTurnContractCandidate[]> candidates)
    {
        var key = SignatureKey(turn.ClientPacketBodySignatures);
        if (!candidates.TryGetValue(key, out var matches))
        {
            return new LiveSourceTurnContractMatch(
                turn.TurnIndex,
                turn.ClientPacketCount,
                turn.ServerResponsePacketCount,
                turn.FirstEventIndex,
                turn.LastEventIndex,
                "unmatched",
                "",
                null,
                Array.Empty<PcapSourceTurnContractCandidate>());
        }

        var status = matches.Length == 1 ? "matched" : "ambiguous";
        return new LiveSourceTurnContractMatch(
            turn.TurnIndex,
            turn.ClientPacketCount,
            turn.ServerResponsePacketCount,
            turn.FirstEventIndex,
            turn.LastEventIndex,
            status,
            matches[0].ServerBodySignature,
            matches[0],
            matches.Length == 1 ? Array.Empty<PcapSourceTurnContractCandidate>() : matches);
    }

    private static LiveSourceTurn[] BuildLiveTurns(LiveSourceEvent[] events)
    {
        var preferProxyForward = events.Any(static e => e.Event == "source-proxy-forward");
        var clientEvents = preferProxyForward
            ? new HashSet<string>(["source-proxy-forward"], StringComparer.Ordinal)
            : new HashSet<string>(["source-traffic"], StringComparer.Ordinal);
        var serverEvents = new HashSet<string>(["source-proxy-send", "source-send"], StringComparer.Ordinal);
        var turns = new List<LiveSourceTurn>();
        var clientSignatures = new List<string>();
        var serverSignatures = new List<string>();
        var turnIndex = 0;
        var firstEventIndex = -1;
        var lastEventIndex = -1;
        var sawServerForCurrentTurn = false;

        foreach (var item in events)
        {
            if (item.SourceBodySignature.Length == 0)
            {
                continue;
            }

            if (clientEvents.Contains(item.Event))
            {
                if (clientSignatures.Count > 0 && sawServerForCurrentTurn)
                {
                    turns.Add(new LiveSourceTurn(
                        turnIndex++,
                        clientSignatures.Count,
                        serverSignatures.Count,
                        firstEventIndex,
                        lastEventIndex,
                        clientSignatures.ToArray(),
                        serverSignatures.ToArray()));
                    clientSignatures.Clear();
                    serverSignatures.Clear();
                    sawServerForCurrentTurn = false;
                    firstEventIndex = -1;
                }

                if (firstEventIndex < 0)
                {
                    firstEventIndex = item.EventIndex;
                }

                clientSignatures.Add(item.SourceBodySignature);
                lastEventIndex = item.EventIndex;
                continue;
            }

            if (serverEvents.Contains(item.Event) && clientSignatures.Count > 0)
            {
                serverSignatures.Add(item.SourceBodySignature);
                sawServerForCurrentTurn = true;
                lastEventIndex = item.EventIndex;
            }
        }

        if (clientSignatures.Count > 0)
        {
            turns.Add(new LiveSourceTurn(
                turnIndex,
                clientSignatures.Count,
                serverSignatures.Count,
                firstEventIndex,
                lastEventIndex,
                clientSignatures.ToArray(),
                serverSignatures.ToArray()));
        }

        return turns.ToArray();
    }

    private static LiveSourceEvent[] ReadEvents(string path)
    {
        if (!File.Exists(path))
        {
            return Array.Empty<LiveSourceEvent>();
        }

        var result = new List<LiveSourceEvent>();
        var index = 0;
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            result.Add(new LiveSourceEvent(
                index++,
                ReadString(root, "Event"),
                ReadString(root, "Endpoint"),
                ReadString(root, "SourceBodySignature")));
        }

        return result.ToArray();
    }

    private static string SignatureKey(IReadOnlyList<string> signatures)
    {
        return string.Join('\n', signatures);
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

internal sealed record LiveSourceEvent(
    int EventIndex,
    string Event,
    string Endpoint,
    string SourceBodySignature);

public sealed record LiveSourceTurn(
    int TurnIndex,
    int ClientPacketCount,
    int ServerResponsePacketCount,
    int FirstEventIndex,
    int LastEventIndex,
    string[] ClientPacketBodySignatures,
    string[] ServerResponseBodySignatures);

public sealed record PcapSourceTurnContractCandidate(
    string File,
    int TurnIndex,
    int ClientPacketCount,
    int ServerResponsePacketCount,
    string ClientBodySignature,
    string ServerBodySignature,
    string TurnBodySignature,
    string[] ClientPacketBodySignatures,
    string[] ServerResponseBodySignatures);

public sealed record LiveSourceTurnContractMatch(
    int LiveTurnIndex,
    int ClientPacketCount,
    int ServerResponsePacketCount,
    int FirstEventIndex,
    int LastEventIndex,
    string MatchStatus,
    string ExpectedServerBodySignature,
    PcapSourceTurnContractCandidate? BestMatch,
    PcapSourceTurnContractCandidate[] AmbiguousMatches);

public sealed record LiveSourceTurnContractMatchReport(
    string Status,
    string EventLogPath,
    string ContractPath,
    int ContractTurnCount,
    int ContractCandidateKeyCount,
    int LiveTurnCount,
    int MatchedTurnCount,
    int AmbiguousTurnCount,
    int UnmatchedTurnCount,
    string GateStatus,
    LiveSourceTurnContractMatch[] Matches);
