using System.Text.Json;
using System.Text.RegularExpressions;

namespace PlasmaGameManager.ReTools;

public static class Tf2Ps3SourceNetworkAnchorReducer
{
    private static readonly Regex CalleeRegex = new(@"(?:_opd_FUN_|FUN_)([0-9a-f]{8})\(", RegexOptions.Compiled);
    private static readonly Regex HexConstantRegex = new(@"0x[0-9a-fA-F]+", RegexOptions.Compiled);
    private static readonly Regex SocketApiRegex = new(@"\b(?:socket|bind|connect|listen|accept|send|sendto|recv|recvfrom|setsockopt|socketselect|gethostbyname|inet_addr)\(", RegexOptions.Compiled);
    private static readonly Regex GlobalRegex = new(@"\b(?:PTR|DAT|_PTR)[A-Za-z0-9_]*_[0-9a-fA-F]{8}\b", RegexOptions.Compiled);
    private static readonly Regex FieldOffsetRegex = new(@"\+\s*(0x[0-9a-fA-F]+)\)", RegexOptions.Compiled);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private static readonly FunctionTarget[] Targets =
    [
        new("000abdb8", "source-player-slot-lookup", "source-client-state", ["PTR_s_unconnected", "param_1 + -0x478"]),
        new("000ac5b8", "source-player-slot-state-update", "source-client-state", ["PTR_s_unconnected", "param_1 + -0xc"]),
        new("00721800", "tcp-connect-helper", "tcp-control-helper", ["socket(2,1,6)", "setsockopt", "connect", "socketselect"]),
        new("00803418", "tcp-send-state", "tcp-control-helper", ["send(", "_opd_FUN_00802ff0(param_1,7)"]),
        new("008034d0", "tcp-connect-state", "tcp-control-helper", ["connect(", "_opd_FUN_00802ff0(param_1,2)"]),
        new("00803580", "tcp-open-state", "tcp-control-helper", ["socket(2,1,6)", "_opd_FUN_00802ff0(param_1,1)"]),
        new("008b8068", "udp-sendto-wrapper", "udp-gameplay-send-path", ["sendto", "param_3", "param_5"]),
        new("008b82c0", "connected-socket-recv-wrapper", "connected-gameplay-helper", ["recv(", "_opd_FUN_008b8288", "0x23"]),
        new("008b8668", "udp-socket-open-bind", "udp-gameplay-socket", ["socket(2,2,0x11)", "setsockopt", "bind", "0x17710"]),
        new("008b8d50", "udp-gameplay-drain-recvfrom", "udp-gameplay-socket", ["recvfrom", "0x800", "0x80", "PTR_DAT_0197336c"]),
        new("008b8e70", "udp-gameplay-connect-socket", "udp-gameplay-socket", ["connect(", "_opd_FUN_008b8668", "FUN_0086c5d8"]),
        new("008b9468", "accepted-peer-short-control-reader", "connected-gameplay-helper", ["_opd_FUN_008b82c0", "auStack_b0,5", "FUN_0086de68"]),
        new("008b9f70", "source-payload-queue", "source-gameplay-queue", ["0x17701", "0x801", "0x808", "FUN_00871708"]),
        new("008bc490", "fragmented-source-send", "udp-gameplay-send-path", ["_opd_FUN_008bb058", "uVar16 + 10", "0x80"]),
        new("008bc978", "source-send-packet-builder", "udp-gameplay-send-path", ["_opd_FUN_008bc490", "_opd_FUN_008bb058", "0x1000", "param_7"]),
        new("016cadd0", "source-object-pool-unconnected-state", "source-client-state", ["PTR_s_unconnected", "0x74", "0x7c"])
    ];

    private static readonly string[] NegativeStringTerms =
    [
        "MOTD",
        "motd",
        "netchan",
        "Netchan",
        "NET_",
        "SVC_",
        "CLC_",
        "bf_read",
        "bf_write",
        "Source Engine Query",
        "challenge",
        "signon",
        "Signon"
    ];

    private static readonly string[] PositiveStringTerms =
    [
        "unconnected",
        "player_connect",
        "player_disconnect",
        "recvfrom",
        "connect("
    ];

    public static async Task ReduceAsync(string cExportPath, string outputPath)
    {
        var lines = File.ReadAllLines(cExportPath);
        var text = string.Join('\n', lines);
        var functions = Targets.Select(target => BuildFunctionAnchor(lines, target)).ToArray();
        var stringEvidence = NegativeStringTerms
            .Select(term => BuildStringEvidence(text, term, expectedPresent: false))
            .Concat(PositiveStringTerms.Select(term => BuildStringEvidence(text, term, expectedPresent: true)))
            .OrderBy(static evidence => evidence.Term, StringComparer.Ordinal)
            .ToArray();

        var udpCluster = functions.Where(static function => function.Category == "udp-gameplay-socket").ToArray();
        var tcpCluster = functions.Where(static function => function.Category == "tcp-control-helper").ToArray();
        var sendPath = functions.Where(static function => function.Category == "udp-gameplay-send-path").ToArray();
        var gameplayHelpers = functions.Where(static function => function.Category == "connected-gameplay-helper").ToArray();
        var nativeTransportEvidence = BuildNativeTransportEvidence(functions);
        var report = new
        {
            status = "seeded-from-tf2ps3-c-export-source-network-anchors",
            note = "Reduces the exported TF.elf C decompile into Source/GameManager handoff anchors. This separates low-level TCP helper code from the UDP gameplay socket cluster and records negative string evidence for PC-style Source transport names that are absent from the PS3 export.",
            input = new
            {
                CExport = cExportPath
            },
            summary = new
            {
                FunctionCount = functions.Length,
                LocatedFunctionCount = functions.Count(static function => function.Located),
                UdpGameplaySocketFunctionCount = udpCluster.Count(static function => function.Located),
                TcpControlHelperFunctionCount = tcpCluster.Count(static function => function.Located),
                UdpGameplaySendPathFunctionCount = sendPath.Count(static function => function.Located),
                ConnectedGameplayHelperFunctionCount = gameplayHelpers.Count(static function => function.Located),
                HasUdpGameplaySocketCluster = udpCluster.All(static function => function.Located && function.EvidenceScore >= 3),
                HasSeparateTcpControlCluster = tcpCluster.Count(static function => function.Located && function.EvidenceScore >= 2) >= 3,
                HasNativeSourceSendBuilder = sendPath.Any(static function => function.Role == "source-send-packet-builder" && function.EvidenceScore >= 3),
                HasNativePayloadQueue = functions.Any(static function => function.Role == "source-payload-queue" && function.EvidenceScore >= 3),
                MissingPcSourceStringTerms = stringEvidence.Count(static evidence => !evidence.ExpectedPresent && evidence.Count == 0),
                PresentAnchorStringTerms = stringEvidence.Count(static evidence => evidence.ExpectedPresent && evidence.Count > 0)
            },
            conclusion = new
            {
                SourceVisibilityModel = "ps3-visible-gamemanager-gameserver-udp-endpoint-with-private-source-backend-bridge",
                EstablishedTransportField = "PCAP evidence supports a big-endian u16 sequence-like field at payload offset 0 in post-handoff Source/gameplay traffic.",
                Tf2ElfAnchor = "008b8d50/008b8e70 are the current TF.elf low-level UDP gameplay socket anchors; the TCP helpers are separate control paths and should not drive the Source backend bridge.",
                NativeSourceSendModel = "TF.elf has a native binary Source/gameplay send builder at 008bc978 which stages data in 0x1000 buffers, optionally wraps/combines bit payloads, then sends via 008bb058 or fragmented 008bc490. This is not a classic PC connectionless srcds packet path.",
                NativeSourceQueueModel = "TF.elf queues source payloads through 008b9f70; payloads below 0x801 bytes use an inline 0x808 allocation, while larger payloads allocate by requested size up to the observed 0x17701/96000 ceiling.",
                NegativeEvidence = "The C export does not contain PC Source names such as netchan, SVC_, CLC_, MOTD, bf_read, or bf_write, so string matching against PC Source transport names is not enough for this PS3 build."
            },
            nativeTransportEvidence,
            stringEvidence,
            functions
        };

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, JsonOptions));
    }

    private static FunctionAnchor BuildFunctionAnchor(string[] lines, FunctionTarget target)
    {
        var start = FindDefinitionLine(lines, target.Entry);
        if (start < 0)
        {
            return new FunctionAnchor(
                target.Entry,
                target.Role,
                target.Category,
                false,
                0,
                [],
                [],
                [],
                [],
                [],
                "",
                "missing-from-export");
        }

        var bodyLines = ExtractFunctionLines(lines, start);
        var body = string.Join('\n', bodyLines);
        var matched = target.RequiredTokens
            .Where(token => body.Contains(token, StringComparison.Ordinal))
            .ToArray();

        return new FunctionAnchor(
            target.Entry,
            target.Role,
            target.Category,
            true,
            matched.Length,
            matched,
            ExtractDistinctMatches(body, CalleeRegex, match => match.Value.TrimEnd('(')),
            ExtractDistinctMatches(body, SocketApiRegex, match => match.Value.TrimEnd('(')),
            ExtractDistinctMatches(body, HexConstantRegex, match => match.Value.ToLowerInvariant()),
            ExtractDistinctMatches(body, GlobalRegex, match => match.Value),
            Preview(bodyLines),
            ClassifyConclusion(target, matched.Length));
    }

    private static int FindDefinitionLine(string[] lines, string entry)
    {
        var marker = "_opd_FUN_" + entry;
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Length == 0 || char.IsWhiteSpace(line[0]))
            {
                continue;
            }

            if (line.Contains(marker + "(", StringComparison.Ordinal))
            {
                return i;
            }
        }

        return -1;
    }

    private static string[] ExtractFunctionLines(string[] lines, int start)
    {
        var end = lines.Length;
        for (var i = start + 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Length == 0 || char.IsWhiteSpace(line[0]))
            {
                continue;
            }

            if (line.Contains("_opd_FUN_", StringComparison.Ordinal) && line.Contains('(', StringComparison.Ordinal))
            {
                end = i;
                break;
            }
        }

        return lines[start..end];
    }

    private static string Preview(string[] lines)
    {
        return string.Join('\n', lines
            .Where(static line => !string.IsNullOrWhiteSpace(line))
            .Take(18));
    }

    private static string ClassifyConclusion(FunctionTarget target, int evidenceScore)
    {
        return target.Category switch
        {
            "udp-gameplay-socket" when evidenceScore >= 3 => "primary-post-handoff-udp-anchor",
            "udp-gameplay-send-path" when evidenceScore >= 3 => "native-ps3-source-send-path",
            "source-gameplay-queue" when evidenceScore >= 3 => "native-ps3-source-payload-queue",
            "connected-gameplay-helper" when evidenceScore >= 2 => "connected-gameplay-helper",
            "tcp-control-helper" when evidenceScore >= 2 => "separate-tcp-control-helper",
            "source-client-state" when evidenceScore >= 1 => "source-client-state-anchor",
            _ => "needs-more-context"
        };
    }

    private static NativeTransportEvidence[] BuildNativeTransportEvidence(FunctionAnchor[] functions)
    {
        var byRole = functions.ToDictionary(static function => function.Role, StringComparer.Ordinal);
        return
        [
            new(
                "udp-socket-table",
                "TF.elf stores per-slot UDP sockets in the PTR_DAT_0197336c table: +0xe8 points at 0x10-byte slot records, +0xf4 is the slot count, +8 is the recvfrom socket, and +0xc is the connected/opened socket.",
                SelectEntries(byRole, "udp-gameplay-drain-recvfrom", "udp-gameplay-connect-socket", "udp-socket-open-bind"),
                ["PTR_DAT_0197336c", "0xe8", "0xf4", "0x10", "0x8", "0xc"]),
            new(
                "udp-open-bind-connect",
                "The native open path creates UDP sockets with socket(2,2,0x11), sets PS3 socket options including 0x1100/0x20 and 0x1001/0x1002 timeouts, binds, then 008b8e70 connects the slot socket to the peer sockaddr.",
                SelectEntries(byRole, "udp-socket-open-bind", "udp-gameplay-connect-socket"),
                ["socket(2,2,0x11)", "setsockopt", "0x1100", "0x20", "0x1001", "0x1002", "0x17710", "bind", "connect"]),
            new(
                "ps3-source-send-builder",
                "The native send path at 008bc978 copies the address, stages payload data in 0x1000 buffers, adds optional bit payload wrapping, and selects direct 008bb058 or fragmented 008bc490 sending based on the configured transport threshold.",
                SelectEntries(byRole, "source-send-packet-builder", "fragmented-source-send", "udp-sendto-wrapper"),
                ["0x1000", "0x10", "param_7", "_opd_FUN_008bb058", "_opd_FUN_008bc490", "sendto"]),
            new(
                "ps3-source-payload-queue",
                "Payload queueing uses 008b9f70. Captured medium packets line up with the inline 0x808 allocation for sizes below 0x801, while larger packets use heap allocation up to the 0x17701/96000 byte ceiling.",
                SelectEntries(byRole, "source-payload-queue"),
                ["0x801", "0x808", "0x17701", "96000"]),
            new(
                "connected-short-control-reader",
                "The connected helper path reads short 5-byte controls from accepted sockets via 008b82c0/recv and parses them with FUN_0086de68 before associating them with a Source player object.",
                SelectEntries(byRole, "accepted-peer-short-control-reader", "connected-socket-recv-wrapper"),
                ["_opd_FUN_008b82c0", "recv", "5", "FUN_0086de68"])
        ];
    }

    private static string[] SelectEntries(IReadOnlyDictionary<string, FunctionAnchor> byRole, params string[] roles)
    {
        return roles
            .Select(role => byRole.TryGetValue(role, out var function) && function.Located ? function.Entry : "")
            .Where(static entry => entry.Length > 0)
            .ToArray();
    }

    private static string[] ExtractDistinctMatches(string body, Regex regex, Func<Match, string> selector)
    {
        return regex.Matches(body)
            .Select(selector)
            .Where(static value => value.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static value => value, StringComparer.Ordinal)
            .Take(32)
            .ToArray();
    }

    private static StringEvidence BuildStringEvidence(string text, string term, bool expectedPresent)
    {
        var count = CountOccurrences(text, term);
        return new StringEvidence(
            term,
            count,
            expectedPresent,
            expectedPresent
                ? count > 0 ? "present-anchor" : "missing-expected-anchor"
                : count == 0 ? "absent-negative-evidence" : "present-review-needed");
    }

    private static int CountOccurrences(string text, string term)
    {
        var count = 0;
        var index = 0;
        while (true)
        {
            index = text.IndexOf(term, index, StringComparison.Ordinal);
            if (index < 0)
            {
                return count;
            }

            count++;
            index += term.Length;
        }
    }
}

public sealed record FunctionTarget(
    string Entry,
    string Role,
    string Category,
    string[] RequiredTokens);

public sealed record FunctionAnchor(
    string Entry,
    string Role,
    string Category,
    bool Located,
    int EvidenceScore,
    string[] EvidenceTokens,
    string[] Callees,
    string[] SocketApiCalls,
    string[] HexConstants,
    string[] Globals,
    string SnippetPreview,
    string Conclusion);

public sealed record StringEvidence(
    string Term,
    int Count,
    bool ExpectedPresent,
    string Assessment);

public sealed record NativeTransportEvidence(
    string Name,
    string Finding,
    string[] FunctionEntries,
    string[] Evidence);
