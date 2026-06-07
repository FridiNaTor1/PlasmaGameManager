using System.Text.Json;
using System.Text.RegularExpressions;

namespace PlasmaGameManager.ReTools;

public static partial class Tf2Ps3UnresolvedFunctionContextReducer
{
    public static async Task ReduceAsync(string functionContextPath, string unresolvedTargetsPath, string outputPath)
    {
        using var functionDoc = JsonDocument.Parse(File.ReadAllText(functionContextPath));
        using var targetDoc = JsonDocument.Parse(File.ReadAllText(unresolvedTargetsPath));

        var targets = targetDoc.RootElement.GetProperty("targets").EnumerateArray()
            .Select(UnresolvedTarget.From)
            .ToArray();
        var functions = functionDoc.RootElement.GetProperty("functions").EnumerateArray()
            .Select(DecompiledFunction.From)
            .Select(function => Classify(function, targets))
            .OrderBy(static function => function.Entry, StringComparer.Ordinal)
            .ToArray();
        var rosterAckConclusion = BuildRosterAckConclusion(targets);

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-tf2ps3-unresolved-function-context",
            note = "Reduces raw Ghidra decompiles for unresolved TF2 GameManager target functions. This report records both positive and negative evidence so unresolved roles are not promoted from adjacent cleanup/timer/control paths.",
            input = new
            {
                FunctionContext = functionContextPath,
                UnresolvedTargets = unresolvedTargetsPath
            },
            summary = new
            {
                FunctionCount = functions.Length,
                ConfirmedNegativeForRosterAck = functions.Count(static function => function.RosterAckAssessment == "negative"),
                CandidateForRosterAck = functions.Count(static function => function.RosterAckAssessment == "candidate"),
                CurrentHighPriorityRoles = targets.Where(static target => target.Priority == "high").Select(static target => target.Role).ToArray(),
                RemainingRoles = targets.Select(static target => target.Role).ToArray()
            },
            functions,
            rosterAckConclusion
        }, JsonOptions));
    }

    private static object BuildRosterAckConclusion(UnresolvedTarget[] targets)
    {
        if (!targets.Any(static target => target.Role == "receive-roster-ack"))
        {
            return new
            {
                Status = "resolved-outside-current-target-set",
                Reason = "receive-roster-ack is no longer in unresolved-targets.json; dispatcher coverage is now supplied by caller-context evidence for 015d5d50.",
                NextTargets = Array.Empty<string>()
            };
        }

        return new
        {
            Status = "unresolved",
            Reason = "Current exported function context does not show a TF2 function that receives roster ack and directly drives native type 5 plus addressed type 9. 015d0b48 is leave cleanup/mesh refresh, while 015d1610 and 015d1988 emit type 0x16 control broadcasts.",
            NextTargets = new[] { "019c09a4", "019c09a8", "100df900", "100df930", "015d0b48", "015d1610", "015d1988" }
        };
    }

    private static FunctionContextRow Classify(DecompiledFunction function, UnresolvedTarget[] targets)
    {
        var callees = Callees(function.Body);
        var packetBuilders = PacketBuilders(function.Body);
        var logTokens = LogTokens(function.Body);
        var slotEvidence = SlotEvidence(function.Body);
        var targetRoles = targets
            .Where(target => target.FunctionContextTargets.Contains(function.Entry, StringComparer.Ordinal)
                || target.HelperCallerTargets.Contains(function.Entry, StringComparer.Ordinal))
            .Select(static target => target.Role)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();

        var role = function.Entry switch
        {
            "015d0b48" => "leave-cleanup-and-mesh-refresh",
            "015d1610" => "state-five-control-broadcast-after-cleanup",
            "015d1988" => "timeout-or-delayed-state-five-control-broadcast",
            "015d5d50" => "received-join-build-and-propagate-player-join",
            "015d5fa0" => "roster-element-counter-and-host-ack",
            "015cfb58" => "host-property-update-reader",
            "015d4e20" => "connection-established-associate-peer-and-send-mesh",
            "015d8580" => "reservation-take-and-session-bootstrap",
            _ => "unclassified-unresolved-context"
        };

        var rosterAckAssessment = AssessRosterAck(function.Entry, packetBuilders, logTokens, callees);
        return new FunctionContextRow(
            function.Entry,
            function.Name,
            role,
            targetRoles,
            rosterAckAssessment,
            RosterAckReason(function.Entry, rosterAckAssessment),
            packetBuilders,
            logTokens,
            callees,
            slotEvidence,
            function.Body.Length);
    }

    private static string AssessRosterAck(string entry, PacketBuilder[] packetBuilders, string[] logTokens, string[] callees)
    {
        var types = packetBuilders.Select(static builder => builder.Type).ToHashSet();
        var hasRosterAckLogs = logTokens.Any(static log => log.Contains("Received_roster_ack", StringComparison.Ordinal)
            || log.Contains("Sent_join_announcement", StringComparison.Ordinal));
        if (hasRosterAckLogs && types.Contains(5) && types.Contains(9))
        {
            return "candidate";
        }

        return entry switch
        {
            "015d0b48" => "negative",
            "015d1610" or "015d1988" => "negative",
            _ when callees.Contains("015d0718", StringComparer.Ordinal) && !hasRosterAckLogs => "adjacent",
            _ => "not-targeted"
        };
    }

    private static string RosterAckReason(string entry, string assessment)
    {
        return (entry, assessment) switch
        {
            ("015d0b48", "negative") => "Builds type 10 leave announcement, performs player/list cleanup, then calls the known mesh sender 015d0718; it does not log roster ack or build type 5/9 directly.",
            ("015d1610", "negative") => "Calls cleanup and emits native type 0x16 through vtable +0xac after forcing state 5; this is a control/timer path, not the roster-ack receive path.",
            ("015d1988", "negative") => "Timeout/delayed variant of 015d1610 using counters 0x31e, 0x65, 0x62, and 0x6d; it also emits type 0x16, not type 5/9.",
            (_, "adjacent") => "Adjacent to mesh/join flow through helper calls, but missing roster-ack log and direct type 5/9 builder evidence.",
            (_, "candidate") => "Contains roster-ack/join-announcement logs and native type 5/9 builders.",
            _ => "No current roster-ack evidence."
        };
    }

    private static PacketBuilder[] PacketBuilders(string body)
    {
        var builders = new List<PacketBuilder>();
        foreach (Match match in TypedBuilderRegex().Matches(body))
        {
            builders.Add(new PacketBuilder("0158d800", ParseType(match.Groups[1].Value)));
        }

        foreach (Match match in AddressedBuilderRegex().Matches(body))
        {
            builders.Add(new PacketBuilder("0158d8c0", ParseType(match.Groups[1].Value)));
        }

        return builders
            .Distinct()
            .OrderBy(static builder => builder.Type)
            .ThenBy(static builder => builder.Helper, StringComparer.Ordinal)
            .ToArray();
    }

    private static int ParseType(string value)
    {
        return value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? Convert.ToInt32(value[2..], 16)
            : int.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string[] LogTokens(string body)
    {
        return LogTokenRegex().Matches(body)
            .Select(static match => match.Value)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    private static string[] SlotEvidence(string body)
    {
        return new[] { "0x31e", "0x65", "0x62", "0x6d", "0x5d", "0x5f", "0x85", "0x86", "0xac", "0xb4", "0xd0" }
            .Where(marker => body.Contains(marker, StringComparison.Ordinal))
            .ToArray();
    }

    private static string[] Callees(string body)
    {
        var helpers = new HashSet<string>(StringComparer.Ordinal);
        for (var index = body.IndexOf("FUN_", StringComparison.Ordinal); index >= 0; index = body.IndexOf("FUN_", index + 4, StringComparison.Ordinal))
        {
            if (index + 12 > body.Length)
            {
                continue;
            }

            var candidate = body.Substring(index + 4, 8);
            if (candidate.All(static c => char.IsDigit(c) || c is >= 'a' and <= 'f'))
            {
                helpers.Add(candidate);
            }
        }

        return helpers.Order(StringComparer.Ordinal).ToArray();
    }

    private sealed record DecompiledFunction(string Entry, string Name, string Body)
    {
        public static DecompiledFunction From(JsonElement element)
        {
            return new DecompiledFunction(
                GetString(element, "entry"),
                GetString(element, "name"),
                GetString(element, "body"));
        }
    }

    private sealed record UnresolvedTarget(string Role, string Priority, string[] FunctionContextTargets, string[] HelperCallerTargets)
    {
        public static UnresolvedTarget From(JsonElement element)
        {
            return new UnresolvedTarget(
                GetString(element, "Role"),
                GetString(element, "Priority"),
                ReadStringArray(element, "FunctionContextTargets"),
                ReadStringArray(element, "HelperCallerTargets"));
        }
    }

    private sealed record FunctionContextRow(
        string Entry,
        string Name,
        string Role,
        string[] TargetRoles,
        string RosterAckAssessment,
        string RosterAckReason,
        PacketBuilder[] PacketBuilders,
        string[] LogTokens,
        string[] Callees,
        string[] SlotEvidence,
        int BodyLength);

    private sealed record PacketBuilder(string Helper, int Type);

    private static string GetString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) ? value.GetString() ?? "" : "";
    }

    private static string[] ReadStringArray(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value)
            ? value.EnumerateArray()
                .Select(static item => item.GetString() ?? "")
                .Where(static item => item.Length > 0)
                .ToArray()
            : Array.Empty<string>();
    }

    [GeneratedRegex(@"_opd_FUN_0158d800\([^,\n]+,\s*(0x[0-9a-fA-F]+|\d+)\)")]
    private static partial Regex TypedBuilderRegex();

    [GeneratedRegex(@"_opd_FUN_0158d8c0\([^,\n]+,\s*(0x[0-9a-fA-F]+|\d+)")]
    private static partial Regex AddressedBuilderRegex();

    [GeneratedRegex(@"PTR_s_[A-Za-z0-9_]+")]
    private static partial Regex LogTokenRegex();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}
