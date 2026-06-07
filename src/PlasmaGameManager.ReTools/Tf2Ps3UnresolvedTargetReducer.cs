using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Tf2Ps3UnresolvedTargetReducer
{
    public static async Task ReduceAsync(
        string dispatcherMapPath,
        string dataNeighborhoodPath,
        string anchorTablePath,
        string anchorContextMapPath,
        string readerFunctionMapPath,
        string helperCallerMapPath,
        string outputPath)
    {
        using var dispatcherDoc = JsonDocument.Parse(File.ReadAllText(dispatcherMapPath));
        using var dataDoc = JsonDocument.Parse(File.ReadAllText(dataNeighborhoodPath));
        using var anchorTableDoc = JsonDocument.Parse(File.ReadAllText(anchorTablePath));
        using var anchorContextDoc = JsonDocument.Parse(File.ReadAllText(anchorContextMapPath));
        using var readerDoc = JsonDocument.Parse(File.ReadAllText(readerFunctionMapPath));
        using var helperDoc = JsonDocument.Parse(File.ReadAllText(helperCallerMapPath));

        var rows = dispatcherDoc.RootElement.GetProperty("dispatcherRows").EnumerateArray()
            .Select(DispatcherRow.From)
            .ToArray();
        var remainingRoles = dispatcherDoc.RootElement.GetProperty("remainingNativeTargets").EnumerateArray()
            .Select(static target => GetString(target, "Role"))
            .Where(static role => role.Length > 0)
            .ToHashSet(StringComparer.Ordinal);
        var dataAnchors = dataDoc.RootElement.GetProperty("anchors").EnumerateArray()
            .Select(DataAnchor.From)
            .ToArray();
        var clusterWords = anchorTableDoc.RootElement.GetProperty("clusterWords").EnumerateArray()
            .Select(ClusterWord.From)
            .ToArray();
        var tableReads = anchorContextDoc.RootElement.GetProperty("tableReads").EnumerateArray()
            .Select(TableRead.From)
            .ToArray();
        var readerFunctions = readerDoc.RootElement.GetProperty("functions").EnumerateArray()
            .Select(ReaderFunction.From)
            .ToArray();
        var helperCallers = helperDoc.RootElement.GetProperty("callers").EnumerateArray()
            .Select(HelperCaller.From)
            .ToArray();

        var targets = rows
            .Where(row => remainingRoles.Contains(row.Role))
            .Select(row => BuildTarget(row, dataAnchors, clusterWords, tableReads, readerFunctions, helperCallers))
            .OrderByDescending(static target => target.PriorityRank)
            .ThenBy(static target => target.Role, StringComparer.Ordinal)
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-tf2ps3-unresolved-native-targets",
            note = "Prioritized recovery list for remaining TF2 PS3 GameManager roles. This does not promote a role; it names the concrete anchors, nearby table words, reader/helper evidence, and next Ghidra export work needed before promotion.",
            input = new
            {
                DispatcherMap = dispatcherMapPath,
                DataNeighborhood = dataNeighborhoodPath,
                AnchorTable = anchorTablePath,
                AnchorContextMap = anchorContextMapPath,
                ReaderFunctionMap = readerFunctionMapPath,
                HelperCallerMap = helperCallerMapPath
            },
            summary = new
            {
                TargetCount = targets.Length,
                HighPriorityTargets = targets.Count(static target => target.Priority == "high"),
                MediumPriorityTargets = targets.Count(static target => target.Priority == "medium"),
                LowPriorityTargets = targets.Count(static target => target.Priority == "low"),
                Roles = targets.Select(static target => target.Role).ToArray()
            },
            targets,
            exportPlan = new
            {
                AddressContextTargets = targets.SelectMany(static target => target.AddressContextTargets).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
                FunctionContextTargets = targets.SelectMany(static target => target.FunctionContextTargets).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
                HelperCallerTargets = targets.SelectMany(static target => target.HelperCallerTargets).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray()
            }
        }, JsonOptions));
    }

    private static UnresolvedTarget BuildTarget(
        DispatcherRow row,
        DataAnchor[] dataAnchors,
        ClusterWord[] clusterWords,
        TableRead[] tableReads,
        ReaderFunction[] readerFunctions,
        HelperCaller[] helperCallers)
    {
        var roleAnchors = dataAnchors.Where(anchor => anchor.Role == row.Role).ToArray();
        var anchorSlots = clusterWords
            .Where(word => word.Roles.Contains(row.Role, StringComparer.Ordinal))
            .Select(word => new AnchorSlot(
                word.Address,
                word.Value,
                word.Annotation,
                NeighborWords(clusterWords, word.Address)))
            .ToArray();
        var readerMatches = readerFunctions
            .Where(reader => reader.ReachesRoles.Contains(row.Role, StringComparer.Ordinal))
            .ToArray();
        var relatedReaders = RelatedReaders(row.Role, readerFunctions);
        var relatedHelpers = helperCallers
            .Where(helper => helper.DispatcherRole == row.Role || RelatedHelper(row.Role, helper.DispatcherRole))
            .ToArray();
        var addressTargets = RoleAddressContextTargets(row.Role, anchorSlots)
            .Concat(roleAnchors.Select(static anchor => anchor.StringAddress))
            .Where(static value => value.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var functionTargets = readerMatches.Select(static reader => reader.Entry)
            .Concat(relatedReaders.Select(static reader => reader.Entry))
            .Concat(relatedHelpers.Select(static helper => helper.Entry))
            .Where(static value => value.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();

        return new UnresolvedTarget(
            row.Role,
            row.EntryPointStatus,
            Priority(row.Role),
            PriorityRank(row.Role),
            row.PacketTypes,
            roleAnchors.Select(static anchor => new StringAnchor(anchor.StringAddress, anchor.StringValue, anchor.RefAddresses)).ToArray(),
            anchorSlots,
            tableReads.Where(read => anchorSlots.Any(slot => slot.Address == read.TableAddress)).ToArray(),
            readerMatches,
            relatedReaders,
            relatedHelpers,
            addressTargets,
            functionTargets,
            relatedHelpers.Select(static helper => helper.Entry).Where(static value => value.Length > 0).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
            NextWork(row.Role, anchorSlots, readerMatches, relatedHelpers));
    }

    private static ClusterNeighbor[] NeighborWords(ClusterWord[] words, string address)
    {
        var index = Array.FindIndex(words, word => word.Address == address);
        if (index < 0)
        {
            return Array.Empty<ClusterNeighbor>();
        }

        var start = Math.Max(0, index - 2);
        var end = Math.Min(words.Length - 1, index + 2);
        return words[start..(end + 1)]
            .Select(static word => new ClusterNeighbor(word.Address, word.Value, word.Annotation, word.Roles))
            .ToArray();
    }

    private static ReaderFunction[] RelatedReaders(string role, ReaderFunction[] readers)
    {
        return role switch
        {
            "receive-roster-ack" => readers.Where(static reader => reader.Entry is "015d1610" or "015d1988" or "015d0b48").ToArray(),
            "reservation-take" => readers.Where(static reader => reader.Entry is "015cfb58" or "015d4e20" or "015d5d50").ToArray(),
            "make-connection-id" => readers.Where(static reader => reader.HelperCalls.Contains("0158e430", StringComparer.Ordinal)).ToArray(),
            "player-inactivity-timeout" => readers.Where(static reader => reader.Entry is "015cfb58").ToArray(),
            _ => Array.Empty<ReaderFunction>()
        };
    }

    private static IEnumerable<string> RoleAddressContextTargets(string role, AnchorSlot[] anchorSlots)
    {
        foreach (var slot in anchorSlots)
        {
            yield return slot.Address;
        }

        if (role == "receive-roster-ack")
        {
            yield return "019c099c..019c09b0";
        }
    }

    private static bool RelatedHelper(string role, string dispatcherRole)
    {
        return (role, dispatcherRole) switch
        {
            ("receive-roster-element", "process-roster-notice-and-send-host-ack") => true,
            ("make-connection-id", "reservation-take") => true,
            ("make-connection-id", "reservation-or-session-bootstrap") => true,
            _ => false
        };
    }

    private static string Priority(string role)
    {
        return role switch
        {
            "reservation-take" or "receive-roster-ack" or "receive-roster-element" => "high",
            "make-connection-id" => "medium",
            _ => "low"
        };
    }

    private static int PriorityRank(string role)
    {
        return Priority(role) switch
        {
            "high" => 3,
            "medium" => 2,
            _ => 1
        };
    }

    private static string[] NextWork(string role, AnchorSlot[] anchorSlots, ReaderFunction[] readers, HelperCaller[] helpers)
    {
        var work = new List<string>();
        if (anchorSlots.Length > 0)
        {
            work.Add($"Export wider Ghidra address context around {string.Join(", ", anchorSlots.Select(static slot => slot.Address))} and its neighboring table words.");
        }

        if (role == "receive-roster-ack")
        {
            work.Add("Export the contiguous table window 019c099c..019c09b0 to catch TOC-relative/table dataflow around roster ack, join announcement, and the next full-mesh anchor.");
        }

        if (readers.Length > 0)
        {
            work.Add($"Export caller/callee context for reader candidate(s): {string.Join(", ", readers.Select(static reader => reader.Entry))}.");
        }

        if (helpers.Length > 0)
        {
            work.Add($"Use helper caller evidence from {string.Join(", ", helpers.Select(static helper => helper.Entry))} to bind table slot and field order.");
        }

        work.Add(role switch
        {
            "receive-roster-ack" => "Recover the exact inbound roster-ack function that drives native type 5 and addressed type 9 responses.",
            "receive-roster-element" => "Split roster-element receive from the already-recovered host-ack completion helper so both roles have implementation-ready entries.",
            "reservation-take" => "Decide whether 015d8580 is the true reservation/session bootstrap path or only adjacent bootstrap logic.",
            "make-connection-id" => "Recover callsites for the connident format string and target formatter helper instead of relying on raw string-pointer scans.",
            "player-inactivity-timeout" => "Recover timer/drop callsites for the no-activity warning string and decide whether it is needed for join/create acceptance.",
            _ => "Recover implementation-ready entry and field order."
        });
        return work.Distinct(StringComparer.Ordinal).ToArray();
    }

    private sealed record DispatcherRow(string Role, string EntryPointStatus, PacketType[] PacketTypes)
    {
        public static DispatcherRow From(JsonElement element)
        {
            return new DispatcherRow(
                GetString(element, "Role"),
                GetString(element, "EntryPointStatus"),
                element.GetProperty("PacketTypes").EnumerateArray()
                    .Select(static packet => new PacketType(packet.GetProperty("Type").GetInt32(), GetString(packet, "Meaning"), GetString(packet, "Source")))
                    .ToArray());
        }
    }

    private sealed record DataAnchor(string Role, string StringAddress, string StringValue, string[] RefAddresses)
    {
        public static DataAnchor From(JsonElement element)
        {
            return new DataAnchor(
                GetString(element, "Role"),
                GetString(element, "StringAddress"),
                GetString(element, "StringValue"),
                element.GetProperty("References").EnumerateArray()
                    .Select(static reference => GetString(reference, "RefAddress"))
                    .Where(static value => value.Length > 0)
                    .ToArray());
        }
    }

    private sealed record ClusterWord(string Address, string Value, string Annotation, string[] Roles)
    {
        public static ClusterWord From(JsonElement element)
        {
            return new ClusterWord(
                GetString(element, "Address"),
                GetString(element, "Value"),
                GetString(element, "Annotation"),
                element.GetProperty("RoleAnchors").EnumerateArray()
                    .Select(static role => GetString(role, "Role"))
                    .Where(static role => role.Length > 0)
                    .ToArray());
        }
    }

    private sealed record TableRead(string TableAddress, string TableValue, string ReaderFunction, string[] Roles)
    {
        public static TableRead From(JsonElement element)
        {
            return new TableRead(
                GetString(element, "TableAddress"),
                GetString(element, "TableValue"),
                GetString(element, "ReaderFunction"),
                element.GetProperty("Roles").EnumerateArray()
                    .Select(static role => role.GetString() ?? "")
                    .Where(static role => role.Length > 0)
                    .ToArray());
        }
    }

    private sealed record ReaderFunction(string Entry, string Role, string[] ReachesRoles, string[] ReachesPacketTypes, string[] HelperCalls)
    {
        public static ReaderFunction From(JsonElement element)
        {
            return new ReaderFunction(
                GetString(element, "Entry"),
                GetString(element, "Role"),
                ReadStringArray(element, "ReachesRoles"),
                element.GetProperty("ReachesPacketTypes").EnumerateArray().Select(static value => value.GetInt32().ToString()).ToArray(),
                ReadStringArray(element, "HelperCalls"));
        }
    }

    private sealed record HelperCaller(string Entry, string Role, string DispatcherRole, string Confidence, string[] MatchedExpectedCallees, string[] SlotEvidence)
    {
        public static HelperCaller From(JsonElement element)
        {
            return new HelperCaller(
                GetString(element, "Entry"),
                GetString(element, "Role"),
                GetString(element, "DispatcherRole"),
                GetString(element, "Confidence"),
                ReadStringArray(element, "MatchedExpectedCallees"),
                ReadStringArray(element, "SlotEvidence"));
        }
    }

    private sealed record UnresolvedTarget(
        string Role,
        string EntryPointStatus,
        string Priority,
        int PriorityRank,
        PacketType[] PacketTypes,
        StringAnchor[] StringAnchors,
        AnchorSlot[] AnchorSlots,
        TableRead[] DirectTableReads,
        ReaderFunction[] MatchingReaderFunctions,
        ReaderFunction[] RelatedReaderCandidates,
        HelperCaller[] RelatedHelperCallers,
        string[] AddressContextTargets,
        string[] FunctionContextTargets,
        string[] HelperCallerTargets,
        string[] NextWork);

    private sealed record PacketType(int Type, string Meaning, string Source);
    private sealed record StringAnchor(string StringAddress, string StringValue, string[] RefAddresses);
    private sealed record AnchorSlot(string Address, string Value, string Annotation, ClusterNeighbor[] Neighbors);
    private sealed record ClusterNeighbor(string Address, string Value, string Annotation, string[] Roles);

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

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}
