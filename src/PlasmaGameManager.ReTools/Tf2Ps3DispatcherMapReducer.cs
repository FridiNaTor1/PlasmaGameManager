using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Tf2Ps3DispatcherMapReducer
{
    private static readonly string[] RequiredJoinRoles =
    {
        "reservation-take",
        "send-roster",
        "receive-roster-ack",
        "receive-roster-element",
        "process-roster-notice-and-send-host-ack",
        "send-join-mesh-announcement",
        "send-peer-mesh-to-host",
        "receive-full-mesh",
        "player-inactivity-timeout"
    };

    private static readonly string[] RecoveredEntryStatuses =
    {
        "direct-decompiled",
        "caller-context-resolved"
    };

    public static async Task ReduceAsync(
        string handlerMapPath,
        string dataNeighborhoodPath,
        string bfbc2DispatcherPath,
        string outputPath,
        string helperCallerMapPath = "")
    {
        using var handlerDoc = JsonDocument.Parse(File.ReadAllText(handlerMapPath));
        using var dataDoc = JsonDocument.Parse(File.ReadAllText(dataNeighborhoodPath));
        using var bfbc2Doc = JsonDocument.Parse(File.ReadAllText(bfbc2DispatcherPath));

        var handlers = handlerDoc.RootElement.GetProperty("handlers").EnumerateArray()
            .Select(HandlerEvidence.From)
            .ToArray();
        var anchors = dataDoc.RootElement.GetProperty("anchors").EnumerateArray()
            .Select(DataAnchor.From)
            .ToArray();
        var bfbc2Packets = bfbc2Doc.RootElement.GetProperty("nativeOutgoingPacketTypes").EnumerateArray()
            .Select(NativePacketType.From)
            .ToArray();
        var bfbc2Branches = bfbc2Doc.RootElement.GetProperty("handleMessage").GetProperty("branches").EnumerateArray()
            .Select(HandleBranch.From)
            .ToArray();
        var helperCallers = LoadHelperCallerEvidence(helperCallerMapPath);

        var rows = BuildRows(handlers, anchors, bfbc2Packets, bfbc2Branches, helperCallers);
        var coveredPacketTypes = rows.SelectMany(static row => row.PacketTypes).Select(static packet => packet.Type).Distinct().Order().ToArray();
        var unresolvedRows = rows.Where(static row => !RecoveredEntryStatuses.Contains(row.EntryPointStatus, StringComparer.Ordinal)).ToArray();
        var requiredRoleCoverage = RequiredJoinRoles
            .Select(role => new
            {
                Role = role,
                Covered = rows.Any(row => row.Role == role),
                EvidenceKind = rows.FirstOrDefault(row => row.Role == role)?.EvidenceKind ?? "missing"
            })
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-tf2ps3-handler-map-data-neighborhood-and-bfbc2-dispatcher",
            note = "Canonical TF2 PS3 GameManager dispatcher coverage report. Direct-decompiled handlers and caller-context-resolved rows are implementation-ready enough to drive native semantics; data-anchor-confirmed rows have native string/table evidence but still need exact entry point/field recovery before they can be considered handler-complete.",
            summary = new
            {
                HandlerRows = rows.Length,
                DirectDecompiledRows = rows.Count(static row => row.EntryPointStatus == "direct-decompiled"),
                CallerContextResolvedRows = rows.Count(static row => row.EntryPointStatus == "caller-context-resolved"),
                DataAnchorConfirmedRows = rows.Count(static row => row.EntryPointStatus == "data-anchor-confirmed"),
                UnresolvedEntryPointRows = unresolvedRows.Length,
                HelperCallerEvidenceRows = helperCallers.Length,
                CoveredPacketTypes = coveredPacketTypes,
                CoveredPacketTypeCount = coveredPacketTypes.Length,
                RequiredJoinRolesCovered = requiredRoleCoverage.Count(static role => role.Covered),
                RequiredJoinRoleCount = requiredRoleCoverage.Length
            },
            requiredJoinRoleCoverage = requiredRoleCoverage,
            dispatcherRows = rows,
            bfbc2Reference = new
            {
                OutgoingPacketTypes = bfbc2Packets,
                HandleMessageBranches = bfbc2Branches
            },
            remainingNativeTargets = unresolvedRows
                .Select(static row => new
                {
                    row.Role,
                    row.EntryPointStatus,
                    row.ExpectedNativeWork,
                    row.AnchorReferences
                })
                .ToArray()
        }, JsonOptions));
    }

    private static DispatcherRow[] BuildRows(
        HandlerEvidence[] handlers,
        DataAnchor[] anchors,
        NativePacketType[] bfbc2Packets,
        HandleBranch[] bfbc2Branches,
        HelperCallerEvidence[] helperCallers)
    {
        return handlers
            .Select(handler =>
            {
                var helperCaller = helperCallers.FirstOrDefault(caller => caller.DispatcherRole == handler.Role);
                var roleAnchors = anchors.Where(anchor => anchor.Role == handler.Role).ToArray();
                var hasAnchorReferences = roleAnchors.Any(static anchor => anchor.ReferenceCount > 0);
                var entryPointStatus = (handler.EvidenceKind, helperCaller) switch
                {
                    ("direct-decompile", _) => "direct-decompiled",
                    (_, not null) => "caller-context-resolved",
                    (_, _) when hasAnchorReferences => "data-anchor-confirmed",
                    _ => "unresolved"
                };
                var confidence = entryPointStatus switch
                {
                    "direct-decompiled" => "high",
                    "caller-context-resolved" => helperCaller?.Confidence ?? "medium",
                    "data-anchor-confirmed" => "medium",
                    _ => "low"
                };
                var entry = entryPointStatus == "caller-context-resolved" ? helperCaller?.Entry ?? handler.Entry : handler.Entry;
                var evidenceKind = entryPointStatus == "caller-context-resolved" ? "helper-caller-context" : handler.EvidenceKind;
                var packets = MergePackets(handler, bfbc2Packets, bfbc2Branches);
                return new DispatcherRow(
                    Role: handler.Role,
                    Entry: entry,
                    EntryPointStatus: entryPointStatus,
                    EvidenceKind: evidenceKind,
                    Confidence: confidence,
                    Semantics: MergeSemantics(handler.Semantics, helperCaller),
                    PacketTypes: packets,
                    LogStrings: handler.LogStrings,
                    AnchorReferences: roleAnchors.Select(static anchor => new AnchorReference(
                        anchor.StringAddress,
                        anchor.StringValue,
                        anchor.ReferenceCount,
                        anchor.RefAddresses)).ToArray(),
                    CallerEvidence: helperCaller is null ? null : new CallerEvidence(
                        helperCaller.Entry,
                        helperCaller.Role,
                        helperCaller.DispatcherRole,
                        helperCaller.Confidence,
                        helperCaller.Semantics,
                        helperCaller.MatchedExpectedCallees,
                        helperCaller.SlotEvidence),
                    ExpectedNativeWork: ExpectedNativeWork(handler.Role, entryPointStatus, packets));
            })
            .OrderBy(static row => RowOrder(row.Role))
            .ThenBy(static row => row.Role, StringComparer.Ordinal)
            .ToArray();
    }

    private static PacketType[] MergePackets(HandlerEvidence handler, NativePacketType[] bfbc2Packets, HandleBranch[] bfbc2Branches)
    {
        var packets = handler.OutgoingMessages
            .Select(static message => new PacketType(message.Type, message.EncodedTypeByte, message.Meaning, "tf2-direct-or-handler-map"))
            .ToList();

        foreach (var packet in Bfbc2PacketsForRole(handler.Role, bfbc2Packets, bfbc2Branches))
        {
            if (!packets.Any(existing => existing.Type == packet.Type && existing.Meaning == packet.Meaning))
            {
                packets.Add(packet);
            }
        }

        return packets
            .OrderBy(static packet => packet.Type)
            .ThenBy(static packet => packet.Source, StringComparer.Ordinal)
            .ToArray();
    }

    private static IEnumerable<PacketType> Bfbc2PacketsForRole(string role, NativePacketType[] bfbc2Packets, HandleBranch[] bfbc2Branches)
    {
        var phaseRoles = role switch
        {
            "send-roster" => new[] { "send-roster" },
            "receive-roster-ack" => new[] { "receive-roster-ack-and-send-join-announcement", "send-join-mesh-announcement" },
            "receive-roster-element" => new[] { "receive-roster-element" },
            "process-roster-notice-and-send-host-ack" => new[] { "process-roster-notice-and-send-host-ack" },
            "send-join-mesh-announcement" => new[] { "send-join-mesh-announcement" },
            _ => Array.Empty<string>()
        };

        foreach (var packet in bfbc2Packets.Where(packet => phaseRoles.Contains(packet.PhaseRole, StringComparer.Ordinal)))
        {
            yield return new PacketType(packet.Type, packet.EncodedTypeByte, packet.Meaning, $"bfbc2:{packet.PhaseRole}");
        }

        if (role == "receive-roster-ack")
        {
            foreach (var branch in bfbc2Branches.Where(static branch => branch.Role.Contains("join", StringComparison.OrdinalIgnoreCase)))
            {
                yield return new PacketType(HexByte(branch.Message), branch.Message, branch.Semantics, $"bfbc2-handleMessage:{branch.Role}");
            }
        }
    }

    private static string ExpectedNativeWork(string role, string entryPointStatus, PacketType[] packets)
    {
        if (entryPointStatus == "direct-decompiled")
        {
            return role switch
            {
                "send-roster" or "send-join-mesh-announcement" or "send-peer-mesh-to-host" => "Name writer helper field order and bind it to typed packet builders.",
                _ => "Keep mapped as direct native support; no entry-point recovery needed."
            };
        }

        if (entryPointStatus == "caller-context-resolved")
        {
            return role switch
            {
                "process-roster-notice-and-send-host-ack" => "Bind caller-context-resolved type 4 host-ack builder to exact inbound roster-notice field order.",
                "receive-full-mesh" => "Bind caller-context-resolved full-mesh completion path to exact mesh field order and start transition.",
                _ => "Bind caller-context-resolved entry to exact dispatcher table slot and field order."
            };
        }

        var packetList = packets.Length == 0
            ? "state transition with no confirmed outgoing packet type"
            : $"packet type(s) {string.Join(", ", packets.Select(static packet => packet.Type).Distinct().Order())}";
        return $"Recover TF.elf function entry and writer/read field order for {packetList}.";
    }

    private static int RowOrder(string role)
    {
        var index = Array.IndexOf(RequiredJoinRoles, role);
        return index >= 0 ? index : RequiredJoinRoles.Length + 1;
    }

    private static int HexByte(string value)
    {
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && int.TryParse(value[2..], System.Globalization.NumberStyles.HexNumber, null, out var parsed))
        {
            return parsed;
        }

        return 0;
    }

    private static HelperCallerEvidence[] LoadHelperCallerEvidence(string helperCallerMapPath)
    {
        if (string.IsNullOrWhiteSpace(helperCallerMapPath) || !File.Exists(helperCallerMapPath))
        {
            return Array.Empty<HelperCallerEvidence>();
        }

        using var doc = JsonDocument.Parse(File.ReadAllText(helperCallerMapPath));
        if (!doc.RootElement.TryGetProperty("callers", out var callers))
        {
            return Array.Empty<HelperCallerEvidence>();
        }

        return callers.EnumerateArray()
            .Select(HelperCallerEvidence.From)
            .Where(static caller => caller.DispatcherRole.Length > 0)
            .ToArray();
    }

    private static string MergeSemantics(string handlerSemantics, HelperCallerEvidence? helperCaller)
    {
        if (helperCaller is null)
        {
            return handlerSemantics;
        }

        return string.IsNullOrWhiteSpace(handlerSemantics)
            ? helperCaller.Semantics
            : $"{handlerSemantics} Native caller evidence: {helperCaller.Semantics}";
    }

    private sealed record HandlerEvidence(
        string Entry,
        string Role,
        string EvidenceKind,
        string Semantics,
        PacketType[] OutgoingMessages,
        string[] LogStrings)
    {
        public static HandlerEvidence From(JsonElement element)
        {
            return new HandlerEvidence(
                GetString(element, "Entry"),
                GetString(element, "Role"),
                GetString(element, "EvidenceKind"),
                GetString(element, "Semantics"),
                element.GetProperty("OutgoingMessages").EnumerateArray()
                    .Select(static message => new PacketType(
                        message.GetProperty("Type").GetInt32(),
                        GetString(message, "EncodedTypeByte"),
                        GetString(message, "Meaning"),
                        "tf2-handler-map"))
                    .ToArray(),
                element.GetProperty("LogStrings").EnumerateArray()
                    .Select(static value => value.GetString() ?? "")
                    .Where(static value => value.Length > 0)
                    .ToArray());
        }
    }

    private sealed record DataAnchor(string Role, string StringAddress, string StringValue, int ReferenceCount, string[] RefAddresses)
    {
        public static DataAnchor From(JsonElement element)
        {
            return new DataAnchor(
                GetString(element, "Role"),
                GetString(element, "StringAddress"),
                GetString(element, "StringValue"),
                element.GetProperty("ReferenceCount").GetInt32(),
                element.GetProperty("References").EnumerateArray()
                    .Select(static reference => GetString(reference, "RefAddress"))
                    .Where(static value => value.Length > 0)
                    .ToArray());
        }
    }

    private sealed record NativePacketType(string PhaseRole, string PhaseEntry, int Type, string Meaning, string EncodedTypeByte)
    {
        public static NativePacketType From(JsonElement element)
        {
            return new NativePacketType(
                GetString(element, "PhaseRole"),
                GetString(element, "PhaseEntry"),
                element.GetProperty("Type").GetInt32(),
                GetString(element, "Meaning"),
                GetString(element, "EncodedTypeByte"));
        }
    }

    private sealed record HandleBranch(string Group, string Message, string Role, string Semantics)
    {
        public static HandleBranch From(JsonElement element)
        {
            return new HandleBranch(
                GetString(element, "Group"),
                GetString(element, "Message"),
                GetString(element, "Role"),
                GetString(element, "Semantics"));
        }
    }

    private sealed record HelperCallerEvidence(
        string Entry,
        string Role,
        string DispatcherRole,
        string Confidence,
        string Semantics,
        string[] MatchedExpectedCallees,
        string[] SlotEvidence)
    {
        public static HelperCallerEvidence From(JsonElement element)
        {
            return new HelperCallerEvidence(
                GetString(element, "Entry"),
                GetString(element, "Role"),
                GetString(element, "DispatcherRole"),
                GetString(element, "Confidence"),
                GetString(element, "Semantics"),
                ReadStringArray(element, "MatchedExpectedCallees"),
                ReadStringArray(element, "SlotEvidence"));
        }
    }

    private sealed record DispatcherRow(
        string Role,
        string Entry,
        string EntryPointStatus,
        string EvidenceKind,
        string Confidence,
        string Semantics,
        PacketType[] PacketTypes,
        string[] LogStrings,
        AnchorReference[] AnchorReferences,
        CallerEvidence? CallerEvidence,
        string ExpectedNativeWork);

    private sealed record PacketType(int Type, string EncodedTypeByte, string Meaning, string Source);
    private sealed record AnchorReference(string StringAddress, string StringValue, int ReferenceCount, string[] RefAddresses);
    private sealed record CallerEvidence(
        string Entry,
        string Role,
        string DispatcherRole,
        string Confidence,
        string Semantics,
        string[] MatchedExpectedCallees,
        string[] SlotEvidence);

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
