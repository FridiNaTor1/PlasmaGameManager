using System.Text.Json;
using System.Text.RegularExpressions;

namespace PlasmaGameManager.ReTools;

public static partial class Tf2Ps3GameManagerReducer
{
    public static async Task ReduceAsync(
        string evidencePath,
        string functionDecompilesPath,
        string bfbc2PhaseMapPath,
        string outputDir)
    {
        using var evidenceDoc = JsonDocument.Parse(File.ReadAllText(evidencePath));
        using var functionDoc = JsonDocument.Parse(File.ReadAllText(functionDecompilesPath));
        using var bfbc2Doc = JsonDocument.Parse(File.ReadAllText(bfbc2PhaseMapPath));

        var evidence = EvidenceIndex.From(evidenceDoc.RootElement);
        var functions = functionDoc.RootElement.GetProperty("functions").EnumerateArray()
            .Select(FunctionExport.From)
            .Where(static function => function.Entry.Length > 0)
            .ToDictionary(static function => function.Entry, StringComparer.Ordinal);
        var bfbc2Phases = bfbc2Doc.RootElement.GetProperty("phases").EnumerateArray()
            .Select(Bfbc2Phase.From)
            .ToArray();

        Directory.CreateDirectory(outputDir);

        var handlers = BuildHandlers(evidence, functions);
        var crossMap = BuildCrossMap(handlers, bfbc2Phases);

        await File.WriteAllTextAsync(
            Path.Combine(outputDir, "handler-map.json"),
            JsonSerializer.Serialize(new
            {
                status = "seeded-from-analyzed-tf2ps3-ghidra-evidence",
                note = "Focused PS3 Ghidra output now maps the TF2 PS3 GameManager listen, roster, join-mesh, peer-mesh, AddAssociations, and FeslThread-adjacent paths. Entries marked pointer-table-evidence still need a handler entry point recovered from xrefs or jumptables before they are implementation-complete.",
                requiredScriptPath = "/home/deck/Documents/Decomp projects/Projects/Ps3GhidraScripts/",
                ghidraWorkflow = new[]
                {
                    "Import as PowerPC:BE:64:A2ALT-32addr.",
                    "Run AnalyzePs3Binary.java before auto-analysis.",
                    "Run AssignPs3R2FromOpd.java and DefinePS3Syscalls.java after analysis.",
                    "Export focused GameManager strings/xrefs and targeted function decompiles."
                },
                summary = new
                {
                    evidence.StringCount,
                    evidence.SymbolCount,
                    evidence.ReferenceCount,
                    DirectDecompiledHandlers = handlers.Count(static h => h.EvidenceKind == "direct-decompile"),
                    PointerTableOnlyHandlers = handlers.Count(static h => h.EvidenceKind == "pointer-table-evidence")
                },
                handlers,
                unresolvedTargets = new[]
                {
                    "Recover entry points for the pointer-table-only TF2 phases: reservation, roster ack receive, join announcement, full mesh receive, roster element receive, roster notice processing, and host roster ack.",
                    "Name the TF2 writer helpers behind 01587708/01587710/01587758/01587998/01587be0/0158d530/0158d8c0/0158e830.",
                    "Map packet type 4/5/8/9 field order from TF2 decompiles and PCAP semantic traces without old replay fallbacks.",
                    "Locate the exact Source/MOTD handoff transition after join-complete/host-hello."
                }
            }, JsonOptions));

        await File.WriteAllTextAsync(
            Path.Combine(outputDir, "bfbc2-crossmap.json"),
            JsonSerializer.Serialize(new
            {
                status = "seeded-from-bfbc2-native-phase-map-and-tf2ps3-decompile-evidence",
                note = "Maps BFBC2 native GameManager phases to TF2 PS3 functions by shared log semantics, outgoing packet types, and writer-call shape. This is a semantic map, not packet replay.",
                mappings = crossMap
            }, JsonOptions));

        await File.WriteAllTextAsync(
            Path.Combine(outputDir, "client-state-machine.md"),
            BuildStateMachineMarkdown(handlers, crossMap));
    }

    private static HandlerRow[] BuildHandlers(EvidenceIndex evidence, IReadOnlyDictionary<string, FunctionExport> functions)
    {
        var rows = new List<HandlerRow>
        {
            Direct(functions, evidence, "015961d8", "listen-start", "initializes/listens for GameManager UDP traffic", Array.Empty<int>(), new[] { "GM: GameManager listening on port %d" }),
            Direct(functions, evidence, "015b3e50", "send-roster", "sends roster header and player roster elements to the joining player; decompile shows one-byte/short/int writer calls and final send helper", new[] { 2, 3 }, new[] { "GM: Sent roster to player %i (%i elements)" }),
            Direct(functions, evidence, "015cee00", "send-peer-mesh-to-host", "sends peer mesh connection data to the current host for the joining player; decompile writes addressed message type 0xb and logs success/error", new[] { 11 }, new[] { "GM: Error Sending Peer Mesh connection to host for player %d", "GM: Peer Mesh connection sent to host for player %d" }),
            Direct(functions, evidence, "015d0718", "send-join-mesh-announcement", "iterates active players, sends join mesh type 8 and addressed detail type 9, then advances join state bookkeeping", new[] { 8, 9 }, new[] { "GM: Sent join mesh announcement for player %i." }),
            Direct(functions, evidence, "015f5eb0", "register-association-rpcs", "registers AssociationManager RPC endpoints including AddAssociations/DeleteAssociations/GetAssociations/GetAssociationCount/NotifyAssociationUpdate", Array.Empty<int>(), new[] { "AddAssociations" }),
            Direct(functions, evidence, "015d5d50", "fesl-thread-adjacent-game-flow", "previous live crash region in FeslThread; decompile calls packet/object helpers and is retained as a triage target for null client-state reads", Array.Empty<int>(), Array.Empty<string>())
        };

        rows.AddRange(new[]
        {
            PointerOnly(evidence, "reservation-take", "reservation/ticket approval state before roster", Array.Empty<int>(), new[] { "GM: Player %d taking theater reservation." }),
            PointerOnly(evidence, "receive-roster-ack", "client ack after receiving roster; BFBC2 sends join announcement/details from this phase", new[] { 5, 9 }, new[] { "GM: Received roster ack from player %i.", "GM: Sent join announcement for player %i." }),
            PointerOnly(evidence, "receive-full-mesh", "client full mesh receive state after mesh exchange", Array.Empty<int>(), new[] { "GM: Received full mesh for player %i." }),
            PointerOnly(evidence, "receive-roster-element", "client roster element receive path; updates notice count", new[] { 4 }, new[] { "GM: Received roster element." }),
            PointerOnly(evidence, "process-roster-notice-and-send-host-ack", "processes roster notice counters and sends roster ack to host when complete", new[] { 4 }, new[] { "GM: Processed roster notice for player id %i (%d of %d).", "GM: Sent roster ack to host." }),
            PointerOnly(evidence, "make-connection-id", "builds/logs connident strings used by mesh/association relationships", Array.Empty<int>(), new[] { "MakeConnId created connident: 0x%s" }),
            PointerOnly(evidence, "player-inactivity-timeout", "activity timeout path for dropped players", Array.Empty<int>(), new[] { "GM: Warning: No activity received from player %i" })
        });

        return rows.ToArray();
    }

    private static HandlerRow Direct(
        IReadOnlyDictionary<string, FunctionExport> functions,
        EvidenceIndex evidence,
        string entry,
        string role,
        string semantics,
        int[] outgoingTypes,
        string[] logStrings)
    {
        functions.TryGetValue(entry, out var function);
        return new HandlerRow(
            Entry: entry,
            Role: role,
            EvidenceKind: "direct-decompile",
            Semantics: semantics,
            OutgoingMessages: outgoingTypes.Select(Message).ToArray(),
            LogStrings: logStrings,
            MatchedStrings: evidence.FindStrings(logStrings),
            ReferencedBy: evidence.FindReferences(logStrings),
            StringPointers: evidence.FindSymbols(logStrings),
            Callees: function?.Callees ?? Array.Empty<string>(),
            WriterCalls: function is null ? Array.Empty<string>() : ExtractWriterCalls(function.Body),
            BodyLength: function?.Body.Length ?? 0);
    }

    private static HandlerRow PointerOnly(
        EvidenceIndex evidence,
        string role,
        string semantics,
        int[] outgoingTypes,
        string[] logStrings)
    {
        return new HandlerRow(
            Entry: "",
            Role: role,
            EvidenceKind: "pointer-table-evidence",
            Semantics: semantics,
            OutgoingMessages: outgoingTypes.Select(Message).ToArray(),
            LogStrings: logStrings,
            MatchedStrings: evidence.FindStrings(logStrings),
            ReferencedBy: evidence.FindReferences(logStrings),
            StringPointers: evidence.FindSymbols(logStrings),
            Callees: Array.Empty<string>(),
            WriterCalls: Array.Empty<string>(),
            BodyLength: 0);
    }

    private static object[] BuildCrossMap(HandlerRow[] handlers, Bfbc2Phase[] bfbc2Phases)
    {
        var mappings = new List<object>();
        AddMapping(mappings, bfbc2Phases, handlers, "send-roster", "send-roster", "shared roster header/element semantics; BFBC2 emits type 2/3, TF2 direct decompile shows the same roster log and writer chain");
        AddMapping(mappings, bfbc2Phases, handlers, "send-join-mesh-announcement", "send-join-mesh-announcement", "shared mesh announcement and addressed detail semantics; both use outgoing type 8 followed by type 9 details");
        AddMapping(mappings, bfbc2Phases, handlers, "receive-roster-ack-and-send-join-announcement", "receive-roster-ack", "shared roster-ack -> join-announcement -> addressed-detail state; TF2 currently has log/pointer evidence but handler entry still needs recovery");
        AddMapping(mappings, bfbc2Phases, handlers, "receive-roster-element", "receive-roster-element", "shared roster element receive semantics; TF2 currently has string/pointer evidence only");
        AddMapping(mappings, bfbc2Phases, handlers, "process-roster-notice-and-send-host-ack", "process-roster-notice-and-send-host-ack", "shared host roster ack completion semantics; TF2 currently has string/pointer evidence only");
        mappings.Add(new
        {
            Bfbc2Role = "make-connection-association",
            Bfbc2Entry = "00dc73a0",
            Tf2Role = "make-connection-id",
            Tf2Entry = "",
            Confidence = "medium",
            Evidence = "same connident log string family; TF2 entry point still unresolved",
            PacketTypes = Array.Empty<object>()
        });
        mappings.Add(new
        {
            Bfbc2Role = "association-rpc-registration",
            Bfbc2Entry = "",
            Tf2Role = "register-association-rpcs",
            Tf2Entry = handlers.Single(static h => h.Role == "register-association-rpcs").Entry,
            Confidence = "high",
            Evidence = "TF2 direct decompile registers AddAssociations/DeleteAssociations/GetAssociations/GetAssociationCount/NotifyAssociationUpdate",
            PacketTypes = Array.Empty<object>()
        });
        return mappings.ToArray();
    }

    private static void AddMapping(List<object> mappings, Bfbc2Phase[] bfbc2Phases, HandlerRow[] handlers, string bfbc2Role, string tf2Role, string evidence)
    {
        var bfbc2 = bfbc2Phases.First(p => p.Role == bfbc2Role);
        var tf2 = handlers.Single(h => h.Role == tf2Role);
        var confidence = tf2.EvidenceKind == "direct-decompile" ? "high" : "medium";
        mappings.Add(new
        {
            Bfbc2Role = bfbc2.Role,
            Bfbc2Entry = bfbc2.Entry,
            Tf2Role = tf2.Role,
            Tf2Entry = tf2.Entry,
            Confidence = confidence,
            Evidence = evidence,
            PacketTypes = tf2.OutgoingMessages.Length > 0 ? tf2.OutgoingMessages : bfbc2.OutgoingMessages
        });
    }

    private static string BuildStateMachineMarkdown(HandlerRow[] handlers, object[] _)
    {
        var lineBreak = Environment.NewLine;
        var lines = new List<string>
        {
            "# TF2 PS3 GameManager Client State Machine",
            "",
            "This state machine is seeded from the focused TF.elf Ghidra pass and the BFBC2_R34 native server phase map. It is intentionally semantic: direct TF2 decompiles are separated from pointer-table-only phases so implementation does not silently become packet replay.",
            "",
            "## Recovered Flow",
            "",
            "1. `listen-start` opens/listens on the GameManager UDP port and logs `GM: GameManager listening on port %d`.",
            "2. `reservation-take` accepts the theater reservation/ticket state for a player.",
            "3. `send-roster` sends roster header type `2` and roster element type `3` records to the joining player.",
            "4. `receive-roster-ack` consumes the client's roster ack and should drive join announcement type `5` plus addressed details type `9`.",
            "5. `receive-roster-element` / `process-roster-notice-and-send-host-ack` consume roster notice records and send host roster ack type `4` when complete.",
            "6. `send-join-mesh-announcement` emits join mesh type `8` and addressed details type `9` for active players.",
            "7. `send-peer-mesh-to-host` emits TF2's peer-mesh-to-host path, observed as addressed message type `11` in decompile.",
            "8. `receive-full-mesh` transitions the player past the mesh exchange toward join-complete/source handoff.",
            "",
            "## Handler Evidence",
            ""
        };

        foreach (var handler in handlers)
        {
            var entry = handler.Entry.Length == 0 ? "unresolved" : handler.Entry;
            var packets = handler.OutgoingMessages.Length == 0
                ? "none known"
                : string.Join(", ", handler.OutgoingMessages.Select(static m => $"{m.Type} ({m.Meaning})"));
            lines.Add($"- `{handler.Role}`: `{entry}`, {handler.EvidenceKind}, outgoing {packets}. {handler.Semantics}");
        }

        lines.Add("");
        lines.Add("## Remaining Native Work");
        lines.Add("");
        lines.Add("- Recover entry points for all pointer-table-only phases from TF.elf xrefs/jumptables.");
        lines.Add("- Name TF2 writer helper field order for packet types `4`, `5`, `8`, `9`, and `11`.");
        lines.Add("- Identify the exact Source/MOTD handoff condition after full mesh/join complete.");
        lines.Add("- Validate the typed implementation against quick-match, custom-match, create-and-join, Dustbowl, and 2Fort PCAP semantic tests.");
        lines.Add("");

        return string.Join(lineBreak, lines);
    }

    private static MessageRow Message(int type)
    {
        return new MessageRow(type, $"0x{type + 0x80:x2}", type switch
        {
            2 => "roster header",
            3 => "roster element",
            4 => "roster ack to host",
            5 => "join announcement",
            8 => "join mesh announcement",
            9 => "addressed join details",
            11 => "peer mesh connection to host",
            _ => "unknown GameManager message"
        });
    }

    private static string[] ExtractWriterCalls(string body)
    {
        return WriterCallRegex().Matches(body)
            .Select(static match => match.Value)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    private sealed record EvidenceIndex(
        int StringCount,
        int SymbolCount,
        int ReferenceCount,
        EvidenceString[] Strings,
        EvidenceReference[] References,
        EvidenceSymbol[] Symbols)
    {
        public static EvidenceIndex From(JsonElement root)
        {
            var strings = root.GetProperty("strings").EnumerateArray()
                .Select(static element => new EvidenceString(
                    GetString(element, "address"),
                    GetString(element, "needle"),
                    GetString(element, "value")))
                .ToArray();
            var references = root.GetProperty("references").EnumerateArray()
                .Select(static element => new EvidenceReference(
                    GetString(element, "stringAddress"),
                    GetString(element, "from"),
                    GetString(element, "functionEntry"),
                    GetString(element, "function"),
                    GetString(element, "needle")))
                .ToArray();
            var symbols = root.GetProperty("symbols").EnumerateArray()
                .Select(static element => new EvidenceSymbol(
                    GetString(element, "address"),
                    GetString(element, "name"),
                    GetString(element, "type"),
                    GetString(element, "needle")))
                .ToArray();

            return new EvidenceIndex(strings.Length, symbols.Length, references.Length, strings, references, symbols);
        }

        public object[] FindReferences(string[] logStrings)
        {
            var exactAddresses = Strings
                .Where(s => logStrings.Any(log => s.Value.Equals(log, StringComparison.Ordinal)))
                .Select(static s => s.Address)
                .ToHashSet(StringComparer.Ordinal);
            var stringAddresses = exactAddresses.Count > 0
                ? exactAddresses
                : Strings
                    .Where(s => logStrings.Any(log => MatchesNeedle(s.Value, log)))
                    .Select(static s => s.Address)
                    .ToHashSet(StringComparer.Ordinal);
            return References
                .Where(reference => stringAddresses.Contains(reference.StringAddress))
                .Select(static reference => new
                {
                    reference.StringAddress,
                    reference.From,
                    reference.FunctionEntry,
                    reference.Function,
                    reference.Needle
                })
                .Cast<object>()
                .ToArray();
        }

        public object[] FindStrings(string[] logStrings)
        {
            var exactMatches = Strings
                .Where(s => logStrings.Any(log => s.Value.Equals(log, StringComparison.Ordinal)))
                .Select(static s => new
                {
                    s.Address,
                    s.Needle,
                    s.Value
                })
                .Cast<object>()
                .ToArray();
            if (exactMatches.Length > 0)
            {
                return exactMatches;
            }

            return Strings
                .Where(s => logStrings.Any(log => MatchesNeedle(s.Value, log)))
                .Select(static s => new
                {
                    s.Address,
                    s.Needle,
                    s.Value
                })
                .Cast<object>()
                .ToArray();
        }

        public object[] FindSymbols(string[] logStrings)
        {
            var exactStringAddresses = Strings
                .Where(s => logStrings.Any(log => s.Value.Equals(log, StringComparison.Ordinal)))
                .Select(static s => s.Address)
                .ToHashSet(StringComparer.Ordinal);
            if (exactStringAddresses.Count > 0)
            {
                return Symbols
                    .Where(symbol => exactStringAddresses.Contains(symbol.Address))
                    .Select(static symbol => new
                    {
                        symbol.Address,
                        symbol.Name,
                        symbol.Type,
                        symbol.Needle
                    })
                    .Cast<object>()
                    .ToArray();
            }

            var needles = logStrings.Select(NormalizeNeedle).Where(static value => value.Length >= 6).ToArray();
            return Symbols
                .Where(symbol => needles.Any(needle => symbol.Name.Contains(needle, StringComparison.OrdinalIgnoreCase)))
                .Select(static symbol => new
                {
                    symbol.Address,
                    symbol.Name,
                    symbol.Type,
                    symbol.Needle
                })
                .Cast<object>()
                .ToArray();
        }

        private static bool MatchesNeedle(string value, string log)
        {
            return value.Equals(log, StringComparison.Ordinal)
                || value.Contains(NormalizeNeedle(log), StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeNeedle(string value)
        {
            var normalized = value
                .Replace("GM:", "", StringComparison.Ordinal)
                .Replace("%i", "", StringComparison.Ordinal)
                .Replace("%d", "", StringComparison.Ordinal)
                .Replace("%s", "", StringComparison.Ordinal)
                .Replace("0x", "", StringComparison.Ordinal)
                .Replace(".", "", StringComparison.Ordinal)
                .Trim();
            var space = normalized.IndexOf(' ', StringComparison.Ordinal);
            return space > 0 ? normalized[..space] : normalized;
        }
    }

    private sealed record EvidenceString(string Address, string Needle, string Value);
    private sealed record EvidenceReference(string StringAddress, string From, string FunctionEntry, string Function, string Needle);
    private sealed record EvidenceSymbol(string Address, string Name, string Type, string Needle);

    private sealed record FunctionExport(string Entry, string Name, string Body, string[] Callees)
    {
        public static FunctionExport From(JsonElement root)
        {
            var entry = GetString(root, "entry");
            var body = GetString(root, "body");
            return new FunctionExport(entry, GetString(root, "name"), body, ExtractCallees(body));
        }

        private static string[] ExtractCallees(string body)
        {
            return CalleeRegex().Matches(body)
                .Select(static match => match.Groups[1].Value)
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray();
        }
    }

    private sealed record Bfbc2Phase(string Entry, string Role, MessageRow[] OutgoingMessages)
    {
        public static Bfbc2Phase From(JsonElement root)
        {
            return new Bfbc2Phase(
                root.GetProperty("Entry").GetString() ?? "",
                root.GetProperty("Role").GetString() ?? "",
                root.GetProperty("OutgoingMessages").EnumerateArray()
                    .Select(static message => new MessageRow(
                        message.GetProperty("Type").GetInt32(),
                        message.GetProperty("EncodedTypeByte").GetString() ?? "",
                        message.GetProperty("Meaning").GetString() ?? ""))
                    .ToArray());
        }
    }

    private sealed record HandlerRow(
        string Entry,
        string Role,
        string EvidenceKind,
        string Semantics,
        MessageRow[] OutgoingMessages,
        string[] LogStrings,
        object[] MatchedStrings,
        object[] ReferencedBy,
        object[] StringPointers,
        string[] Callees,
        string[] WriterCalls,
        int BodyLength);

    private sealed record MessageRow(int Type, string EncodedTypeByte, string Meaning);

    private static string GetString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) ? value.GetString() ?? "" : "";
    }

    [GeneratedRegex(@"FUN_([0-9a-fA-F]{8})")]
    private static partial Regex CalleeRegex();

    [GeneratedRegex(@"_opd_FUN_0158[0-9a-fA-F]{4}|_opd_FUN_01587[0-9a-fA-F]{3}")]
    private static partial Regex WriterCallRegex();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}
