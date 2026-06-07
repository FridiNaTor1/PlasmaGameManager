using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Tf2Ps3ReaderFunctionReducer
{
    public static async Task ReduceAsync(string anchorContextMapPath, string dispatcherMapPath, string outputPath)
    {
        using var anchorDoc = JsonDocument.Parse(File.ReadAllText(anchorContextMapPath));
        using var dispatcherDoc = JsonDocument.Parse(File.ReadAllText(dispatcherMapPath));

        var functions = anchorDoc.RootElement.GetProperty("decompiledReaderFunctions").EnumerateArray()
            .Select(ReaderFunction.From)
            .ToArray();
        var tableReads = anchorDoc.RootElement.GetProperty("tableReads").EnumerateArray()
            .Select(TableRead.From)
            .ToArray();
        var dispatcherRows = dispatcherDoc.RootElement.GetProperty("dispatcherRows").EnumerateArray()
            .Select(DispatcherRow.From)
            .ToArray();

        var rows = functions
            .Select(function => BuildFunctionMap(function, tableReads.Where(read => read.ReaderFunction == function.Entry).ToArray(), dispatcherRows))
            .OrderBy(static function => function.Entry, StringComparer.Ordinal)
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-tf2ps3-ghidra-reader-functions",
            note = "Reduces confirmed table-reader decompiles into native TF2 GameManager handler semantics. This is not packet replay; it records code-derived helper calls, branch guards, state writes, and the packet roles that each reader reaches.",
            input = new
            {
                AnchorContextMap = anchorContextMapPath,
                DispatcherMap = dispatcherMapPath
            },
            summary = new
            {
                ReaderFunctionCount = rows.Length,
                ClassifiedReaderFunctionCount = rows.Count(static row => row.Role != "unclassified-table-reader"),
                MeshTriggerFunction = rows.FirstOrDefault(static row => row.Entry == "015d4e20")?.Role ?? "",
                ReceivedJoinFunction = rows.FirstOrDefault(static row => row.Entry == "015d5d50")?.Role ?? "",
                PacketTypesReached = rows.SelectMany(static row => row.ReachesPacketTypes).Distinct().Order().ToArray()
            },
            functions = rows,
            remainingNativeTargets = new[]
            {
                "Run a wider context export around callers of 015d4e20 to recover the exact inbound message id that enters the connection-established branch.",
                "Run a focused export for callees 01587ed8, 0158e1a0, 015d5a00, 0158f078, 015ae358, 015a2300, and 015a2220 to name read-field order and state mutations.",
                "Recover register-relative references for the still-unxrefed anchored strings 019c09a4, 019c09a8, 019c09b0, 019c09b8, 019c09bc, and 019c09c0."
            }
        }, JsonOptions));
    }

    private static FunctionMap BuildFunctionMap(ReaderFunction function, TableRead[] reads, DispatcherRow[] dispatcherRows)
    {
        return function.Entry switch
        {
            "015d4e20" => ConnectionEstablished(function, reads, dispatcherRows),
            "015d5d50" => ReceivedJoin(function, reads, dispatcherRows),
            _ => Generic(function, reads)
        };
    }

    private static FunctionMap ConnectionEstablished(ReaderFunction function, TableRead[] reads, DispatcherRow[] dispatcherRows)
    {
        var reaches = PacketTypesFor(dispatcherRows, "send-join-mesh-announcement");
        return new FunctionMap(
            Entry: function.Entry,
            Name: function.Name,
            Role: "connection-established-associate-peer-and-send-mesh",
            Confidence: HasAll(function.Body, "_opd_FUN_01587ed8", "_opd_FUN_0158e1a0", "_opd_FUN_015a7178", "_opd_FUN_015d0718") ? "high" : "medium",
            Semantics: "Reads the incoming peer/player id tuple, rejects duplicate association state, resolves the player object, chooses host-vs-peer association handling on param_2 == 0xb, logs the established connection, then calls 015d0718 to emit native type 8/9 join mesh packets.",
            StateGuards: new[]
            {
                "_opd_FUN_0158e1a0(param_1 + 8, 1, param_3, param_4) must return false",
                "_opd_FUN_015a7178(param_1 + 8, auStack_50[0]) must resolve a player object",
                "param_2 == 0xb selects _opd_FUN_015a2300; all other values select _opd_FUN_015a2220"
            },
            HelperCalls: Helpers(function.Body),
            TableReads: reads,
            ReachesRoles: new[] { "send-join-mesh-announcement" },
            ReachesPacketTypes: reaches,
            NativeFieldEvidence: new[]
            {
                "01587ed8(param_4, auStack_50) decodes a six-word stack tuple from the inbound packet.",
                "auStack_50[0] is used as the player lookup key.",
                "param_3 vtable +0x18 and resolved-player vtable +0x18 are used for log/display ids.",
                "015d0718 is the direct mesh sender already mapped to packet types 8 and 9."
            },
            NextTargets: new[]
            {
                "Export callers and callsites for 015d4e20 to bind param_2 value 0xb to the exact inbound native message.",
                "Decompile 015a2300 and 015a2220 to name the two association mutations."
            },
            BodyLength: function.Body.Length);
    }

    private static FunctionMap ReceivedJoin(ReaderFunction function, TableRead[] reads, DispatcherRow[] dispatcherRows)
    {
        return new FunctionMap(
            Entry: function.Entry,
            Name: function.Name,
            Role: "received-join-build-and-propagate-player-join",
            Confidence: HasAll(function.Body, "_opd_FUN_01587ed8", "_opd_FUN_0158e1a0", "_opd_FUN_015d5a00", "_opd_FUN_0158f078") ? "high" : "medium",
            Semantics: "Reads the incoming join player id, logs it, rejects duplicate/local-player joins, builds a join object, updates it through 0158f078, and either sends it through 015ae358 or broadcasts it to registered listeners when the session state is 5.",
            StateGuards: new[]
            {
                "The local/current player id is read from param_1[0x5d] vtable +0x18.",
                "_opd_FUN_0158e1a0(param_1, 0, 0, param_4) must return false.",
                "The decoded joining player id aiStack_40[0] must not equal the local/current player id.",
                "param_1[5] == 5 enables listener broadcast of the built join object."
            },
            HelperCalls: Helpers(function.Body),
            TableReads: reads,
            ReachesRoles: new[] { "receive-full-mesh", "receive-roster-element", "process-roster-notice-and-send-host-ack" },
            ReachesPacketTypes: PacketTypesFor(dispatcherRows, "receive-full-mesh", "receive-roster-element", "process-roster-notice-and-send-host-ack"),
            NativeFieldEvidence: new[]
            {
                "01587ed8(param_4, aiStack_40) decodes a six-word stack tuple from the inbound packet.",
                "aiStack_40[0] is logged as the joining player id.",
                "015d5a00(param_1, param_4) builds the native join object from session state and inbound packet fields.",
                "Listener callbacks at vtable +0x1c receive the built join object while state slot param_1[5] is 5."
            },
            NextTargets: new[]
            {
                "Decompile 015d5a00 to recover the join object field order used by TF2.",
                "Decompile 0158f078 and 015ae358 to split local state update from outbound/broadcast behavior.",
                "Export callers for 015d5d50 to tie this path to the inbound type/phase after roster and mesh."
            },
            BodyLength: function.Body.Length);
    }

    private static FunctionMap Generic(ReaderFunction function, TableRead[] reads)
    {
        var role = reads.Any() ? "confirmed-table-reader" : "unclassified-table-reader";
        return new FunctionMap(
            Entry: function.Entry,
            Name: function.Name,
            Role: role,
            Confidence: reads.Any() ? "medium" : "low",
            Semantics: reads.Any()
                ? "Confirmed Ghidra table reader. Needs a focused semantic pass before implementation use."
                : "Ghidra exported this function in reader context, but it is not tied to a named native GameManager phase yet.",
            StateGuards: ExtractConditions(function.Body),
            HelperCalls: Helpers(function.Body),
            TableReads: reads,
            ReachesRoles: reads.SelectMany(static read => read.Roles).Distinct(StringComparer.Ordinal).ToArray(),
            ReachesPacketTypes: Array.Empty<int>(),
            NativeFieldEvidence: Array.Empty<string>(),
            NextTargets: new[] { "Inspect this reader with caller/callee context and classify its GameManager state role." },
            BodyLength: function.Body.Length);
    }

    private static string[] Helpers(string body)
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

    private static string[] ExtractConditions(string body)
    {
        var conditions = new List<string>();
        foreach (var line in body.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("if (", StringComparison.Ordinal))
            {
                conditions.Add(trimmed);
            }
        }

        return conditions.Take(8).ToArray();
    }

    private static bool HasAll(string body, params string[] needles)
    {
        return needles.All(needle => body.Contains(needle, StringComparison.Ordinal));
    }

    private static int[] PacketTypesFor(DispatcherRow[] rows, params string[] roles)
    {
        return rows
            .Where(row => roles.Contains(row.Role, StringComparer.Ordinal))
            .SelectMany(static row => row.PacketTypes)
            .Distinct()
            .Order()
            .ToArray();
    }

    private sealed record ReaderFunction(string Entry, string Name, string Body)
    {
        public static ReaderFunction From(JsonElement element)
        {
            return new ReaderFunction(
                GetString(element, "Entry"),
                GetString(element, "Name"),
                GetString(element, "Body").Length > 0 ? GetString(element, "Body") : GetString(element, "BodyPreview"));
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

    private sealed record DispatcherRow(string Role, int[] PacketTypes)
    {
        public static DispatcherRow From(JsonElement element)
        {
            return new DispatcherRow(
                GetString(element, "Role"),
                element.GetProperty("PacketTypes").EnumerateArray()
                    .Select(static packet => packet.GetProperty("Type").GetInt32())
                    .ToArray());
        }
    }

    private sealed record FunctionMap(
        string Entry,
        string Name,
        string Role,
        string Confidence,
        string Semantics,
        string[] StateGuards,
        string[] HelperCalls,
        TableRead[] TableReads,
        string[] ReachesRoles,
        int[] ReachesPacketTypes,
        string[] NativeFieldEvidence,
        string[] NextTargets,
        int BodyLength);

    private static string GetString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) ? value.GetString() ?? "" : "";
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}
