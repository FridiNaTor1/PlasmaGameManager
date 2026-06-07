using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Tf2Ps3ReaderHelperReducer
{
    public static async Task ReduceAsync(string helperDecompilesPath, string outputPath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(helperDecompilesPath));
        var helpers = doc.RootElement.GetProperty("functions").EnumerateArray()
            .Select(HelperFunction.From)
            .Select(ReduceHelper)
            .OrderBy(static helper => helper.Entry, StringComparer.Ordinal)
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-tf2ps3-reader-helper-decompiles",
            note = "Focused helper map for the native TF2 GameManager reader paths. Names are conservative and code-derived; unresolved field labels are offsets until later class recovery names the owning types.",
            input = helperDecompilesPath,
            summary = new
            {
                HelperCount = helpers.Length,
                ClassifiedHelperCount = helpers.Count(static helper => helper.Role != "unclassified-helper"),
                AssociationStateValues = helpers
                    .Where(static helper => helper.Role.Contains("association-state", StringComparison.Ordinal))
                    .Select(static helper => new { helper.Entry, helper.Role, helper.StateWrites })
                    .ToArray(),
                JoinObjectHelper = helpers.FirstOrDefault(static helper => helper.Entry == "015d5a00")?.Role ?? "",
                OutboundJoinHelper = helpers.FirstOrDefault(static helper => helper.Entry == "015ae358")?.Role ?? ""
            },
            helpers,
            nextNativeTargets = new[]
            {
                "Decompile 015938f8 to name the packet-to-player-object field population used by 015d5a00.",
                "Decompile 015ad060, 015acfb0, 015ae2a8, and 0158e430 to name the address/key structures passed into outbound join setup.",
                "Export callers for 015a2220/015a2300 to bind association state 2 and 3 to exact inbound native message phases."
            }
        }, JsonOptions));
    }

    private static HelperMap ReduceHelper(HelperFunction function)
    {
        return function.Entry switch
        {
            "01587ed8" => Map(function, "read-native-player-id-tuple", "Reads the packet reader object at param_1 + 4 through 015875c8 and seeds the decoded tuple/player id slot with 0x80000000. Ghidra currently removes most reader-body blocks, so this remains a partial tuple-reader map.", new[] { "param_1 + 4", "param_2[0]" }, new[] { "param_2[0] = 0x80000000" }),
            "0158e1a0" => Map(function, "reject-existing-connection-token", "Checks packet/session field +0x414. If no token exists and the caller allows the state, returns 0; otherwise logs the existing token and returns 1 to reject duplicate/invalid association handling.", new[] { "*(param_4 + 4) + 0x414", "param_2", "param_3" }, Array.Empty<string>()),
            "015a2220" => Map(function, "write-association-state-2", "Finds or inserts the association record for the peer/player id and writes state value 2.", new[] { "param_1 + 0x18", "param_1 + 0x1c", "param_1 + 0x25", "record[1]" }, new[] { "record[1] = 2" }),
            "015a2300" => Map(function, "write-association-state-3", "Finds or inserts the association record for the peer/player id and writes state value 3.", new[] { "param_1 + 0x18", "param_1 + 0x1c", "param_1 + 0x25", "record[1]" }, new[] { "record[1] = 3" }),
            "015a7178" => Map(function, "lookup-player-object-by-id", "Walks the linked player-object list at session +0x18c, dereferences each node to a player object, calls vtable +0x18 for the object id, and returns the object whose id matches param_2.", new[] { "param_1 + 0x18c", "player-object vtable +0x18", "node[1]" }, Array.Empty<string>()),
            "015d5a00" => Map(function, "get-or-create-join-player-object", "Reads the incoming player tuple, looks up an existing player object, allocates from the session pool when missing, inserts the object into the active list, populates it through 015938f8, updates lookup arrays at +0x1d0/+0x1e0, and kicks 015d01f8 when object state slot 0xb equals 6.", new[] { "param_1 + 0x17c", "param_1 + 0x180", "param_1 + 0x184", "param_1 + 0x188", "param_1 + 0x18c", "param_1 + 0x194", "param_1 + 0x198", "param_1 + 0x1d0", "param_1 + 0x1e0", "player[6]", "player[0xb]" }, new[] { "active_count + 1", "free_count - 1", "lookup_by_index[player.vtable+0x1c] = player", "lookup_by_slot[player[6]] = player" }),
            "0158f078" => Map(function, "mark-join-object-ready-if-backend-active", "If the joined player's backend/session object has flag +0x22c set and status +0xbc is not -2, queries a global controller and writes join-object flag +0x3c to 1 when the controller reports active.", new[] { "param_1 + 8", "player/session +0x22c", "player/session +0xbc", "param_1 + 0x3c" }, new[] { "param_1 + 0x3c = 1" }),
            "015ae358" => Map(function, "create-outbound-join-session-and-send", "Builds several address/key structures from the join object, chooses a target id from either the host/current player or join object slot 4, creates an outbound object through a manager at player-session +0x94, stores it in join object slot 10, then submits setup payloads and the boolean mode flag.", new[] { "param_1[2]", "param_1[4]", "param_1[10]", "player-session +0x94", "player +0x150", "player +0x169" }, new[] { "param_1[10] = outbound session object" }),
            _ => Map(function, "unclassified-helper", "Exported helper needs manual classification.", Array.Empty<string>(), Array.Empty<string>())
        };
    }

    private static HelperMap Map(HelperFunction function, string role, string semantics, string[] observedOffsets, string[] stateWrites)
    {
        return new HelperMap(
            function.Requested,
            function.Entry,
            function.Name,
            role,
            semantics,
            Callees(function.Body),
            observedOffsets,
            stateWrites,
            ExtractConditions(function.Body),
            function.Body.Length);
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

    private static string[] ExtractConditions(string body)
    {
        return body.Split('\n')
            .Select(static line => line.Trim())
            .Where(static line => line.StartsWith("if (", StringComparison.Ordinal) || line.StartsWith("while (", StringComparison.Ordinal))
            .Take(10)
            .ToArray();
    }

    private sealed record HelperFunction(string Requested, string Entry, string Name, string Body)
    {
        public static HelperFunction From(JsonElement element)
        {
            return new HelperFunction(
                GetString(element, "requested"),
                GetString(element, "entry"),
                GetString(element, "name"),
                GetString(element, "body"));
        }
    }

    private sealed record HelperMap(
        string Requested,
        string Entry,
        string Name,
        string Role,
        string Semantics,
        string[] Callees,
        string[] ObservedOffsets,
        string[] StateWrites,
        string[] Conditions,
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
