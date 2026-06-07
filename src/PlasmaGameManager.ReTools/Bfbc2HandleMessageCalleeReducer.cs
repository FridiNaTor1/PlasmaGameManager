using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Bfbc2HandleMessageCalleeReducer
{
    public static async Task ReduceAsync(string calleeDecompilesPath, string handleMessageMapPath, string outputPath)
    {
        using var calleeDoc = JsonDocument.Parse(File.ReadAllText(calleeDecompilesPath));
        using var branchDoc = JsonDocument.Parse(File.ReadAllText(handleMessageMapPath));

        var functions = calleeDoc.RootElement.GetProperty("functions").EnumerateArray()
            .Select(ParseFunction)
            .Where(static function => function.Entry.Length > 0)
            .Select(ReduceFunction)
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-bfbc2-handlemessage-callee-decompiles",
            note = "Reduces the two concrete callees behind handleMessage group 0x10/message 0x1d. This names that branch as switch-squad behavior instead of a generic player/session forward.",
            parentBranch = branchDoc.RootElement.GetProperty("branches").EnumerateArray()
                .Where(static branch => branch.GetProperty("Group").GetString() == "0x10" && branch.GetProperty("Message").GetString() == "0x1d")
                .Select(static branch => new
                {
                    branch = "0x10/0x1d",
                    role = branch.GetProperty("Role").GetString() ?? "",
                    confidence = branch.GetProperty("Confidence").GetString() ?? ""
                })
                .FirstOrDefault(),
            summary = new
            {
                FunctionCount = functions.Length,
                ConfirmedFunctions = functions.Count(static function => function.Confidence == "confirmed"),
                Roles = functions.Select(static function => function.Role).ToArray()
            },
            functions,
            nextTargets = new[]
            {
                "Export 00a3e880 to name the switch-squad backend mutation path.",
                "Cross-map TF.elf branches for switch-squad/team-change behavior; this may be gameplay state rather than join-state GameManager.",
                "Keep this branch separate from TF2 join/create roster semantics unless TF.elf shows the same group/message ids."
            }
        }, JsonOptions));
    }

    private static FunctionRow ParseFunction(JsonElement element)
    {
        var body = element.TryGetProperty("body", out var bodyElement) ? bodyElement.GetString() ?? "" : "";
        return new FunctionRow(
            element.TryGetProperty("entry", out var entryElement) ? entryElement.GetString() ?? "" : "",
            element.TryGetProperty("name", out var nameElement) ? nameElement.GetString() ?? "" : "",
            body,
            body.Length);
    }

    private static ReducedFunction ReduceFunction(FunctionRow function)
    {
        return function.Entry switch
        {
            "00a3ed30" => new ReducedFunction(
                function.Entry,
                function.GhidraName,
                "on-player-switch-squad",
                HasAll(function.Body, "onPlayerSwitchSquad", "FUN_009dc130", "FUN_00a3e880", "return *(undefined2 *)(iStack_ac + 0x1c)") ? "confirmed" : "partial",
                "Validates user/player identity, looks up the player record through the listener player table at this+0x60, rejects the sentinel at this+0x64 as non-existent, calls 00a3e880 with the player id and requested squad/team fields, and returns the player-record short at +0x1c.",
                new[]
                {
                    "param_2/param_3: player/user identity pair; both zero logs 'Attempting to switch squad with no user'",
                    "param_4/param_5/param_6: requested switch-squad fields logged as onPlayerSwitchSquad(...)",
                    "param_7: forwarded to 00a3e880 as final request/context field"
                },
                "short from matched player record offset +0x1c, or 0 on invalid/no user.",
                new[] { "009dc130", "00a3e880" },
                function.BodyLength),
            "005f95f0" => new ReducedFunction(
                function.Entry,
                function.GhidraName,
                "apply-switch-squad-result",
                HasAll(function.Body, "param_1 + 0x148", "param_1 + 0xc10", "FUN_00fff990") ? "confirmed" : "partial",
                "Applies the returned short to object offset +0x148. If the value changes and the notification pointer at +0xc10 is present, emits notification/event type 4 using the high/low words of +0xc14.",
                new[]
                {
                    "param_1: player/gameplay object that owns switch-squad state",
                    "param_2: short returned by onPlayerSwitchSquad"
                },
                "Updates object offset +0x148 and optionally emits event type 4 through 00fff990.",
                new[] { "00fff990" },
                function.BodyLength),
            _ => new ReducedFunction(
                function.Entry,
                function.GhidraName,
                "unknown",
                "unknown",
                "Unclassified handleMessage callee.",
                Array.Empty<string>(),
                "",
                Array.Empty<string>(),
                function.BodyLength)
        };
    }

    private static bool HasAll(string body, params string[] patterns)
    {
        return patterns.All(pattern => body.Contains(pattern, StringComparison.Ordinal));
    }

    private sealed record FunctionRow(string Entry, string GhidraName, string Body, int BodyLength);

    private sealed record ReducedFunction(
        string Entry,
        string GhidraName,
        string Role,
        string Confidence,
        string Semantics,
        string[] Inputs,
        string Output,
        string[] KeyCallees,
        int BodyLength);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}
