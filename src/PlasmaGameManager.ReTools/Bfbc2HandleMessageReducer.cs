using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Bfbc2HandleMessageReducer
{
    private const string DispatcherEntry = "00a3ef70";

    public static async Task ReduceAsync(string decompilesPath, string completeListenerMapPath, string outputPath)
    {
        using var decompilesDoc = JsonDocument.Parse(File.ReadAllText(decompilesPath));
        using var listenerDoc = JsonDocument.Parse(File.ReadAllText(completeListenerMapPath));

        var function = decompilesDoc.RootElement.GetProperty("functions").EnumerateArray()
            .FirstOrDefault(static row => row.TryGetProperty("entry", out var entry) && entry.GetString() == DispatcherEntry);
        if (function.ValueKind == JsonValueKind.Undefined)
        {
            throw new InvalidDataException($"Missing {DispatcherEntry} in {decompilesPath}.");
        }

        var body = function.TryGetProperty("body", out var bodyElement) ? bodyElement.GetString() ?? "" : "";
        var slot = listenerDoc.RootElement.GetProperty("slots").EnumerateArray()
            .FirstOrDefault(static row => row.GetProperty("FunctionAddress").GetString() == DispatcherEntry);

        var branches = new[]
        {
            Branch(
                body,
                group: 0x10,
                message: 0x1d,
                role: "player-switch-squad-dispatch",
                stateEffect: "Resolves a player switch-squad request from param_5 offsets 0x18/0x1c/0xa8/0xac/0x144/0x154, then applies the returned short through 005f95f0.",
                semantics: "Requires a backend pointer and a player/session object. It asserts player presence when param_5 is null, checks backend online state unless the payload subtype is 0x18, calls 00a3ed30 / ServerGameManagerListener::onPlayerSwitchSquad, then forwards the returned short to 005f95f0 for state update/notification.",
                evidencePatterns: new[] { "param_2 == 0x10", "param_3 == 0x1d", "func_0x00a3ed30", "func_0x005f95f0" }),
            Branch(
                body,
                group: 0x26,
                message: 0x14,
                role: "player-association-cleanup",
                stateEffect: "Walks the listener player list at this+0x50 and removes the entry whose player ref matches payload param_4+0x30.",
                semantics: "Requires backend, active game object, and payload. It compares the payload player ref with cached listener player refs and unlinks the matching association node through 009e4150.",
                evidencePatterns: new[] { "param_2 == 0x26", "param_3 == 0x14", "param_1 + 0x50", "FUN_009e4150" }),
            Branch(
                body,
                group: 0x27,
                message: 0x18,
                role: "game-start-state-advance",
                stateEffect: "Sets listener flag this+0x2c and advances this+0x14 from 0 to 1 when enough players exist, then from 1 to 2 on the next qualifying update.",
                semantics: "Uses Server.PlayerCountNeededForMultiplayer, game state this+0x10 == 2, and game vtable calls +0xc8/+0xcc to advance native multiplayer startup state.",
                evidencePatterns: new[] { "param_2 == 0x27", "param_3 == 0x18", "Server.PlayerCountNeededForMultiplayer", "param_1 + 0x14" }),
            Branch(
                body,
                group: 0x27,
                message: 0x1a,
                role: "pb-backchannel-player-index",
                stateEffect: "If payload bytes start with PB_, resolves endpoint/player identity and sends callback id 0x0d with the resolved player index and payload bytes.",
                semantics: "BFBC2-specific PunkBuster/data-collection backchannel. It validates payload length, matches endpoint address/port against active players, derives a zero-based player index, and calls 006a66e0(0x0d, index, length, bytes).",
                evidencePatterns: new[] { "param_2 == 0x27", "param_3 == 0x1a", "0x50", "0x42", "0x5f", "FUN_006a66e0(0xd" })
        };

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-bfbc2-server-gamemanager-listener-handlemessage",
            note = "Reduces BFBC2 ServerGameManagerListener::handleMessage from the targeted Ghidra decompile. This names the native dispatcher branch families without claiming field-complete payload decoding yet.",
            dispatcher = new
            {
                Entry = DispatcherEntry,
                ListenerTableSlot = slot.ValueKind == JsonValueKind.Undefined ? -1 : slot.GetProperty("Index").GetInt32(),
                FunctionName = slot.ValueKind == JsonValueKind.Undefined ? "" : slot.GetProperty("FunctionName").GetString() ?? "",
                BodyLength = body.Length
            },
            parameters = new[]
            {
                new { Name = "param_2", Meaning = "primary native message group discriminator", ObservedValues = new[] { "0x10", "0x26", "0x27" } },
                new { Name = "param_3", Meaning = "message id inside the primary group", ObservedValues = new[] { "0x14", "0x18", "0x1a", "0x1d" } },
                new { Name = "param_4", Meaning = "optional payload/context object used by group 0x26 and group 0x27 message 0x1a", ObservedValues = Array.Empty<string>() },
                new { Name = "param_5", Meaning = "player/session message object used by group 0x10 message 0x1d", ObservedValues = Array.Empty<string>() }
            },
            summary = new
            {
                BranchCount = branches.Length,
                ConfirmedBranches = branches.Count(static branch => branch.Confidence == "confirmed"),
                PrimaryGroups = branches.Select(static branch => branch.Group).Distinct(StringComparer.Ordinal).ToArray(),
                MessageIds = branches.Select(static branch => branch.Message).Distinct(StringComparer.Ordinal).ToArray()
            },
            branches,
            nextTargets = new[]
            {
                "Reduce callees 00a3ed30 and 005f95f0 to field-level switch-squad semantics.",
                "Cross-map TF.elf GameManager receive branches against BFBC2 group/message pairs.",
                "Decide whether group 0x27 message 0x1a is BFBC2-only backchannel behavior or has a TF2 analogue."
            }
        }, JsonOptions));
    }

    private static HandleMessageBranch Branch(string body, int group, int message, string role, string stateEffect, string semantics, string[] evidencePatterns)
    {
        var missingPatterns = evidencePatterns.Where(pattern => !body.Contains(pattern, StringComparison.Ordinal)).ToArray();
        return new HandleMessageBranch(
            Group: $"0x{group:x2}",
            Message: $"0x{message:x2}",
            Role: role,
            Confidence: missingPatterns.Length == 0 ? "confirmed" : "partial",
            StateEffect: stateEffect,
            Semantics: semantics,
            EvidencePatterns: evidencePatterns,
            MissingEvidencePatterns: missingPatterns);
    }

    private sealed record HandleMessageBranch(
        string Group,
        string Message,
        string Role,
        string Confidence,
        string StateEffect,
        string Semantics,
        string[] EvidencePatterns,
        string[] MissingEvidencePatterns);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}
