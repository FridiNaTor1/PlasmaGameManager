using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Bfbc2GameManagerPhaseReducer
{
    public static async Task ReduceAsync(string logFunctionsPath, string builderFunctionsPath, string outputPath)
    {
        using var logDoc = JsonDocument.Parse(File.ReadAllText(logFunctionsPath));
        using var builderDoc = JsonDocument.Parse(File.ReadAllText(builderFunctionsPath));

        var logFunctions = logDoc.RootElement.GetProperty("functions").EnumerateArray()
            .Where(static f => f.TryGetProperty("entry", out var entry) && entry.GetString() is { Length: > 0 })
            .GroupBy(static f => f.GetProperty("entry").GetString() ?? "", StringComparer.Ordinal)
            .ToDictionary(static g => g.Key, static g => g.First(), StringComparer.Ordinal);
        var builderFunctions = builderDoc.RootElement.GetProperty("functions").EnumerateArray()
            .Where(static f => f.TryGetProperty("entry", out var entry) && entry.GetString() is { Length: > 0 })
            .GroupBy(static f => f.GetProperty("entry").GetString() ?? "", StringComparer.Ordinal)
            .ToDictionary(static g => g.Key, static g => g.First(), StringComparer.Ordinal);

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-native-bfbc2-gamemanager-log-functions",
            note = "Maps BFBC2 GameManager roster/join/mesh phases from native log-bearing functions and shared message-builder helpers. This is stronger than PCAP replay, but remaining packet fields still need complete writer-offset naming.",
            builderHelpers = BuildHelpers(builderFunctions),
            phases = BuildPhases(logFunctions),
            nextTargets = new[]
            {
                "Name writer vtables PTR_FUN_018283c8 and PTR_FUN_018283cc.",
                "Resolve callback/listener entries that call these phase functions.",
                "Map TF.elf packet type 2/3/4/5/8/9 fields against the BFBC2 phase map."
            }
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static object[] BuildHelpers(IReadOnlyDictionary<string, JsonElement> functions)
    {
        return
        [
            Helper(functions, "00dac6a0", "message-start", "allocates a 0x4b0 writer buffer and writes the one-byte GameManager message type using biased signed-byte encoding (type + 0x80)"),
            Helper(functions, "00dac7b0", "addressed-message-start", "calls message-start, switches to the addressed writer vtable, then writes the target/player id using biased 32-bit encoding (id + 0x80000000)"),
            Helper(functions, "00da9e20", "write-biased-int32-with-slice-bookkeeping", "writes a biased 32-bit value and tracks writer slice bounds/error state"),
            Helper(functions, "00da9ed0", "serialize-object", "delegates object serialization through the object's vtable and restores writer slice state on error"),
            Helper(functions, "00dab2e0", "write-player-details", "serializes player/session detail blocks from backend and player objects"),
            Helper(functions, "00dc73a0", "make-connection-association", "builds/logs a connident string and creates the association object used for mesh/join relationships")
        ];
    }

    private static object Helper(IReadOnlyDictionary<string, JsonElement> functions, string entry, string role, string semantics)
    {
        functions.TryGetValue(entry, out var function);
        return new
        {
            Entry = entry,
            Role = role,
            Semantics = semantics,
            BodyLength = function.ValueKind == JsonValueKind.Undefined
                ? 0
                : function.TryGetProperty("body", out var body) ? (body.GetString() ?? "").Length : 0
        };
    }

    private static object[] BuildPhases(IReadOnlyDictionary<string, JsonElement> functions)
    {
        return
        [
            Phase(functions, "00db6190", "send-roster",
                "counts eligible players, emits roster header to the target player, then emits one roster element for each eligible player",
                new[] { Message(2, "roster header"), Message(3, "roster element") },
                new[] { "GM: Sent roster to player %i (%i elements)" }),
            Phase(functions, "00dc6d00", "receive-roster-ack-and-send-join-announcement",
                "handles roster ack from player, marks player state 5 when needed, sends join announcement, then sends addressed mesh/join details",
                new[] { Message(5, "join announcement"), Message(9, "addressed join details") },
                new[] { "GM: Received roster ack from player %i.", "GM: Sent join announcement for player %i." }),
            Phase(functions, "00dc44d0", "send-join-mesh-announcement",
                "iterates active players in state 5, sends mesh announcement and addressed join detail records, then decrements pending join counters",
                new[] { Message(8, "join mesh announcement"), Message(9, "addressed join details") },
                new[] { "GM: Sent join mesh announcement for player %i." }),
            Phase(functions, "00dc7d90", "receive-roster-element",
                "processes a roster element, resolves the player object, updates roster notice counters, and sends host roster ack when complete",
                new[] { Message(4, "roster ack to host") },
                new[] { "GM: Received roster element.", "GM: Processed roster notice for player id %i (%d of %d).", "GM: Sent roster ack to host." }),
            Phase(functions, "00dc7e04", "process-roster-notice-and-send-host-ack",
                "updates roster notice counters from a non-element path and sends host roster ack when all notices have arrived",
                new[] { Message(4, "roster ack to host") },
                new[] { "GM: Processed roster notice for player id %i (%d of %d).", "GM: Sent roster ack to host." })
        ];
    }

    private static object Phase(
        IReadOnlyDictionary<string, JsonElement> functions,
        string entry,
        string role,
        string semantics,
        object[] outgoingMessages,
        string[] logStrings)
    {
        functions.TryGetValue(entry, out var function);
        return new
        {
            Entry = entry,
            Role = role,
            Semantics = semantics,
            OutgoingMessages = outgoingMessages,
            LogStrings = logStrings,
            BodyLength = function.ValueKind == JsonValueKind.Undefined
                ? 0
                : function.TryGetProperty("body", out var body) ? (body.GetString() ?? "").Length : 0,
            PresentInExport = function.ValueKind != JsonValueKind.Undefined
        };
    }

    private static object Message(int type, string meaning)
    {
        return new
        {
            Type = type,
            EncodedTypeByte = $"0x{type + 0x80:x2}",
            Meaning = meaning
        };
    }
}
