using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Bfbc2JoinChainReducer
{
    public static async Task ReduceAsync(string functionsPath, string outputPath)
    {
        using var functionsDoc = JsonDocument.Parse(File.ReadAllText(functionsPath));
        var functions = functionsDoc.RootElement.GetProperty("functions").EnumerateArray()
            .Select(ParseFunction)
            .Where(static function => function.Entry.Length > 0)
            .OrderBy(static function => function.Entry, StringComparer.Ordinal)
            .ToArray();

        var rows = functions.Select(function => new
        {
            function.Entry,
            function.NativeName,
            function.GhidraName,
            Role = InferRole(function),
            Semantics = InferSemantics(function),
            function.Callees,
            function.LogStrings,
            BodyLength = function.Body.Length
        }).ToArray();

        var report = new
        {
            status = "seeded-from-bfbc2-on-player-join-callee-chain",
            note = "Summarizes the native BFBC2 path entered by ServerGameManagerListener::OnPlayerJoin and the adjacent unresolved listener-table slot. Field names remain conservative where the recovered function has no source log string.",
            joinPath = new[]
            {
                "OnPlayerJoin validates player and socket manager state.",
                "ServerSocketManager::addPlayer inserts the player by player ref and rejects duplicate refs.",
                "OnPlayerJoin copies player id/name into the listener player cache.",
                "ServerVoiceManager::addPlayer registers the player with the voice controller.",
                "A backend/event-bus record with event id 0x26 is emitted for the joined player.",
                "Two local player lookup maps are updated: one by player ref and one by a two-word secondary key."
            },
            stateSlot = new
            {
                Entry = "00a0fd50",
                CurrentClassification = "listener-state-drain",
                ObservedBehavior = "Requires listener state offset 0x14 to be 2, clears offset 0x88, initializes an iterator from the callback parameter, and sets state 3 when no records remain. When records exist it copies two variable strings into an owned record and inserts/looks up that record through an FNV-1a string-keyed hash table.",
                RemainingUnknowns = new[]
                {
                    "Exact callback name for table index 23.",
                    "Meaning of the two copied strings.",
                    "Which listener object owns the destination hash table."
                }
            },
            functions = rows,
            nextTargets = new[]
            {
                "Resolve event/vtable PTR_FUN_01732d84 used by 009d8920 event id 0x26.",
                "Cross-map TF.elf player-join flow against BFBC2 socket/voice/cache/event sequence."
            }
        };

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, JsonOptions));
    }

    private static FunctionRow ParseFunction(JsonElement element)
    {
        var body = element.TryGetProperty("body", out var bodyElement) ? bodyElement.GetString() ?? string.Empty : string.Empty;
        var entry = element.TryGetProperty("entry", out var entryElement) ? entryElement.GetString() ?? string.Empty : string.Empty;
        var ghidraName = element.TryGetProperty("name", out var nameElement) ? nameElement.GetString() ?? string.Empty : string.Empty;
        return new FunctionRow(
            entry,
            ExtractNativeName(body),
            ghidraName,
            ExtractLogStrings(body),
            ExtractCallees(body),
            body);
    }

    private static string InferRole(FunctionRow function)
    {
        return function.Entry switch
        {
            "00a0faa0" => "player-join-callback",
            "00a08770" => "socket-manager-add-player",
            "009cf3a0" => "voice-manager-add-player",
            "009d8920" => "backend-player-join-event",
            "00a05790" => "player-ref-cache-get-or-create",
            "00a05840" => "secondary-player-cache-get-or-create",
            "00a0fd50" => "listener-state-drain",
            "0054a5c0" => "two-string-record-builder",
            "0051f090" => "string-keyed-hash-insert",
            _ => "unknown"
        };
    }

    private static string InferSemantics(FunctionRow function)
    {
        return function.Entry switch
        {
            "00a0faa0" => "ServerGameManagerListener::OnPlayerJoin validates inputs, registers the player with the socket manager, copies id/name into backend caches, registers voice state, emits a backend player event, and links delayed player bookkeeping.",
            "00a08770" => "ServerSocketManager::addPlayer logs the player/ref index, verifies the player ref is not already present, and inserts the player pointer into the socket manager player map keyed by GetPlayerRef().",
            "009cf3a0" => "ServerVoiceManager::addPlayer validates that the voice controller exists, then dispatches to the controller vtable to register the player.",
            "009d8920" => "Builds a stack record containing player id/name data, tags it with vtable PTR_FUN_01732d84, and sends event id 0x26 through the backend/event manager.",
            "00a05790" => "Looks up or inserts a player-cache node keyed by player ref, returning the payload area at node + 0x18.",
            "00a05840" => "Looks up or inserts a secondary player-cache node keyed by a two-word value, returning the payload area at node + 0x18.",
            "00a0fd50" => "Unresolved listener callback slot 23. Observed as a state-2 iterator drain that clears pending state, copies two variable strings from each record, calls helper pair 0054a5c0/0051f090, and transitions state to 3 when no records remain.",
            "0054a5c0" => "Builds an owned record from two string spans: initializes two string buffers, allocates capacity length + 1, copies bytes, and null terminates both strings.",
            "0051f090" => "Looks up or inserts a record in an EASTL hash table keyed by a null-terminated string using FNV-1a seed 0x811c9dc5 and multiplier 0x1000193.",
            _ => "unclassified join-chain function"
        };
    }

    private static string ExtractNativeName(string body)
    {
        var fallback = string.Empty;
        foreach (var value in ExtractLogStrings(body))
        {
            if (value.Contains("dice::", StringComparison.Ordinal))
            {
                return value;
            }

            if (fallback.Length == 0 && !value.Contains('\\', StringComparison.Ordinal))
            {
                fallback = value;
            }
        }

        return fallback;
    }

    private static string[] ExtractLogStrings(string body)
    {
        var strings = new List<string>();
        var inString = false;
        var current = new System.Text.StringBuilder();
        for (var i = 0; i < body.Length; i++)
        {
            var c = body[i];
            if (!inString)
            {
                if (c == '"')
                {
                    inString = true;
                    current.Clear();
                }
                continue;
            }

            if (c == '\\' && i + 1 < body.Length)
            {
                var next = body[++i];
                current.Append(next switch
                {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    _ => next
                });
                continue;
            }

            if (c == '"')
            {
                var value = current.ToString();
                if (value.Contains("Server", StringComparison.Ordinal)
                    || value.Contains("Plasma", StringComparison.Ordinal)
                    || value.Contains("Adding player", StringComparison.Ordinal)
                    || value.Contains("socketManager", StringComparison.Ordinal)
                    || value.Contains("m_controller", StringComparison.Ordinal))
                {
                    strings.Add(value);
                }

                inString = false;
                continue;
            }

            current.Append(c);
        }

        return strings.Distinct(StringComparer.Ordinal).ToArray();
    }

    private static string[] ExtractCallees(string body)
    {
        var callees = new HashSet<string>(StringComparer.Ordinal);
        for (var index = body.IndexOf("FUN_", StringComparison.Ordinal); index >= 0; index = body.IndexOf("FUN_", index + 4, StringComparison.Ordinal))
        {
            if (index + 12 <= body.Length)
            {
                var candidate = body.Substring(index + 4, 8);
                if (candidate.All(static c => char.IsDigit(c) || c is >= 'a' and <= 'f'))
                {
                    callees.Add(candidate);
                }
            }
        }

        return callees.Order(StringComparer.Ordinal).ToArray();
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private sealed record FunctionRow(
        string Entry,
        string NativeName,
        string GhidraName,
        string[] LogStrings,
        string[] Callees,
        string Body);
}
