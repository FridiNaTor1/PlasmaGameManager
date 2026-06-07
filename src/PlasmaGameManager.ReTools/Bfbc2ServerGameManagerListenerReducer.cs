using System.Text.Json;
using System.Text.RegularExpressions;

namespace PlasmaGameManager.ReTools;

public static partial class Bfbc2ServerGameManagerListenerReducer
{
    public static async Task ReduceAsync(string functionsPath, string pointersPath, string outputPath)
    {
        using var functionDoc = JsonDocument.Parse(File.ReadAllText(functionsPath));
        using var pointerDoc = JsonDocument.Parse(File.ReadAllText(pointersPath));

        var functions = functionDoc.RootElement.GetProperty("functions").EnumerateArray()
            .Where(static row => row.TryGetProperty("entry", out var entry) && !string.IsNullOrWhiteSpace(entry.GetString()))
            .GroupBy(static row => row.GetProperty("entry").GetString() ?? "", StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => BuildFunction(group.First()), StringComparer.Ordinal);

        var pointerRows = pointerDoc.RootElement.GetProperty("targets").EnumerateArray()
            .SelectMany(target => target.GetProperty("dataPointers").EnumerateArray()
                .Select(pointer => new
                {
                    PointerAddress = pointer.GetProperty("address").GetString() ?? "",
                    Target = target.GetProperty("target").GetString() ?? "",
                    TargetName = target.GetProperty("targetName").GetString() ?? ""
                }))
            .Where(static row => row.PointerAddress.StartsWith("01782b", StringComparison.Ordinal))
            .OrderBy(static row => row.PointerAddress, StringComparer.Ordinal)
            .ToArray();

        var callbackTable = pointerRows
            .Select(row =>
            {
                functions.TryGetValue(row.Target, out var function);
                function ??= new ListenerFunction(row.Target, row.TargetName, "", "", "", "", [], [], 0, false, false, false);
                return new
                {
                    Index = PointerIndex(row.PointerAddress),
                    row.PointerAddress,
                    FunctionAddress = row.Target,
                    FunctionName = function.NativeName.Length == 0 ? row.TargetName : function.NativeName,
                    function.Role,
                    function.Status,
                    function.Semantics,
                    function.LogStrings,
                    function.Callees,
                    function.BodyLength
                };
            })
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-server-gamemanager-listener-vtable",
            note = "Reconstructs the BFBC2 ServerGameManagerListener callback table from .rdata pointer sites and recovered log-bearing functions. Some adjacent functions are jump-in aliases, so this table is reconstructed from data pointer addresses rather than Ghidra's contiguous-table heuristic.",
            summary = new
            {
                FunctionCount = functions.Count,
                CallbackPointerCount = callbackTable.Length,
                ImplementedCallbacks = callbackTable.Count(static row => row.Status == "implemented"),
                StubCallbacks = callbackTable.Count(static row => row.Status == "stub"),
                LifecycleCallbacks = callbackTable.Count(static row => row.Role.Contains("lifecycle", StringComparison.Ordinal))
            },
            callbackTableBase = "01782b4c",
            callbackTable,
            implementedFunctions = functions.Values
                .Where(static function => function.Status == "implemented")
                .OrderBy(static function => function.Entry, StringComparer.Ordinal)
                .ToArray(),
            unresolved = functions.Values
                .Where(static function => function.Status == "unknown")
                .OrderBy(static function => function.Entry, StringComparer.Ordinal)
                .ToArray()
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static ListenerFunction BuildFunction(JsonElement row)
    {
        var entry = row.GetProperty("entry").GetString() ?? "";
        var body = row.TryGetProperty("body", out var bodyElement) ? bodyElement.GetString() ?? "" : "";
        var strings = LogStringPattern().Matches(body)
            .Select(static match => match.Groups["value"].Value)
            .Where(static value => value.Contains("ServerGameManagerListener", StringComparison.Ordinal)
                || value.Contains("GM:", StringComparison.Ordinal)
                || value.Contains("not implemented", StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var nativeName = strings
            .FirstOrDefault(static value => value.StartsWith("dice::online::plasma::ServerGameManagerListener::", StringComparison.Ordinal))
            ?? "";
        var callees = CalleePattern().Matches(body)
            .Select(static match => match.Groups["target"].Value)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var isStub = body.Contains("is not implemented", StringComparison.Ordinal);
        var role = InferRole(nativeName, entry, body, callees, isStub);
        var status = isStub ? "stub" : role == "unknown" ? "unknown" : "implemented";
        var semantics = InferSemantics(role, nativeName, entry, body, callees, isStub);

        return new ListenerFunction(
            entry,
            nativeName,
            row.TryGetProperty("name", out var name) ? name.GetString() ?? "" : "",
            role,
            status,
            semantics,
            strings,
            callees,
            body.Length,
            body.Contains("00dac6a0", StringComparison.Ordinal) || callees.Contains("00dac6a0", StringComparer.Ordinal),
            body.Contains("00dac7b0", StringComparison.Ordinal) || callees.Contains("00dac7b0", StringComparer.Ordinal),
            body.Contains("00db6190", StringComparison.Ordinal) || callees.Contains("00db6190", StringComparer.Ordinal));
    }

    private static int PointerIndex(string pointerAddress)
    {
        var raw = Convert.ToInt32(pointerAddress, 16);
        return (raw - 0x01782b4c) / 4;
    }

    private static string InferRole(string nativeName, string entry, string body, string[] callees, bool isStub)
    {
        if (isStub)
        {
            return "unimplemented-callback";
        }

        if (nativeName.EndsWith("addPlayer", StringComparison.Ordinal) || nativeName.EndsWith("removePlayer", StringComparison.Ordinal))
        {
            return "player-list-maintenance";
        }

        if (nativeName.EndsWith("OnPlayerRequestedEntry", StringComparison.Ordinal))
        {
            return "player-entry-request";
        }

        if (nativeName.EndsWith("OnPlayerJoin", StringComparison.Ordinal) || entry == "00a0faa0")
        {
            return "player-join-lifecycle";
        }

        if (nativeName.EndsWith("OnGameCreated", StringComparison.Ordinal) || entry == "00a18af0")
        {
            return "game-created-lifecycle";
        }

        if (nativeName.EndsWith("OnPlayerLeave", StringComparison.Ordinal) || entry == "00a1c4f0")
        {
            return "player-leave-lifecycle";
        }

        if (nativeName.EndsWith("OnGameDestroyed", StringComparison.Ordinal))
        {
            return "game-destroyed-lifecycle";
        }

        if (nativeName.EndsWith("update", StringComparison.Ordinal))
        {
            return "periodic-maintenance";
        }

        if (nativeName.EndsWith("create", StringComparison.Ordinal))
        {
            return "listener-create";
        }

        if (nativeName.EndsWith("createGroup", StringComparison.Ordinal) || nativeName.EndsWith("destroyGroup", StringComparison.Ordinal))
        {
            return "group-maintenance";
        }

        if (nativeName.EndsWith("onPlayerVoiceCleanup", StringComparison.Ordinal))
        {
            return "voice-cleanup";
        }

        return "unknown";
    }

    private static string InferSemantics(string role, string nativeName, string entry, string body, string[] callees, bool isStub)
    {
        if (isStub)
        {
            return $"{ShortName(nativeName)} logs an explicit not-implemented callback path";
        }

        return role switch
        {
            "player-list-maintenance" => $"{ShortName(nativeName)} maintains ServerGameManagerListener player collections and validates player pointers",
            "player-entry-request" => "OnPlayerRequestedEntry is implemented and validates/logs requested player entry; field-level request handling still needs deeper decompile naming",
            "player-join-lifecycle" => "OnPlayerJoin is implemented; allocates/links player state and calls 00a08770 plus backend/player helpers before the roster/join phase functions run",
            "game-created-lifecycle" => "OnGameCreated is implemented; stores game attributes and persistent server info through ServerBackend setters",
            "player-leave-lifecycle" => "OnPlayerLeave is implemented; runs voice cleanup, backend player-left handling, and ServerGameManager::onPlayerLeft",
            "game-destroyed-lifecycle" => "OnGameDestroyed is implemented; tears down game/player state and routes through ServerGameManager::onPlayerLeft cleanup as needed",
            "periodic-maintenance" => "update performs timeout/maintenance polling and routes scheduled backend work",
            "listener-create" => "create initializes ServerGameManagerListener state and links it to backend/game manager objects",
            "group-maintenance" => $"{ShortName(nativeName)} manages listener group state",
            "voice-cleanup" => "onPlayerVoiceCleanup bridges player voice cleanup into backend voice state",
            _ => "unclassified recovered ServerGameManagerListener function"
        };
    }

    private static string ShortName(string nativeName)
    {
        var index = nativeName.LastIndexOf("::", StringComparison.Ordinal);
        return index < 0 ? nativeName : nativeName[(index + 2)..];
    }

    [GeneratedRegex("\"(?<value>[^\"]+)\"")]
    private static partial Regex LogStringPattern();

    [GeneratedRegex(@"FUN_(?<target>[0-9a-fA-F]{8})")]
    private static partial Regex CalleePattern();

    private sealed record ListenerFunction(
        string Entry,
        string NativeName,
        string GhidraName,
        string Role,
        string Status,
        string Semantics,
        string[] LogStrings,
        string[] Callees,
        int BodyLength,
        bool CallsMessageStart,
        bool CallsAddressedMessageStart,
        bool CallsRosterSend);
}
