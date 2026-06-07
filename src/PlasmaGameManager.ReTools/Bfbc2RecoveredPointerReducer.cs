using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Bfbc2RecoveredPointerReducer
{
    public static async Task ReduceAsync(string recoveredSummaryPath, string pointerEvidencePath, string outputPath)
    {
        using var recoveredDoc = JsonDocument.Parse(File.ReadAllText(recoveredSummaryPath));
        using var pointerDoc = JsonDocument.Parse(File.ReadAllText(pointerEvidencePath));

        var semantics = recoveredDoc.RootElement.GetProperty("functions").EnumerateArray()
            .Where(static e => e.TryGetProperty("Entry", out var entry) && (entry.GetString() ?? "").Length != 0)
            .GroupBy(static e => e.GetProperty("Entry").GetString() ?? "", StringComparer.Ordinal)
            .ToDictionary(
                static g => g.Key,
                static g =>
                {
                    var e = g.First();
                    return new RecoveredSemantic(
                        e.GetProperty("Group").GetString() ?? "unclassified",
                        e.GetProperty("Semantics").GetString() ?? "",
                        e.GetProperty("ShortNames").EnumerateArray()
                            .Select(static s => s.GetString() ?? "")
                            .Where(static s => s.Length != 0)
                            .ToArray());
                },
                StringComparer.Ordinal);
        foreach (var extra in LoadExtraUnknownSemantics(outputPath))
        {
            semantics[extra.Key] = extra.Value;
        }

        var targets = pointerDoc.RootElement.GetProperty("targets").EnumerateArray()
            .Select(e => BuildTarget(e, semantics))
            .OrderBy(static t => t.Target, StringComparer.Ordinal)
            .ToArray();

        var callbackTables = targets
            .SelectMany(static t => t.PointerTables)
            .GroupBy(static table => table.Base, StringComparer.Ordinal)
            .Select(g => new
            {
                Base = g.Key,
                EntryCount = g.Max(static table => table.EntryCount),
                Entries = g.SelectMany(static table => table.Entries)
                    .GroupBy(static entry => entry.Index)
                    .Select(entryGroup => entryGroup.First())
                    .OrderBy(static entry => entry.Index)
                    .ToArray()
            })
            .OrderBy(static table => table.Base, StringComparer.Ordinal)
            .ToArray();

        var singletonPointers = targets
            .Where(static t => t.DataPointers.Length != 0 && t.PointerTables.Length == 0)
            .Select(static t => new
            {
                t.Target,
                t.TargetName,
                t.Group,
                t.ShortNames,
                t.Semantics,
                DataPointers = t.DataPointers
            })
            .OrderBy(static t => t.DataPointers[0].Address, StringComparer.Ordinal)
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-recovered-callback-pointer-evidence",
            note = "Maps recovered BFBC2 Plasma callbacks to .rdata function-pointer sites and short contiguous callback tables. These are callback/vtable-style tables, not yet the complete packet dispatcher.",
            summary = new
            {
                TargetCount = targets.Length,
                TargetsWithDataPointers = targets.Count(static t => t.DataPointers.Length != 0),
                CallbackTableCount = callbackTables.Length,
                SingletonPointerCount = singletonPointers.Length,
                DirectCodeReferenceCount = targets.Sum(static t => t.DirectCodeReferences.Length)
            },
            callbackTables,
            singletonPointers,
            targets
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static PointerTarget BuildTarget(JsonElement element, Dictionary<string, RecoveredSemantic> semantics)
    {
        var target = element.GetProperty("target").GetString() ?? "";
        semantics.TryGetValue(target, out var semantic);
        semantic ??= new RecoveredSemantic("unclassified", "", Array.Empty<string>());

        var dataPointers = element.GetProperty("dataPointers").EnumerateArray()
            .Select(static e => new DataPointer(
                e.GetProperty("address").GetString() ?? "",
                e.GetProperty("block").GetString() ?? "",
                e.GetProperty("writable").GetBoolean(),
                e.GetProperty("executable").GetBoolean()))
            .ToArray();
        var directCodeReferences = element.GetProperty("directReferences").EnumerateArray()
            .Where(static e => e.GetProperty("type").GetString() != "DATA")
            .Select(static e => new DirectCodeReference(
                e.GetProperty("from").GetString() ?? "",
                e.GetProperty("type").GetString() ?? "",
                e.GetProperty("fromFunction").GetString() ?? "",
                e.GetProperty("fromFunctionEntry").GetString() ?? ""))
            .ToArray();
        var pointerTables = element.GetProperty("pointerTables").EnumerateArray()
            .Select(e => BuildPointerTable(e, semantics))
            .ToArray();

        return new PointerTarget(
            target,
            element.GetProperty("targetName").GetString() ?? "",
            semantic.Group,
            semantic.ShortNames,
            semantic.Semantics,
            dataPointers,
            directCodeReferences,
            pointerTables);
    }

    private static PointerTable BuildPointerTable(JsonElement element, Dictionary<string, RecoveredSemantic> semantics)
    {
        var entries = element.GetProperty("entries").EnumerateArray()
            .Select(e =>
            {
                var functionAddress = e.GetProperty("functionAddress").GetString() ?? "";
                semantics.TryGetValue(functionAddress, out var semantic);
                semantic ??= new RecoveredSemantic("unknown", "", Array.Empty<string>());
                return new PointerTableEntry(
                    e.GetProperty("index").GetInt32(),
                    e.GetProperty("pointerAddress").GetString() ?? "",
                    functionAddress,
                    e.GetProperty("functionName").GetString() ?? "",
                    semantic.Group,
                    semantic.ShortNames,
                    semantic.Semantics);
            })
            .ToArray();

        return new PointerTable(
            element.GetProperty("base").GetString() ?? "",
            element.GetProperty("entryCount").GetInt32(),
            entries);
    }

    private static Dictionary<string, RecoveredSemantic> LoadExtraUnknownSemantics(string outputPath)
    {
        var directory = Path.GetDirectoryName(outputPath);
        if (directory is null)
        {
            return new Dictionary<string, RecoveredSemantic>(StringComparer.Ordinal);
        }

        var path = Path.Combine(directory, "callback-table-unknown-decompiles.json");
        if (!File.Exists(path))
        {
            return new Dictionary<string, RecoveredSemantic>(StringComparer.Ordinal);
        }

        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        return doc.RootElement.GetProperty("functions").EnumerateArray()
            .Select(static e =>
            {
                var entry = e.TryGetProperty("entry", out var entryElement) ? entryElement.GetString() ?? "" : "";
                var body = e.TryGetProperty("body", out var bodyElement) ? bodyElement.GetString() ?? "" : "";
                return new KeyValuePair<string, RecoveredSemantic>(entry, InferExtraSemantic(entry, body));
            })
            .Where(static kvp => kvp.Key.Length != 0)
            .ToDictionary(static kvp => kvp.Key, static kvp => kvp.Value, StringComparer.Ordinal);
    }

    private static RecoveredSemantic InferExtraSemantic(string entry, string body)
    {
        if (entry == "00a08630" || (body.Contains("FUN_00a025c0", StringComparison.Ordinal) && body.Contains("FUN_004e3660", StringComparison.Ordinal)))
        {
            return new RecoveredSemantic(
                "player-lifecycle",
                "player lifecycle packet/send helper adjacent to OnPlayerLeave; builds a small serialized record and forwards it through the backend send path",
                ["player-send-helper"]);
        }

        if (entry == "00a1c140" || (body.Contains("0x43298", StringComparison.Ordinal) && body.Contains("0x27", StringComparison.Ordinal) && body.Contains("0x10", StringComparison.Ordinal)))
        {
            return new RecoveredSemantic(
                "backend-maintenance",
                "ServerBackend cleanup/reset sibling to create; clears backend state, releases connection-owned objects, and unregisters event hooks 0x27 and 0x10",
                ["cleanup"]);
        }

        return new RecoveredSemantic("unknown", "", Array.Empty<string>());
    }

    private sealed record RecoveredSemantic(string Group, string Semantics, string[] ShortNames);

    private sealed record PointerTarget(
        string Target,
        string TargetName,
        string Group,
        string[] ShortNames,
        string Semantics,
        DataPointer[] DataPointers,
        DirectCodeReference[] DirectCodeReferences,
        PointerTable[] PointerTables);

    private sealed record DataPointer(string Address, string Block, bool Writable, bool Executable);

    private sealed record DirectCodeReference(string From, string Type, string FromFunction, string FromFunctionEntry);

    private sealed record PointerTable(string Base, int EntryCount, PointerTableEntry[] Entries);

    private sealed record PointerTableEntry(
        int Index,
        string PointerAddress,
        string FunctionAddress,
        string FunctionName,
        string Group,
        string[] ShortNames,
        string Semantics);
}
