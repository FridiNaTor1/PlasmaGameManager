using System.Text.Json;
using System.Text.RegularExpressions;

namespace PlasmaGameManager.ReTools;

public static partial class Bfbc2EvidenceReducer
{
    public static async Task ReduceAsync(string evidencePath, string reportDirectory)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(evidencePath));
        var strings = doc.RootElement.GetProperty("strings").EnumerateArray()
            .Select(static e => new EvidenceString(
                e.GetProperty("address").GetString() ?? "",
                e.GetProperty("needle").GetString() ?? "",
                e.GetProperty("value").GetString() ?? ""))
            .ToArray();
        var stringByAddress = strings.ToDictionary(static s => s.Address, StringComparer.Ordinal);
        var references = doc.RootElement.TryGetProperty("references", out var referencesElement)
            ? referencesElement.EnumerateArray()
                .Select(e => new EvidenceReference(
                    e.GetProperty("stringAddress").GetString() ?? "",
                    e.GetProperty("from").GetString() ?? "",
                    e.GetProperty("function").GetString() ?? "",
                    e.GetProperty("functionEntry").GetString() ?? "",
                    e.GetProperty("needle").GetString() ?? ""))
                .ToArray()
            : Array.Empty<EvidenceReference>();

        var handlerCandidates = strings
            .Where(static s => s.Value.Contains("GameManager", StringComparison.Ordinal) || s.Value.Contains("ServerBackend", StringComparison.Ordinal))
            .Where(static s => s.Value.StartsWith("dice::", StringComparison.Ordinal) || s.Value.Contains("ServerGameManagerListener.cpp", StringComparison.Ordinal))
            .Select(static s => new
            {
                s.Address,
                Symbol = s.Value,
                Component = ComponentFor(s.Value),
                Handler = HandlerFor(s.Value),
                ReferenceSites = Array.Empty<object>(),
                Evidence = "ghidra-string-export"
            })
            .Where(static h => h.Handler.Length != 0)
            .DistinctBy(static h => h.Symbol)
            .OrderBy(static h => h.Component, StringComparer.Ordinal)
            .ThenBy(static h => h.Handler, StringComparer.Ordinal)
            .ToArray();
        var sourceReferenceSites = references
            .Select(r => new
            {
                Reference = r,
                Text = stringByAddress.TryGetValue(r.StringAddress, out var str) ? str.Value : ""
            })
            .Where(static x => IsPlasmaGameManagerSourceOrSymbol(x.Text))
            .Select(static x => new
            {
                x.Reference.StringAddress,
                x.Reference.From,
                x.Reference.Function,
                x.Reference.FunctionEntry,
                Text = x.Text,
                Component = ComponentFor(x.Text),
                Handler = HandlerFor(x.Text),
                Evidence = "focused-ghidra-xref"
            })
            .OrderBy(static x => x.Component, StringComparer.Ordinal)
            .ThenBy(static x => x.FunctionEntry, StringComparer.Ordinal)
            .ThenBy(static x => x.From, StringComparer.Ordinal)
            .ToArray();
        var serverRelevantFunctions = sourceReferenceSites
            .Where(static x => x.Component is "ServerGameManagerListener" or "ServerGameManager" or "ServerBackend")
            .Where(static x => x.FunctionEntry.Length != 0)
            .GroupBy(static x => new { x.Component, x.Function, x.FunctionEntry })
            .Select(static g => new
            {
                g.Key.Component,
                g.Key.Function,
                g.Key.FunctionEntry,
                ReferenceCount = g.Count(),
                EvidenceStrings = g.Select(static x => x.Text).Distinct().Take(8).ToArray()
            })
            .OrderBy(static x => x.Component, StringComparer.Ordinal)
            .ThenBy(static x => x.FunctionEntry, StringComparer.Ordinal)
            .ToArray();

        var packetTypes = strings
            .Where(static s => IsExactPacketName(s.Value))
            .Select(static s => new
            {
                s.Address,
                Name = s.Value,
                Evidence = "ghidra-string-export",
                Meaning = PacketMeaning(s.Value)
            })
            .DistinctBy(static p => p.Name)
            .OrderBy(static p => p.Name, StringComparer.Ordinal)
            .ToArray();
        var packetTypeNames = packetTypes.Select(static p => p.Name).ToHashSet(StringComparer.Ordinal);
        var pcapSeededPacketTypes = KnownPacketNames()
            .Where(name => !packetTypeNames.Contains(name))
            .Select(name => new
            {
                Address = "",
                Name = name,
                Evidence = "pcap-known-marker",
                Meaning = PacketMeaning(name)
            })
            .ToArray();

        Directory.CreateDirectory(reportDirectory);
        await WriteJson(Path.Combine(reportDirectory, "handlers.json"), new
        {
            status = "seeded-from-bfbc2-ghidra-string-evidence",
            note = "Address values on handlerCandidates are string addresses. sourceReferenceSites and serverRelevantFunctions come from the focused Ghidra xref pass.",
            handlerCandidates,
            sourceReferenceSites,
            serverRelevantFunctions
        });

        await WriteJson(Path.Combine(reportDirectory, "packet-types.json"), new
        {
            status = "seeded-from-bfbc2-ghidra-string-evidence-and-pcap-known-markers",
            packetTypes = packetTypes.Cast<object>().Concat(pcapSeededPacketTypes.Cast<object>()).ToArray()
        });

        await WriteJson(Path.Combine(reportDirectory, "dispatcher-table.json"), new
        {
            status = "pending-full-analysis",
            evidence = "handlers.json has named listener callbacks plus focused Ghidra xrefs. Dispatcher slots still require vtable/callsite recovery.",
            requiredNextSteps = new[]
            {
                "Run OOAnalyzer or targeted vtable recovery on BFBC2_R34.",
                "Resolve ServerGameManager::handleMessage references.",
                "Map listener callback vtable entries to packet constructors and send paths."
            },
            serverRelevantFunctions,
            sourceReferenceSiteCount = sourceReferenceSites.Length,
            slots = Array.Empty<object>()
        });
    }

    private static string ComponentFor(string value)
    {
        if (value.Contains("ServerGameManagerListener", StringComparison.Ordinal))
        {
            return "ServerGameManagerListener";
        }

        if (value.Contains("ServerGameManager", StringComparison.Ordinal))
        {
            return "ServerGameManager";
        }

        if (value.Contains("ClientGameManagerListener", StringComparison.Ordinal))
        {
            return "ClientGameManagerListener";
        }

        if (value.Contains("ServerBackend", StringComparison.Ordinal))
        {
            return "ServerBackend";
        }

        return "Unknown";
    }

    private static string HandlerFor(string value)
    {
        var match = CppSymbolPattern().Match(value);
        if (match.Success)
        {
            return match.Groups["method"].Value;
        }

        var sourceLine = SourceLinePattern().Match(value);
        return sourceLine.Success ? $"line-{sourceLine.Groups["line"].Value}" : "";
    }

    private static bool IsPlasmaGameManagerSourceOrSymbol(string value)
    {
        return value.Contains("ServerGameManager", StringComparison.Ordinal)
            || value.Contains("ClientGameManager", StringComparison.Ordinal)
            || value.Contains("ServerBackend", StringComparison.Ordinal)
            || value.Contains("Engine/Game/Server/Backend/Plasma/", StringComparison.Ordinal)
            || value.Contains("Engine/Game/Online/Presence/Plasma/", StringComparison.Ordinal);
    }

    private static bool IsExactPacketName(string value)
    {
        return KnownPacketNames().Contains(value, StringComparer.Ordinal);
    }

    private static string[] KnownPacketNames() => ["EGEG", "EGRS", "PENT", "UGAM", "UBRA", "COc", "PNG", "DSC"];

    private static string PacketMeaning(string value)
    {
        return value switch
        {
            "EGEG" => "client game entry/reservation request",
            "EGRS" => "server reservation/entry grant",
            "PENT" => "player entered notification",
            "UGAM" => "game update/join announcement",
            "UBRA" => "mesh/association/start update",
            "COc" => "roster/object record",
            "PNG" => "ping/heartbeat or roster-adjacent object marker",
            "DSC" => "disconnect/control marker",
            _ => "unknown"
        };
    }

    private static Task WriteJson(string path, object value)
    {
        return File.WriteAllTextAsync(path, JsonSerializer.Serialize(value, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
    }

    private sealed record EvidenceString(string Address, string Needle, string Value);

    private sealed record EvidenceReference(string StringAddress, string From, string Function, string FunctionEntry, string Needle);

    [GeneratedRegex("::(?<method>~?[A-Za-z0-9_]+)$", RegexOptions.CultureInvariant)]
    private static partial Regex CppSymbolPattern();

    [GeneratedRegex("\\.cpp\\((?<line>[0-9]+)\\)", RegexOptions.CultureInvariant)]
    private static partial Regex SourceLinePattern();
}
