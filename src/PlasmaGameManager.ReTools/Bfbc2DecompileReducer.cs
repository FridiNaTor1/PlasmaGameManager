using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Bfbc2DecompileReducer
{
    public static async Task ReduceAsync(string handlersPath, string decompilesPath, string classMapPath)
    {
        using var handlersDoc = JsonDocument.Parse(File.ReadAllText(handlersPath));
        using var decompilesDoc = JsonDocument.Parse(File.ReadAllText(decompilesPath));

        var functionEvidence = handlersDoc.RootElement.GetProperty("serverRelevantFunctions")
            .EnumerateArray()
            .ToDictionary(
                static e => e.GetProperty("FunctionEntry").GetString() ?? "",
                static e => new
                {
                    Component = e.GetProperty("Component").GetString() ?? "",
                    Function = e.GetProperty("Function").GetString() ?? "",
                    ReferenceCount = e.GetProperty("ReferenceCount").GetInt32(),
                    EvidenceStrings = e.GetProperty("EvidenceStrings").EnumerateArray()
                        .Select(static s => s.GetString() ?? "")
                        .Where(static s => s.Length != 0)
                        .ToArray()
                },
                StringComparer.Ordinal);

        var functions = decompilesDoc.RootElement.GetProperty("functions")
            .EnumerateArray()
            .Select(e =>
            {
                var entry = e.GetProperty("entry").GetString() ?? e.GetProperty("requested").GetString() ?? "";
                functionEvidence.TryGetValue(entry, out var evidence);
                var body = e.TryGetProperty("body", out var bodyElement) ? bodyElement.GetString() ?? "" : "";
                var instructions = e.TryGetProperty("instructions", out var instructionsElement) ? instructionsElement.GetArrayLength() : 0;
                return new
                {
                    Entry = entry,
                    GhidraName = e.GetProperty("name").GetString() ?? "",
                    Signature = e.GetProperty("signature").GetString() ?? "",
                    Component = evidence?.Component ?? "Unknown",
                    EvidenceFunction = evidence?.Function ?? "",
                    EvidenceStrings = evidence?.EvidenceStrings ?? Array.Empty<string>(),
                    ReferenceCount = evidence?.ReferenceCount ?? 0,
                    Decompiled = body.Length > 0,
                    BodyLength = body.Length,
                    InstructionSampleCount = instructions,
                    Summary = Summarize(evidence?.Component ?? "", evidence?.EvidenceStrings ?? Array.Empty<string>(), body)
                };
            })
            .OrderBy(static f => f.Component, StringComparer.Ordinal)
            .ThenBy(static f => f.Entry, StringComparer.Ordinal)
            .ToArray();

        var classes = functions
            .GroupBy(static f => f.Component)
            .Select(static g => new
            {
                Component = g.Key,
                FunctionCount = g.Count(),
                Functions = g.ToArray()
            })
            .OrderBy(static c => c.Component, StringComparer.Ordinal)
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(classMapPath)!);
        await File.WriteAllTextAsync(classMapPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-focused-ghidra-xrefs-and-targeted-decompiles",
            note = "This is not full OOAnalyzer class recovery yet. It maps recovered function entries to likely BFBC2 Plasma/GameManager components.",
            classes
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static string Summarize(string component, string[] evidenceStrings, string body)
    {
        var joinedEvidence = string.Join(" | ", evidenceStrings);
        if (joinedEvidence.Contains("ServerGameManagerListener::create", StringComparison.Ordinal))
        {
            return "Constructs/initializes the server GameManager listener and links it to backend state.";
        }

        if (joinedEvidence.Contains("ServerGameManager::onPlayerLeft", StringComparison.Ordinal))
        {
            return "Handles player leave cleanup from the server GameManager side.";
        }

        if (joinedEvidence.Contains("ServerBackend::onAssociationsAdded", StringComparison.Ordinal))
        {
            return "Handles Plasma association-add callbacks after GameManager mesh/session association.";
        }

        if (joinedEvidence.Contains("ServerBackend::onAssociationOpened", StringComparison.Ordinal))
        {
            return "Handles opened Plasma association callback.";
        }

        if (joinedEvidence.Contains("ServerBackend::disconnect", StringComparison.Ordinal))
        {
            return "Disconnects Plasma backend and tears down server backend state.";
        }

        if (joinedEvidence.Contains("ServerBackend::setGameAttributes", StringComparison.Ordinal))
        {
            return "Stores or validates game attribute data before backend publication.";
        }

        if (component == "ServerGameManagerListener" && body.Contains("m_reverseIds", StringComparison.Ordinal))
        {
            return "ServerGameManagerListener reverse-id bookkeeping.";
        }

        return component.Length == 0 ? "Unclassified focused decompile target." : $"Focused {component} decompile target.";
    }
}
