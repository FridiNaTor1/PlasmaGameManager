using System.Text.Json;
using System.Text.RegularExpressions;

namespace PlasmaGameManager.ReTools;

public static partial class Bfbc2RecoveredCallsiteReducer
{
    public static async Task ReduceAsync(string recoveredFunctionsPath, string outputPath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(recoveredFunctionsPath));

        var functions = doc.RootElement.GetProperty("functions").EnumerateArray()
            .Select(BuildSummary)
            .OrderBy(static f => f.Entry, StringComparer.Ordinal)
            .ThenBy(static f => f.Requested, StringComparer.Ordinal)
            .ToArray();

        var uniqueFunctions = functions
            .GroupBy(static f => f.Entry, StringComparer.Ordinal)
            .Select(static g => g.First())
            .OrderBy(static f => f.Entry, StringComparer.Ordinal)
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-recovered-ghidra-callsite-functions",
            note = "These functions were recovered from raw direct callsites that were outside Ghidra function boundaries in the focused pass. They expose additional BFBC2 Plasma server callback semantics.",
            summary = new
            {
                RequestedCallsites = functions.Length,
                UniqueRecoveredFunctions = uniqueFunctions.Length,
                CreatedFunctions = functions.Count(static f => f.Status == "created-function"),
                ExistingFunctions = functions.Count(static f => f.Status == "existing-function"),
                MissingOrFailed = functions.Count(static f => !f.ContainsRequested)
            },
            semanticGroups = new
            {
                ConnectionLifecycle = uniqueFunctions.Where(static f => f.Group == "connection-lifecycle").ToArray(),
                GameLifecycle = uniqueFunctions.Where(static f => f.Group == "game-lifecycle").ToArray(),
                AssociationLifecycle = uniqueFunctions.Where(static f => f.Group == "association-lifecycle").ToArray(),
                PlayerLifecycle = uniqueFunctions.Where(static f => f.Group == "player-lifecycle").ToArray(),
                BackendMaintenance = uniqueFunctions.Where(static f => f.Group == "backend-maintenance").ToArray(),
                Unclassified = uniqueFunctions.Where(static f => f.Group == "unclassified").ToArray()
            },
            functions
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static RecoveredFunctionSummary BuildSummary(JsonElement functionElement)
    {
        var body = functionElement.TryGetProperty("body", out var bodyElement) ? bodyElement.GetString() ?? "" : "";
        var requested = functionElement.GetProperty("requested").GetString() ?? "";
        var entry = functionElement.TryGetProperty("entry", out var entryElement) ? entryElement.GetString() ?? "" : "";
        var logStrings = LogStringPattern().Matches(body)
            .Select(static m => m.Groups["value"].Value)
            .Where(static value => IsRelevant(value))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var symbolNames = logStrings
            .Where(static value => value.StartsWith("dice::", StringComparison.Ordinal))
            .ToArray();
        var shortNames = symbolNames
            .Select(static value => value.Split("::").Last())
            .Concat(KnownShortNamesFromBody(body))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var callees = CalleePattern().Matches(body)
            .Select(static m => m.Groups["target"].Value)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var stateOffsets = StateOffsetPattern().Matches(body)
            .Select(static m => "0x" + m.Groups["offset"].Value)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var constants = InterestingConstantPattern().Matches(body)
            .Select(static m => m.Groups["constant"].Value)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var group = Classify(shortNames, logStrings, callees, body);

        return new RecoveredFunctionSummary(
            requested,
            functionElement.GetProperty("status").GetString() ?? "",
            entry,
            functionElement.TryGetProperty("end", out var endElement) ? endElement.GetString() ?? "" : "",
            functionElement.TryGetProperty("name", out var nameElement) ? nameElement.GetString() ?? "" : "",
            functionElement.TryGetProperty("containsRequested", out var containsElement) && containsElement.GetBoolean(),
            body.Length,
            group,
            shortNames,
            logStrings,
            callees,
            stateOffsets,
            constants,
            InferSemantics(group, shortNames, logStrings, callees, body));
    }

    private static string Classify(string[] shortNames, string[] logStrings, string[] callees, string body)
    {
        var joinedNames = string.Join('\n', shortNames);
        var joinedLogs = string.Join('\n', logStrings);

        if (joinedNames.Contains("OnConnection", StringComparison.Ordinal) || joinedLogs.Contains("m_connection", StringComparison.Ordinal))
        {
            return "connection-lifecycle";
        }

        if (joinedNames.Contains("OnGameCreated", StringComparison.Ordinal))
        {
            return "game-lifecycle";
        }

        if (joinedNames.Contains("OnAssociationsAdded", StringComparison.Ordinal) || callees.Contains("00a08110", StringComparer.Ordinal) || callees.Contains("00a07f80", StringComparer.Ordinal))
        {
            return "association-lifecycle";
        }

        if (joinedNames.Contains("OnPlayerLeave", StringComparison.Ordinal) || callees.Contains("009efc80", StringComparer.Ordinal) || callees.Contains("00a1c430", StringComparer.Ordinal))
        {
            return "player-lifecycle";
        }

        if (joinedNames.Contains("create", StringComparison.Ordinal) || joinedNames.Contains("updateDogTags", StringComparison.Ordinal) || body.Contains("dog-tag", StringComparison.Ordinal))
        {
            return "backend-maintenance";
        }

        return "unclassified";
    }

    private static string InferSemantics(string group, string[] shortNames, string[] logStrings, string[] callees, string body)
    {
        var joinedNames = string.Join(", ", shortNames);
        if (shortNames.Contains("OnConnectionReady", StringComparer.Ordinal))
        {
            return "connection-ready callback; creates two conn-tagged logging channels and activates FESL/Theater TCP connection logging";
        }

        if (shortNames.Any(static name => name.StartsWith("OnConnection", StringComparison.Ordinal)))
        {
            return $"{joinedNames} callback; routes backend connection lifecycle/error handling into the central disconnect path when needed";
        }

        if (shortNames.Contains("OnGameCreated", StringComparer.Ordinal))
        {
            return "game-created callback; forwards game attributes and persistent server info into ServerBackend";
        }

        if (shortNames.Contains("OnAssociationsAdded", StringComparer.Ordinal))
        {
            return "association-manager listener callback; logs association owner/associate inputs and forwards them into ServerBackend::onAssociationsAdded";
        }

        if (shortNames.Contains("OnPlayerLeave", StringComparer.Ordinal))
        {
            return "player-leave callback; performs voice cleanup and forwards player-left state into ServerGameManager";
        }

        if (shortNames.Contains("updateDogTags", StringComparer.Ordinal))
        {
            return "dog-tag update path; validates online/player/id state and issues deferred dog-tag sends from queued backend state";
        }

        if (shortNames.Contains("create", StringComparer.Ordinal))
        {
            return "ServerBackend create path; allocates/validates backend connection state and reads persistent info";
        }

        if (callees.Contains("00a31d90", StringComparer.Ordinal))
        {
            return "connection/error wrapper feeding central backend disconnect cleanup";
        }

        return group == "unclassified" ? "unclassified recovered raw callsite function" : $"recovered {group} function";
    }

    private static bool IsRelevant(string value)
    {
        return value.StartsWith("dice::", StringComparison.Ordinal)
            || value.Contains("ServerBackend", StringComparison.Ordinal)
            || value.Contains("ServerGameManager", StringComparison.Ordinal)
            || value.Contains("ServerAssociation", StringComparison.Ordinal)
            || value.Contains("dog-tag", StringComparison.Ordinal)
            || value.Contains("Fesl", StringComparison.Ordinal)
            || value.Contains("Theater", StringComparison.Ordinal)
            || value.Contains("m_connection", StringComparison.Ordinal);
    }

    private static IEnumerable<string> KnownShortNamesFromBody(string body)
    {
        if (body.Contains("ServerBackend::create", StringComparison.Ordinal))
        {
            yield return "create";
        }

        if (body.Contains("OnConnectionReady", StringComparison.Ordinal))
        {
            yield return "OnConnectionReady";
        }

        if (body.Contains("OnGameCreated", StringComparison.Ordinal))
        {
            yield return "OnGameCreated";
        }

        if (body.Contains("OnAssociationsAdded", StringComparison.Ordinal))
        {
            yield return "OnAssociationsAdded";
        }

        if (body.Contains("OnPlayerLeave", StringComparison.Ordinal))
        {
            yield return "OnPlayerLeave";
        }

        if (body.Contains("updateDogTags", StringComparison.Ordinal))
        {
            yield return "updateDogTags";
        }
    }

    private sealed record RecoveredFunctionSummary(
        string Requested,
        string Status,
        string Entry,
        string End,
        string Name,
        bool ContainsRequested,
        int BodyLength,
        string Group,
        string[] ShortNames,
        string[] LogStrings,
        string[] Callees,
        string[] StateOffsets,
        string[] InterestingConstants,
        string Semantics);

    [GeneratedRegex("\"(?<value>[^\"]+)\"", RegexOptions.CultureInvariant)]
    private static partial Regex LogStringPattern();

    [GeneratedRegex("FUN_(?<target>[0-9a-f]{8})", RegexOptions.CultureInvariant)]
    private static partial Regex CalleePattern();

    [GeneratedRegex("param_1 \\+ 0x(?<offset>[0-9a-f]+)|ESI \\+ 0x(?<offset>[0-9a-f]+)|unaff_ESI \\+ 0x(?<offset>[0-9a-f]+)", RegexOptions.CultureInvariant)]
    private static partial Regex StateOffsetPattern();

    [GeneratedRegex("(?<constant>0x636f6e6e|-0x3ea|0x432[0-9a-f]+)", RegexOptions.CultureInvariant)]
    private static partial Regex InterestingConstantPattern();
}
