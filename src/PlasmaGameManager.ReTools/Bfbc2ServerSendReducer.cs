using System.Text.Json;
using System.Text.RegularExpressions;

namespace PlasmaGameManager.ReTools;

public static partial class Bfbc2ServerSendReducer
{
    public static async Task ReduceAsync(string serverSendFunctionsPath, string outputPath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(serverSendFunctionsPath));

        var functions = doc.RootElement.GetProperty("functions").EnumerateArray()
            .Select(BuildSummary)
            .OrderBy(static f => f.Entry, StringComparer.Ordinal)
            .ThenBy(static f => f.Requested, StringComparer.Ordinal)
            .ToArray();

        var uniqueFunctions = functions
            .Where(static f => f.Entry.Length != 0)
            .GroupBy(static f => f.Entry, StringComparer.Ordinal)
            .Select(static g => g.First())
            .OrderBy(static f => f.Entry, StringComparer.Ordinal)
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-server-socket-send-decompile",
            note = "Maps the BFBC2 Plasma server low-level send wrapper. This confirms the transport send path but does not yet identify high-level GameManager packet constructors.",
            summary = new
            {
                RequestedCallsites = functions.Length,
                UniqueFunctions = uniqueFunctions.Length,
                SendWrappers = uniqueFunctions.Count(static f => f.Kind == "server-socket-send-wrapper"),
                DownstreamCallees = uniqueFunctions.SelectMany(static f => f.DownstreamSendCallees).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray()
            },
            sendPath = uniqueFunctions,
            callsiteRows = functions
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static ServerSendFunctionSummary BuildSummary(JsonElement element)
    {
        var requested = element.GetProperty("requested").GetString() ?? "";
        var status = element.GetProperty("status").GetString() ?? "";
        var entry = element.TryGetProperty("entry", out var entryElement) ? entryElement.GetString() ?? "" : "";
        var name = element.TryGetProperty("name", out var nameElement) ? nameElement.GetString() ?? "" : "";
        var signature = element.TryGetProperty("signature", out var signatureElement) ? signatureElement.GetString() ?? "" : "";
        var body = element.TryGetProperty("body", out var bodyElement) ? bodyElement.GetString() ?? "" : "";

        var asserts = AssertPattern().Matches(body)
            .Select(static m => m.Groups["assertion"].Value)
            .Where(static value => value.Length != 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var callees = CalleePattern().Matches(body)
            .Select(static m => m.Groups["target"].Value)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var downstreamSendCallees = callees
            .Where(callee => body.Contains($"FUN_{callee}(param_1 + 8,param_2,param_3,0)", StringComparison.Ordinal)
                || body.Contains($"CALL 0x{callee}", StringComparison.Ordinal))
            .ToArray();

        var kind = asserts.Contains("!m_isBroadcasting", StringComparer.Ordinal)
            && asserts.Contains("m_peerAddressIsValid", StringComparer.Ordinal)
            && asserts.Contains("socketManager", StringComparer.Ordinal)
            && callees.Contains("009ef210", StringComparer.Ordinal)
                ? "server-socket-send-wrapper"
                : "unclassified-send-path";

        var semantics = kind == "server-socket-send-wrapper"
            ? "dice::online::plasma::ServerSocket::send; validates broadcast state, peer address, and socket manager, then sends the payload through 009ef210(this+8, payload, length, 0)"
            : "send-path function requiring more callsite context";

        return new ServerSendFunctionSummary(
            requested,
            status,
            entry,
            name,
            signature,
            kind,
            semantics,
            asserts,
            callees,
            downstreamSendCallees,
            body.Length);
    }

    [GeneratedRegex("\"(?<assertion>!m_isBroadcasting|m_peerAddressIsValid|socketManager)\"")]
    private static partial Regex AssertPattern();

    [GeneratedRegex(@"FUN_(?<target>[0-9a-fA-F]{8})")]
    private static partial Regex CalleePattern();

    private sealed record ServerSendFunctionSummary(
        string Requested,
        string Status,
        string Entry,
        string Name,
        string Signature,
        string Kind,
        string Semantics,
        string[] Assertions,
        string[] Callees,
        string[] DownstreamSendCallees,
        int BodyLength);
}
