using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Bfbc2DispatcherTableReducer
{
    public static async Task ReduceAsync(string listenerCompletePath, string handleMessagePath, string phaseMapPath, string outputPath)
    {
        using var listenerDoc = JsonDocument.Parse(File.ReadAllText(listenerCompletePath));
        using var handleDoc = JsonDocument.Parse(File.ReadAllText(handleMessagePath));
        using var phaseDoc = JsonDocument.Parse(File.ReadAllText(phaseMapPath));

        var listenerRoot = listenerDoc.RootElement;
        var handleRoot = handleDoc.RootElement;
        var phaseRoot = phaseDoc.RootElement;

        var slots = listenerRoot.GetProperty("slots").EnumerateArray()
            .Select(static slot => new
            {
                Index = slot.GetProperty("Index").GetInt32(),
                PointerAddress = slot.GetProperty("PointerAddress").GetString() ?? "",
                FunctionAddress = slot.GetProperty("FunctionAddress").GetString() ?? "",
                FunctionName = slot.GetProperty("FunctionName").GetString() ?? "",
                Role = slot.GetProperty("Role").GetString() ?? "",
                Status = slot.GetProperty("Status").GetString() ?? "",
                Semantics = slot.GetProperty("Semantics").GetString() ?? ""
            })
            .ToArray();

        var branches = handleRoot.GetProperty("branches").EnumerateArray()
            .Select(static branch => new
            {
                Group = branch.GetProperty("Group").GetString() ?? "",
                Message = branch.GetProperty("Message").GetString() ?? "",
                Role = branch.GetProperty("Role").GetString() ?? "",
                Confidence = branch.GetProperty("Confidence").GetString() ?? "",
                Semantics = branch.GetProperty("Semantics").GetString() ?? "",
                StateEffect = branch.GetProperty("StateEffect").GetString() ?? ""
            })
            .ToArray();

        var outgoingPacketTypes = phaseRoot.GetProperty("phases").EnumerateArray()
            .SelectMany(static phase => phase.GetProperty("OutgoingMessages").EnumerateArray()
                .Select(message => new
                {
                    PhaseRole = phase.GetProperty("Role").GetString() ?? "",
                    PhaseEntry = phase.GetProperty("Entry").GetString() ?? "",
                    Type = message.GetProperty("Type").GetInt32(),
                    Meaning = GetOptionalString(message, "Meaning"),
                    EncodedTypeByte = GetOptionalString(message, "EncodedTypeByte"),
                    Confidence = GetOptionalString(message, "Confidence", "confirmed")
                }))
            .GroupBy(static message => $"{message.Type}|{message.Meaning}|{message.PhaseRole}", StringComparer.Ordinal)
            .Select(static group => group.First())
            .OrderBy(static message => message.Type)
            .ThenBy(static message => message.PhaseRole, StringComparer.Ordinal)
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-bfbc2-complete-listener-and-handlemessage",
            evidence = "Combines the raw 34-slot ServerGameManagerListener table, reduced handleMessage branch families, and native GameManager phase packet constructors. This replaces the earlier pointer-only pending report; field-level payload names remain tracked in the phase/callee reports.",
            summary = new
            {
                ListenerSlotCount = slots.Length,
                UnknownListenerSlots = slots.Count(static slot => slot.Status == "unknown" || slot.Role == "unknown"),
                DispatcherCandidateSlots = slots.Count(static slot => slot.Role.Contains("dispatcher", StringComparison.Ordinal)),
                HandleMessageBranchCount = branches.Length,
                ConfirmedHandleMessageBranches = branches.Count(static branch => branch.Confidence == "confirmed"),
                NativeOutgoingPacketTypeCount = outgoingPacketTypes.Select(static message => message.Type).Distinct().Count()
            },
            table = listenerRoot.GetProperty("table"),
            listenerSlots = slots,
            handleMessage = new
            {
                DispatcherEntry = handleRoot.GetProperty("dispatcher").GetProperty("Entry").GetString() ?? "",
                ListenerTableSlot = handleRoot.GetProperty("dispatcher").GetProperty("ListenerTableSlot").GetInt32(),
                branches
            },
            nativeOutgoingPacketTypes = outgoingPacketTypes,
            remainingFieldNamingTargets = new[]
            {
                "Packet field order for native types 4, 5, 8, 9, and TF2 type 11 still needs TF.elf field-level confirmation.",
                "BFBC2 handleMessage branch field names are reduced for 0x10/0x1d switch-squad; other branches are named at semantic branch level.",
                "TF2 parity still requires mapping TF.elf receive/create/join flows against this BFBC2 dispatcher model."
            }
        }, JsonOptions));
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private static string GetOptionalString(JsonElement element, string property, string fallback = "")
    {
        return element.TryGetProperty(property, out var value) ? value.GetString() ?? fallback : fallback;
    }
}
