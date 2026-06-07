using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Tf2Ps3AnchorContextReducer
{
    public static async Task ReduceAsync(string anchorContextPath, string anchorTablePath, string outputPath)
    {
        using var contextDoc = JsonDocument.Parse(File.ReadAllText(anchorContextPath));
        using var tableDoc = JsonDocument.Parse(File.ReadAllText(anchorTablePath));

        var addresses = contextDoc.RootElement.GetProperty("addresses").EnumerateArray()
            .Select(AddressContext.From)
            .ToDictionary(static address => address.Address, StringComparer.Ordinal);
        var decompiledFunctions = contextDoc.RootElement.GetProperty("decompiledFunctions").EnumerateArray()
            .Select(DecompiledFunction.From)
            .ToArray();
        var roleSlots = tableDoc.RootElement.GetProperty("unresolvedRoleSlots").EnumerateArray()
            .Select(RoleSlot.From)
            .ToArray();

        var candidate = addresses.GetValueOrDefault("015d3f64");
        var tableReads = addresses.Values
            .Where(static address => address.RefsTo.Length > 0)
            .SelectMany(address => address.RefsTo.Select(reference => new
            {
                TableAddress = address.Address,
                TableValue = address.U32Be,
                address.MemoryBlock,
                ReadSite = reference.From,
                ReaderFunction = reference.FromFunction,
                ReaderFunctionName = decompiledFunctions.FirstOrDefault(function => function.Entry == reference.FromFunction)?.Name ?? "",
                Roles = roleSlots.Where(slot => slot.Address == address.Address).SelectMany(static slot => slot.Roles).Distinct(StringComparer.Ordinal).ToArray()
            }))
            .OrderBy(static read => read.TableAddress, StringComparer.Ordinal)
            .ToArray();
        var unreferencedAnchoredSlots = roleSlots
            .Where(slot => !addresses.TryGetValue(slot.Address, out var context) || context.RefsTo.Length == 0)
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-ghidra-anchor-context",
            note = "Reduces targeted Ghidra context for the TF2 unresolved anchor table. This report is authoritative for whether 015d3f64 is currently code in Ghidra; do not promote it unless a later export shows an instruction/function.",
            input = new
            {
                AnchorContext = anchorContextPath,
                AnchorTable = anchorTablePath
            },
            summary = new
            {
                AddressContextCount = addresses.Count,
                DecompiledReaderFunctionCount = decompiledFunctions.Length,
                TableReadCount = tableReads.Length,
                UnreferencedAnchoredSlotCount = unreferencedAnchoredSlots.Length,
                Candidate015d3f64Classification = ClassifyCandidate(candidate)
            },
            candidate015d3f64 = candidate is null ? null : new
            {
                candidate.Address,
                candidate.MemoryBlock,
                candidate.U32Be,
                candidate.CodeUnitType,
                candidate.CodeUnitText,
                candidate.HasInstruction,
                candidate.HasFunctionAt,
                candidate.HasFunctionContaining,
                candidate.RefsToCount,
                candidate.RefsFromCount,
                Classification = ClassifyCandidate(candidate),
                Reason = CandidateReason(candidate)
            },
            tableReads,
            unreferencedAnchoredSlots,
            decompiledReaderFunctions = decompiledFunctions.Select(static function => new
            {
                function.Entry,
                function.Name,
                function.Signature,
                BodyLength = function.Body.Length,
                Body = function.Body,
                BodyPreview = function.Body.Length > 1200 ? function.Body[..1200] : function.Body
            }).ToArray(),
            nextNativeRecoveryTargets = new[]
            {
                "Inspect 015d4e20 and 015d5d50 as confirmed table readers for join/connection flow.",
                "Recover why Ghidra does not xref exact anchored words 019c09a4, 019c09a8, 019c09b0, 019c09b8, 019c09bc, and 019c09c0; likely TOC/register-relative dataflow or unresolved table typing.",
                "Keep 015d3f64 classified as data until Ghidra exports an instruction or function at that address."
            }
        }, JsonOptions));
    }

    private static string ClassifyCandidate(AddressContext? candidate)
    {
        if (candidate is null)
        {
            return "missing";
        }

        if (candidate.HasFunctionAt || candidate.HasFunctionContaining || candidate.HasInstruction)
        {
            return "code-confirmed";
        }

        return candidate.CodeUnitType == "DataDB" ? "data-not-confirmed-function" : "unknown-not-confirmed-function";
    }

    private static string CandidateReason(AddressContext candidate)
    {
        if (candidate.HasFunctionAt || candidate.HasFunctionContaining)
        {
            return "Ghidra has a function at or containing this address.";
        }

        if (candidate.HasInstruction)
        {
            return "Ghidra has an instruction at this address.";
        }

        return $"Ghidra reports code unit {candidate.CodeUnitType} ({candidate.CodeUnitText}), u32be={candidate.U32Be}, refsTo={candidate.RefsToCount}, refsFrom={candidate.RefsFromCount}.";
    }

    private sealed record AddressContext(
        string Address,
        string MemoryBlock,
        string U32Be,
        string CodeUnitType,
        string CodeUnitText,
        bool HasInstruction,
        bool HasFunctionAt,
        bool HasFunctionContaining,
        int RefsToCount,
        int RefsFromCount,
        ReferenceContext[] RefsTo)
    {
        public static AddressContext From(JsonElement element)
        {
            var codeUnit = element.GetProperty("codeUnit");
            return new AddressContext(
                GetString(element, "address"),
                GetString(element, "memoryBlock"),
                GetString(element, "u32be"),
                codeUnit.ValueKind == JsonValueKind.Null ? "" : GetString(codeUnit, "type"),
                codeUnit.ValueKind == JsonValueKind.Null ? "" : GetString(codeUnit, "text"),
                element.GetProperty("instruction").ValueKind != JsonValueKind.Null,
                element.GetProperty("functionAt").ValueKind != JsonValueKind.Null,
                element.GetProperty("functionContaining").ValueKind != JsonValueKind.Null,
                element.GetProperty("refsTo").GetArrayLength(),
                element.GetProperty("refsFrom").GetArrayLength(),
                element.GetProperty("refsTo").EnumerateArray().Select(ReferenceContext.Parse).ToArray());
        }
    }

    private sealed record ReferenceContext(string From, string To, string Type, string FromFunction)
    {
        public static ReferenceContext Parse(JsonElement element)
        {
            return new ReferenceContext(
                GetString(element, "from"),
                GetString(element, "to"),
                GetString(element, "type"),
                GetString(element, "fromFunction"));
        }
    }

    private sealed record DecompiledFunction(string Entry, string Name, string Signature, string Body)
    {
        public static DecompiledFunction From(JsonElement element)
        {
            return new DecompiledFunction(
                GetString(element, "entry"),
                GetString(element, "name"),
                GetString(element, "signature"),
                GetString(element, "body"));
        }
    }

    private sealed record RoleSlot(string Address, string Value, string[] Roles)
    {
        public static RoleSlot From(JsonElement element)
        {
            return new RoleSlot(
                GetString(element, "Address"),
                GetString(element, "Value"),
                element.GetProperty("Roles").EnumerateArray().Select(static role => role.GetString() ?? "").Where(static role => role.Length > 0).ToArray());
        }
    }

    private static string GetString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) ? value.GetString() ?? "" : "";
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}
