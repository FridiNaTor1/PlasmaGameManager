using System.Text.Json;
using System.Text.RegularExpressions;

namespace PlasmaGameManager.ReTools;

public static partial class Bfbc2ServerGameManagerListenerCompleteReducer
{
    private const uint ListenerTableBase = 0x01782b4c;
    private const int ListenerTableSlotCount = 34;

    public static async Task ReduceAsync(string exePath, string listenerMapPath, string missingSlotDecompilesPath, string outputPath)
    {
        var image = Pe32Image.Load(exePath);
        using var listenerDoc = JsonDocument.Parse(File.ReadAllText(listenerMapPath));
        using var missingDoc = JsonDocument.Parse(File.ReadAllText(missingSlotDecompilesPath));

        var existing = listenerDoc.RootElement.GetProperty("callbackTable").EnumerateArray()
            .ToDictionary(static row => row.GetProperty("Index").GetInt32(), static row => row);
        var missingFunctions = missingDoc.RootElement.GetProperty("functions").EnumerateArray()
            .Where(static row => row.TryGetProperty("entry", out var entry) && !string.IsNullOrWhiteSpace(entry.GetString()))
            .GroupBy(static row => row.GetProperty("entry").GetString() ?? "", StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => FunctionSummary.From(group.First()), StringComparer.Ordinal);

        var slots = Enumerable.Range(0, ListenerTableSlotCount)
            .Select(index => BuildSlot(image, existing, missingFunctions, index))
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-bfbc2-raw-listener-table-and-decompile-evidence",
            note = "Reads the ServerGameManagerListener table directly from BFBC2 .rdata and merges previous listener-map entries with targeted decompiles for slots omitted by pointer evidence.",
            table = new
            {
                Base = Hex(ListenerTableBase),
                ImageBase = Hex(image.ImageBase),
                SlotCount = ListenerTableSlotCount,
                ByteLength = ListenerTableSlotCount * 4
            },
            summary = new
            {
                SlotCount = slots.Length,
                ImplementedSlots = slots.Count(static slot => slot.Status == "implemented"),
                StubSlots = slots.Count(static slot => slot.Status == "stub"),
                ThunkSlots = slots.Count(static slot => slot.Status == "thunk"),
                NoOpSlots = slots.Count(static slot => slot.Status == "no-op"),
                ConstantReturnSlots = slots.Count(static slot => slot.Status == "constant-return"),
                UnknownSlots = slots.Count(static slot => slot.Status == "unknown"),
                DispatcherCandidateSlots = slots.Count(static slot => slot.Role.Contains("dispatcher", StringComparison.Ordinal))
            },
            slots,
            nextTargets = new[]
            {
                "Decompile and reduce 00a3ef70 ServerGameManagerListener::handleMessage into packet branch semantics.",
                "Map handleMessage branches param_2/param_3 to incoming GameManager packet types and listener callbacks.",
                "Confirm whether slots 4, 6, 18, 32, and 33 are interface boilerplate/no-op slots or meaningful virtual methods."
            }
        }, JsonOptions));
    }

    private static ListenerSlot BuildSlot(
        Pe32Image image,
        IReadOnlyDictionary<int, JsonElement> existing,
        IReadOnlyDictionary<string, FunctionSummary> missingFunctions,
        int index)
    {
        var pointerAddress = ListenerTableBase + (uint)(index * 4);
        var functionAddress = image.ReadU32(pointerAddress);
        var functionHex = Hex(functionAddress);
        if (existing.TryGetValue(index, out var row))
        {
            var existingRole = row.GetProperty("Role").GetString() ?? "";
            var existingStatus = row.GetProperty("Status").GetString() ?? "";
            var existingSemantics = row.GetProperty("Semantics").GetString() ?? "";
            if (index == 23 && functionHex == "00a0fd50" && existingStatus == "unknown")
            {
                existingRole = "listener-state-drain";
                existingStatus = "implemented";
                existingSemantics = "Recovered listener slot 23. Requires listener state offset 0x14 to be 2, clears pending state at +0x88, drains iterator records into an owned two-string hash table through 0054a5c0/0051f090, and moves state to 3 when the iterator is empty.";
            }

            return new ListenerSlot(
                index,
                Hex(pointerAddress),
                functionHex,
                row.GetProperty("FunctionName").GetString() ?? "",
                existingRole,
                existingStatus,
                existingSemantics,
                GetStringArray(row, "LogStrings"),
                GetStringArray(row, "Callees"),
                row.GetProperty("BodyLength").GetInt32());
        }

        missingFunctions.TryGetValue(functionHex, out var function);
        var role = InferMissingRole(index, functionHex, function);
        var status = InferMissingStatus(role, function);
        return new ListenerSlot(
            index,
            Hex(pointerAddress),
            functionHex,
            function?.NativeName ?? function?.GhidraName ?? "",
            role,
            status,
            InferMissingSemantics(index, functionHex, role, function),
            function?.LogStrings ?? Array.Empty<string>(),
            function?.Callees ?? Array.Empty<string>(),
            function?.BodyLength ?? 0);
    }

    private static string InferMissingRole(int index, string address, FunctionSummary? function)
    {
        if (function?.NativeName.EndsWith("handleMessage", StringComparison.Ordinal) == true || address == "00a3ef70")
        {
            return "message-dispatcher-candidate";
        }

        if (function?.Body.Trim().Contains("return 0;", StringComparison.Ordinal) == true)
        {
            return "boolean-default";
        }

        if (function?.Body.Trim().Contains("return 100;", StringComparison.Ordinal) == true)
        {
            return "constant-return-100";
        }

        if (function?.Body.Trim().EndsWith("return;\n}", StringComparison.Ordinal) == true && function.BodyLength < 80)
        {
            return "no-op";
        }

        if (function?.Callees.Contains("00a18980", StringComparer.Ordinal) == true)
        {
            return "destructor-delete-thunk";
        }

        if (address == "00a08630")
        {
            return "player-send-helper";
        }

        if (address is "009f9b60" or "009d85a0" or "009d85e0")
        {
            return "backend-state-sync";
        }

        return "unknown";
    }

    private static string InferMissingStatus(string role, FunctionSummary? function)
    {
        return role switch
        {
            "message-dispatcher-candidate" => "implemented",
            "player-send-helper" => "implemented",
            "backend-state-sync" => "implemented",
            "destructor-delete-thunk" => "thunk",
            "boolean-default" => "constant-return",
            "constant-return-100" => "constant-return",
            "no-op" => "no-op",
            _ => function is null ? "missing-decompile" : "unknown"
        };
    }

    private static string InferMissingSemantics(int index, string address, string role, FunctionSummary? function)
    {
        return role switch
        {
            "message-dispatcher-candidate" => "ServerGameManagerListener::handleMessage; checks packet/message ids and backend online state, making this the next dispatcher-reduction target.",
            "player-send-helper" => "Player lifecycle packet/send helper adjacent to OnPlayerLeave; builds a small serialized record and forwards it through backend send path.",
            "backend-state-sync" => "Backend/listener state synchronization helper that reads socket/backend state and updates offsets 0x98/0xa0.",
            "destructor-delete-thunk" => "Destructor/delete thunk around listener cleanup.",
            "boolean-default" => "Default virtual method returning false/0.",
            "constant-return-100" => "Default virtual method returning constant 100.",
            "no-op" => "Default virtual method with no body.",
            _ => $"Unclassified raw listener table slot {index} at {address}."
        };
    }

    private static string[] GetStringArray(JsonElement row, string property)
    {
        return row.TryGetProperty(property, out var array)
            ? array.EnumerateArray().Select(static item => item.GetString() ?? "").Where(static value => value.Length > 0).ToArray()
            : Array.Empty<string>();
    }

    private static string Hex(uint value) => $"{value:x8}";

    private sealed record ListenerSlot(
        int Index,
        string PointerAddress,
        string FunctionAddress,
        string FunctionName,
        string Role,
        string Status,
        string Semantics,
        string[] LogStrings,
        string[] Callees,
        int BodyLength);

    private sealed record FunctionSummary(string Entry, string GhidraName, string NativeName, string Body, string[] LogStrings, string[] Callees, int BodyLength)
    {
        public static FunctionSummary From(JsonElement row)
        {
            var body = row.TryGetProperty("body", out var bodyElement) ? bodyElement.GetString() ?? "" : "";
            var strings = StringPattern().Matches(body)
                .Select(static match => match.Groups["value"].Value)
                .Where(static value => value.Contains("ServerGameManagerListener", StringComparison.Ordinal)
                    || value.Contains("Server.PlayerCountNeededForMultiplayer", StringComparison.Ordinal)
                    || value.Contains("not implemented", StringComparison.Ordinal))
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            var nativeName = strings
                .FirstOrDefault(static value => value.StartsWith("dice::online::plasma::ServerGameManagerListener::", StringComparison.Ordinal))
                ?? "";
            var callees = CalleePattern().Matches(body)
                .Select(static match => match.Groups["target"].Value.ToLowerInvariant())
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray();
            return new FunctionSummary(
                row.GetProperty("entry").GetString() ?? "",
                row.TryGetProperty("name", out var name) ? name.GetString() ?? "" : "",
                nativeName,
                body,
                strings,
                callees,
                body.Length);
        }
    }

    [GeneratedRegex("\"(?<value>[^\"]+)\"")]
    private static partial Regex StringPattern();

    [GeneratedRegex(@"FUN_(?<target>[0-9a-fA-F]{8})")]
    private static partial Regex CalleePattern();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}

internal sealed class Pe32Image
{
    private readonly byte[] _bytes;
    private readonly Section[] _sections;

    public uint ImageBase { get; }

    private Pe32Image(byte[] bytes, uint imageBase, Section[] sections)
    {
        _bytes = bytes;
        ImageBase = imageBase;
        _sections = sections;
    }

    public static Pe32Image Load(string path)
    {
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length < 0x100 || bytes[0] != 'M' || bytes[1] != 'Z')
        {
            throw new InvalidDataException($"{path} is not a PE file.");
        }

        var peOffset = ReadU32Le(bytes, 0x3c);
        if (ReadU32Le(bytes, checked((int)peOffset)) != 0x00004550)
        {
            throw new InvalidDataException($"{path} has no PE signature.");
        }

        var fileHeader = checked((int)peOffset + 4);
        var sectionCount = ReadU16Le(bytes, fileHeader + 2);
        var optionalHeaderSize = ReadU16Le(bytes, fileHeader + 16);
        var optionalHeader = fileHeader + 20;
        var optionalHeaderMagic = ReadU16Le(bytes, optionalHeader);
        var imageBase = optionalHeaderMagic switch
        {
            0x10b => ReadU32Le(bytes, optionalHeader + 28),
            0x20b => checked((uint)ReadU64Le(bytes, optionalHeader + 24)),
            _ => throw new InvalidDataException($"{path} has unsupported PE optional header magic 0x{optionalHeaderMagic:x}.")
        };
        var sectionOffset = optionalHeader + optionalHeaderSize;
        var sections = new List<Section>();
        for (var index = 0; index < sectionCount; index++)
        {
            var offset = sectionOffset + index * 40;
            var virtualSize = ReadU32Le(bytes, offset + 8);
            var virtualAddress = ReadU32Le(bytes, offset + 12);
            var rawSize = ReadU32Le(bytes, offset + 16);
            var rawPointer = ReadU32Le(bytes, offset + 20);
            var characteristics = ReadU32Le(bytes, offset + 36);
            sections.Add(new Section(virtualAddress, virtualSize, rawPointer, rawSize, characteristics));
        }

        return new Pe32Image(bytes, imageBase, sections.ToArray());
    }

    public uint ReadU32(uint virtualAddress)
    {
        var rva = virtualAddress >= ImageBase
            ? virtualAddress - ImageBase
            : virtualAddress;
        var section = _sections.FirstOrDefault(section =>
            rva >= section.VirtualAddress
            && rva + 4 <= section.VirtualAddress + Math.Max(section.VirtualSize, section.RawSize));
        if (section == default)
        {
            throw new InvalidOperationException($"Address {virtualAddress:x8} (RVA {rva:x8}) is not in a loaded PE section.");
        }

        var offset = checked((int)(section.RawPointer + (rva - section.VirtualAddress)));
        return ReadU32Le(_bytes, offset);
    }

    private static ushort ReadU16Le(byte[] bytes, int offset)
    {
        return (ushort)(bytes[offset] | (bytes[offset + 1] << 8));
    }

    private static uint ReadU32Le(byte[] bytes, int offset)
    {
        return bytes[offset] | ((uint)bytes[offset + 1] << 8) | ((uint)bytes[offset + 2] << 16) | ((uint)bytes[offset + 3] << 24);
    }

    private static ulong ReadU64Le(byte[] bytes, int offset)
    {
        return ReadU32Le(bytes, offset) | ((ulong)ReadU32Le(bytes, offset + 4) << 32);
    }

    private readonly record struct Section(uint VirtualAddress, uint VirtualSize, uint RawPointer, uint RawSize, uint Characteristics);
}
