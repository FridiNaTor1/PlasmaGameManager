using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Tf2Ps3SecondLevelHelperReducer
{
    public static async Task ReduceAsync(string decompilesPath, string outputPath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(decompilesPath));
        var helpers = doc.RootElement.GetProperty("functions").EnumerateArray()
            .Select(HelperFunction.From)
            .Select(Reduce)
            .OrderBy(static helper => helper.Entry, StringComparer.Ordinal)
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-tf2ps3-second-level-helper-decompiles",
            note = "Second-level native helper map for TF2 GameManager. These findings name the field-population layer beneath the received-join path and outbound join/session setup.",
            input = decompilesPath,
            summary = new
            {
                HelperCount = helpers.Length,
                ClassifiedHelperCount = helpers.Count(static helper => helper.Role != "unclassified-second-level-helper"),
                PacketPopulationHelper = helpers.FirstOrDefault(static helper => helper.Entry == "015938f8")?.Role ?? "",
                DescriptorBuilderCount = helpers.Count(static helper => helper.Role == "build-six-word-descriptor"),
                TargetFormatter = helpers.FirstOrDefault(static helper => helper.Entry == "0158e430")?.Role ?? "",
                CompletionHelper = helpers.FirstOrDefault(static helper => helper.Entry == "015d01f8")?.Role ?? ""
            },
            helpers,
            nextNativeTargets = new[]
            {
                "Export the vtable method behind player object +0x68 to recover exact packet field reads into the object.",
                "Export caller context for descriptor builder callsites to bind PTR_PTR_019c076c/0770/0774/0778 to protocol field names.",
                "Use instruction-level dataflow around 015875c8's jump table to recover exact reader widths and endian/bias behavior for the tuple reader."
            }
        }, JsonOptions));
    }

    private static HelperMap Reduce(HelperFunction function)
    {
        return function.Entry switch
        {
            "015875c8" => Map(function, "bounded-reader-dispatch", "Bounds-checks packet reader offsets +0x408/+0x410, writes error 0xfffffc14 at +0x414 on overrun, zeroes the output, then dispatches a size-specific reader through the jump table at 019c03ec for widths up to 8.", new[] { "reader +0x408", "reader +0x410", "reader +0x414", "jump table 019c03ec" }, new[] { "reader +0x414 = 0xfffffc14 on overrun", "output = 0 before size dispatch" }),
            "015938f8" => Map(function, "populate-player-object-from-join-packet", "Stores session and player id into the player object, invokes player-object vtable +0x68 with the packet, sets local/spectator-like flag +0x39 from session vtable +0x84 == 2, resolves backend presence into flag +0x3a, and mirrors readiness into backend bitmasks at session-backend +0x2a0/+0x2a4.", new[] { "player[2]", "player[4]", "player +0x39", "player +0x3a", "session +0x22c", "session +0xbc", "session +0xc", "backend +0x29c", "backend +0x2a0", "backend +0x2a4", "backend +0x2b1" }, new[] { "player[2] = session", "player[4] = decoded player id", "player +0x39 = session_mode_is_2", "player +0x3a = backend presence state", "backend +0x2a0 bit[player[6]] updated", "backend +0x2a4 bit[player[6]] updated" }),
            "015d01f8" => Map(function, "complete-state-six-player-and-notify", "Marks player state slot 0xb as 6, toggles an attached outbound/session object when present, allocates a secondary completion object from the session pool, emits a vtable +0xcc notification using player vtable +0x20, and conditionally sends a Source/voice/team-style backend update through 015cea50 and readiness bitmasks.", new[] { "player[0xb]", "player[10]", "session[0x59]", "session[0x6a..0x71]", "session vtable +0xcc", "player vtable +0x20", "player vtable +0x2c", "session vtable +0x84", "session vtable +0x68", "backend +0x29c", "backend +0x2a0", "backend +0x2a4" }, new[] { "player[0xb] = 6", "completion object pool active/free counts updated", "backend readiness bitmasks updated" }),
            "015ad060" => Descriptor(function, "PTR_PTR_019c06dc"),
            "015acfb0" => Descriptor(function, "PTR_PTR_019c06d8"),
            "015ae2a8" => Descriptor(function, "PTR_PTR_019c0768"),
            "0158e430" => Map(function, "format-join-target-identifier", "Formats a 0x20-byte target identifier string with pattern at 019c04b4 using player/session fields +0xbc, +0xc0, and the selected target id, then logs the generated identifier.", new[] { "format string 019c04b4", "param_1 + 0xbc", "param_1 + 0xc0", "selected target id", "output buffer length 0x20" }, new[] { "target identifier string buffer populated" }),
            "01589140" => Map(function, "choose-outbound-port-or-mode", "Returns 0x1771 when field +0x9c is zero; otherwise returns 0x1772 or 0x5 based on the signed transform of +0x9c ^ 1. This value is passed into outbound join session creation.", new[] { "param_1 + 0x9c" }, Array.Empty<string>()),
            _ => Map(function, "unclassified-second-level-helper", "Exported second-level helper needs manual classification.", Array.Empty<string>(), Array.Empty<string>())
        };
    }

    private static HelperMap Descriptor(HelperFunction function, string descriptorVtable)
    {
        return Map(function, "build-six-word-descriptor", $"Builds a six-word descriptor tagged with {descriptorVtable}: word0 type/vtable pointer, word1 source object pointer, words2/3 the high/low 32 bits of the 64-bit key, word4 zero, word5 zero.", new[] { "descriptor[0]", "descriptor[1]", "descriptor[2]", "descriptor[3]", "descriptor[4]", "descriptor[5]" }, new[] { $"descriptor[0] = {descriptorVtable}", "descriptor[1] = source object", "descriptor[2] = key high32", "descriptor[3] = key low32", "descriptor[4] = 0", "descriptor[5] = 0" });
    }

    private static HelperMap Map(HelperFunction function, string role, string semantics, string[] observedFields, string[] stateWrites)
    {
        return new HelperMap(
            function.Requested,
            function.Entry,
            function.Name,
            role,
            semantics,
            Callees(function.Body),
            observedFields,
            stateWrites,
            ExtractConditions(function.Body),
            function.Instructions.Take(20).ToArray(),
            function.Body.Length);
    }

    private static string[] Callees(string body)
    {
        var helpers = new HashSet<string>(StringComparer.Ordinal);
        for (var index = body.IndexOf("FUN_", StringComparison.Ordinal); index >= 0; index = body.IndexOf("FUN_", index + 4, StringComparison.Ordinal))
        {
            if (index + 12 > body.Length)
            {
                continue;
            }

            var candidate = body.Substring(index + 4, 8);
            if (candidate.All(static c => char.IsDigit(c) || c is >= 'a' and <= 'f'))
            {
                helpers.Add(candidate);
            }
        }

        return helpers.Order(StringComparer.Ordinal).ToArray();
    }

    private static string[] ExtractConditions(string body)
    {
        return body.Split('\n')
            .Select(static line => line.Trim())
            .Where(static line => line.StartsWith("if (", StringComparison.Ordinal) || line.StartsWith("while (", StringComparison.Ordinal))
            .Take(12)
            .ToArray();
    }

    private sealed record HelperFunction(string Requested, string Entry, string Name, string Body, string[] Instructions)
    {
        public static HelperFunction From(JsonElement element)
        {
            return new HelperFunction(
                GetString(element, "requested"),
                GetString(element, "entry"),
                GetString(element, "name"),
                GetString(element, "body"),
                element.TryGetProperty("instructions", out var instructions) && instructions.ValueKind == JsonValueKind.Array
                    ? instructions.EnumerateArray().Select(static instruction => GetString(instruction, "text")).Where(static text => text.Length > 0).ToArray()
                    : Array.Empty<string>());
        }
    }

    private sealed record HelperMap(
        string Requested,
        string Entry,
        string Name,
        string Role,
        string Semantics,
        string[] Callees,
        string[] ObservedFields,
        string[] StateWrites,
        string[] Conditions,
        string[] InstructionPreview,
        int BodyLength);

    private static string GetString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) ? value.GetString() ?? "" : "";
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}
