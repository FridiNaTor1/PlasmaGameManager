using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Bfbc2SwitchSquadMutationReducer
{
    private const string Entry = "00a3e880";

    public static async Task ReduceAsync(string decompilesPath, string calleeMapPath, string outputPath)
    {
        using var decompileDoc = JsonDocument.Parse(File.ReadAllText(decompilesPath));
        using var calleeDoc = JsonDocument.Parse(File.ReadAllText(calleeMapPath));

        var function = decompileDoc.RootElement.GetProperty("functions").EnumerateArray()
            .FirstOrDefault(static row => row.TryGetProperty("entry", out var entry) && entry.GetString() == Entry);
        if (function.ValueKind == JsonValueKind.Undefined)
        {
            throw new InvalidDataException($"Missing {Entry} in {decompilesPath}.");
        }

        var body = function.TryGetProperty("body", out var bodyElement) ? bodyElement.GetString() ?? "" : "";
        var parent = calleeDoc.RootElement.GetProperty("functions").EnumerateArray()
            .FirstOrDefault(static row => row.GetProperty("Entry").GetString() == "00a3ed30");

        var report = new
        {
            status = "seeded-from-bfbc2-switch-squad-mutation-decompile",
            note = "Reduces 00a3e880, the backend mutation callee reached from ServerGameManagerListener::onPlayerSwitchSquad. Names remain field/offset based where BFBC2 lacks a native log string.",
            parent = new
            {
                Entry = parent.ValueKind == JsonValueKind.Undefined ? "" : parent.GetProperty("Entry").GetString() ?? "",
                Role = parent.ValueKind == JsonValueKind.Undefined ? "" : parent.GetProperty("Role").GetString() ?? "",
                Caller = "00a3ed30"
            },
            function = new
            {
                Entry,
                GhidraName = function.TryGetProperty("name", out var nameElement) ? nameElement.GetString() ?? "" : "",
                Role = "switch-squad-record-upsert",
                Confidence = HasAll(body, "FUN_009dbe30", "FUN_00a15d20", "FUN_00a3e020", "FUN_009ebea0", "param_1 + 0x40") ? "confirmed" : "partial",
                BodyLength = body.Length
            },
            parameters = new[]
            {
                new { Name = "param_1/this", Meaning = "listener/game object owning the switch-squad record table; sentinel/end node is this+0x40 and lookup root is this+0x3c" },
                new { Name = "param_2", Meaning = "player/user key used by 009dbe30 lookup and 009ebea0 insert; low byte cleared before insert" },
                new { Name = "param_3", Meaning = "requested field copied into record offset +0x1c" },
                new { Name = "param_4", Meaning = "requested field copied into record offset +0x14" },
                new { Name = "param_5", Meaning = "requested field copied into record offset +0x18" },
                new { Name = "param_6", Meaning = "requested field copied into record offset +0x20" }
            },
            stateMachine = new[]
            {
                new
                {
                    Step = "lookup",
                    Evidence = "FUN_009dbe30(&param_4,&param_2)",
                    Meaning = "Finds the existing switch-squad record for the key under this+0x3c."
                },
                new
                {
                    Step = "existing-record-update",
                    Evidence = "if (param_4 != param_1 + 0x40) ... writes +0x14/+0x18/+0x1c/+0x20",
                    Meaning = "When the record exists, compares the first three requested fields against the current record. If changed, it calls 00a15d20 and 00a3e020 before storing all four fields."
                },
                new
                {
                    Step = "new-record-insert",
                    Evidence = "sentinel branch calls 00a3e020 then 009ebea0 with param_2 & 0xffffff00",
                    Meaning = "When lookup returns the sentinel, creates/defaults a record and inserts it into the table with a low-byte-masked key."
                }
            },
            recordLayout = new[]
            {
                new { Offset = "+0x14", Source = "param_4", Notes = "first requested switch-squad field; compared before notification" },
                new { Offset = "+0x18", Source = "param_5", Notes = "second requested switch-squad field; compared before notification" },
                new { Offset = "+0x1c", Source = "param_3", Notes = "third requested switch-squad field; compared before notification" },
                new { Offset = "+0x20", Source = "param_6", Notes = "fourth requested switch-squad field; stored without participating in the three-field change check" }
            },
            callees = new[]
            {
                new { Entry = "009dbe30", Role = "record-lookup", Meaning = "Looks up the existing switch-squad record by key." },
                new { Entry = "00a15d20", Role = "pre-update-notify", Meaning = "Called with the key and existing record payload before changed existing-record fields are overwritten." },
                new { Entry = "00a3e020", Role = "default-record-fill", Meaning = "Builds/fills the stack record values used before updating or inserting." },
                new { Entry = "009ebea0", Role = "record-insert", Meaning = "Inserts a newly built record when lookup returns the sentinel." }
            },
            nextTargets = new[]
            {
                "Export 009dbe30/009ebea0 if switch-squad table structure becomes relevant to TF2.",
                "Do not mix this BFBC2 gameplay mutation path with TF2 join/create roster semantics unless TF.elf shows equivalent branch ids."
            }
        };

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, JsonOptions));
    }

    private static bool HasAll(string body, params string[] patterns)
    {
        return patterns.All(pattern => body.Contains(pattern, StringComparison.Ordinal));
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}
