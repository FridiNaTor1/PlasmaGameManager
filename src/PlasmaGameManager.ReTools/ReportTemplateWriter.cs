using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class ReportTemplateWriter
{
    public static async Task WriteAsync(string repoRoot)
    {
        Directory.CreateDirectory(Path.Combine(repoRoot, "re/bfbc2"));
        Directory.CreateDirectory(Path.Combine(repoRoot, "re/tf2ps3"));

        await WriteJson(Path.Combine(repoRoot, "re/bfbc2/dispatcher-table.json"), new
        {
            status = "pending-fresh-ghidra-analysis",
            binary = ".local/input/BFBC2_R34/Frost.Game.Main_Win32_Final.exe",
            goal = "Every GameManager dispatcher slot with address, symbol/log evidence, packet kind, response builders, and state writes.",
            slots = Array.Empty<object>()
        });

        await WriteJson(Path.Combine(repoRoot, "re/bfbc2/packet-types.json"), new
        {
            status = "pending-fresh-ghidra-analysis",
            packetTypes = Array.Empty<object>()
        });

        await WriteJson(Path.Combine(repoRoot, "re/bfbc2/handlers.json"), new
        {
            status = "pending-fresh-ghidra-analysis",
            handlers = Array.Empty<object>()
        });

        await WriteJson(Path.Combine(repoRoot, "re/bfbc2/serializer-writers.json"), new
        {
            status = "seeded-from-known-writer-shape",
            writers = new[]
            {
                new { name = "write-biased-sbyte", transform = "value + 0x80", confidence = "confirmed-by-TF-ELF-writer-pass" },
                new { name = "write-biased-int16", transform = "value + 0x8000", confidence = "confirmed-by-TF-ELF-writer-pass" },
                new { name = "write-uint64", transform = "big-endian/u64 payload writer", confidence = "needs BFBC2 cross-check" }
            }
        });

        await WriteJson(Path.Combine(repoRoot, "re/bfbc2/class-map.json"), new
        {
            status = "pending-rtti-and-ooanalyzer",
            classes = Array.Empty<object>()
        });

        await File.WriteAllTextAsync(Path.Combine(repoRoot, "re/bfbc2/state-machine.md"), """
            # BFBC2 R34 GameManager State Machine

            Fresh reverse-engineering target. Fill from Ghidra RTTI, log strings, dispatcher tables, and OOAnalyzer output.

            Required states:
            - connection accepted
            - reservation requested
            - reservation granted
            - player entered
            - roster sent
            - mesh associated
            - game joined
            - game started/source handoff equivalent
            - leave/drop cleanup
            """);

        await WriteJson(Path.Combine(repoRoot, "re/tf2ps3/handler-map.json"), new
        {
            status = "pending-ps3-ghidra-analysis",
            requiredScriptPath = "/home/deck/Documents/Decomp projects/Projects/Ps3GhidraScripts/",
            handlers = Array.Empty<object>()
        });

        await WriteJson(Path.Combine(repoRoot, "re/tf2ps3/bfbc2-crossmap.json"), new
        {
            status = "pending-cross-binary-analysis",
            mappings = Array.Empty<object>()
        });

        await File.WriteAllTextAsync(Path.Combine(repoRoot, "re/tf2ps3/client-state-machine.md"), """
            # TF2 PS3 GameManager Client State Machine

            Import `TF.elf` using the PS3 Ghidra scripts workflow:

            - Language: `PowerISA-Altivec-64-32addr`
            - Big-endian
            - Apply the PowerPC cspec `r2` unaffected-register fix before decompilation
            - Run `AnalyzePs3Binary.java` before auto-analysis
            - Run auto-analysis
            - Run `DefinePs3Syscalls.java`
            - Use `AssignPs3R2FromOpd.java` and jumptable recovery where needed

            Target client phases:
            - hello
            - ticket/reservation approval
            - roster
            - roster ack
            - join mesh
            - join announcement
            - full mesh
            - join complete
            - host hello/source handoff
            """);
    }

    private static Task WriteJson(string path, object value)
    {
        return File.WriteAllTextAsync(path, JsonSerializer.Serialize(value, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
    }
}
