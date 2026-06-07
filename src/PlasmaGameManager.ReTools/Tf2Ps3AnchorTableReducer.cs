using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Tf2Ps3AnchorTableReducer
{
    public static async Task ReduceAsync(string dataNeighborhoodPath, string dispatcherMapPath, string outputPath)
    {
        using var dataDoc = JsonDocument.Parse(File.ReadAllText(dataNeighborhoodPath));
        using var dispatcherDoc = JsonDocument.Parse(File.ReadAllText(dispatcherMapPath));

        var anchors = dataDoc.RootElement.GetProperty("anchors").EnumerateArray()
            .Select(Anchor.From)
            .ToArray();
        var dispatcherRows = dispatcherDoc.RootElement.GetProperty("dispatcherRows").EnumerateArray()
            .Select(DispatcherRow.From)
            .ToDictionary(static row => row.Role, StringComparer.Ordinal);
        var words = anchors
            .SelectMany(static anchor => anchor.References.SelectMany(static reference => reference.Window))
            .GroupBy(static word => word.Address, StringComparer.Ordinal)
            .Select(static group => group.First())
            .OrderBy(static word => word.Address, StringComparer.Ordinal)
            .ToArray();
        var roleByRef = anchors
            .SelectMany(anchor => anchor.References.Select(reference => new
            {
                reference.RefAddress,
                anchor.Role,
                anchor.StringAddress,
                anchor.StringValue,
                anchor.EvidenceKind
            }))
            .GroupBy(static reference => reference.RefAddress, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.ToArray(), StringComparer.Ordinal);

        var clusterWords = words
            .Where(static word => string.CompareOrdinal(word.Address, "019c0948") >= 0 && string.CompareOrdinal(word.Address, "019c09c8") <= 0)
            .Select(word =>
            {
                roleByRef.TryGetValue(word.Address, out var roles);
                return new ClusterWord(
                    word.Address,
                    word.Value,
                    word.Annotation,
                    roles?.Select(role =>
                    {
                        dispatcherRows.TryGetValue(role.Role, out var dispatcher);
                        return new RoleAnchor(
                            role.Role,
                            role.StringAddress,
                            role.StringValue,
                            role.EvidenceKind,
                            dispatcher?.EntryPointStatus ?? "not-in-dispatcher-map",
                            dispatcher?.PacketTypes ?? Array.Empty<int>());
                    }).ToArray() ?? Array.Empty<RoleAnchor>());
            })
            .ToArray();
        var unresolvedRoleSlots = clusterWords
            .Where(static word => word.RoleAnchors.Length > 0)
            .Select(word => new
            {
                word.Address,
                word.Value,
                word.Annotation,
                Roles = word.RoleAnchors.Select(static role => role.Role).Distinct(StringComparer.Ordinal).ToArray()
            })
            .ToArray();
        var executableCandidates = clusterWords
            .Where(static word => word.Annotation.Contains("executable", StringComparison.OrdinalIgnoreCase))
            .Select(word => new
            {
                word.Address,
                CandidateEntry = word.Value,
                NeighborRoles = NeighborRoles(clusterWords, word.Address)
            })
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-tf2ps3-data-neighborhood-anchor-table",
            note = "Condenses repeated TF.elf data-neighborhood windows into the contiguous GameManager string/table cluster. Code-looking values remain candidates only; they must be confirmed by PS3 Ghidra disassembly before becoming handler entries.",
            input = new
            {
                DataNeighborhood = dataNeighborhoodPath,
                DispatcherMap = dispatcherMapPath
            },
            summary = new
            {
                ClusterStart = "019c0948",
                ClusterEnd = "019c09c8",
                ClusterWordCount = clusterWords.Length,
                AnchoredWordCount = unresolvedRoleSlots.Length,
                ExecutableCandidateCount = executableCandidates.Length,
                UnresolvedAnchoredRoleCount = unresolvedRoleSlots.SelectMany(static slot => slot.Roles).Distinct(StringComparer.Ordinal).Count()
            },
            clusterWords,
            unresolvedRoleSlots,
            executableCandidates,
            nextNativeRecoveryTargets = new[]
            {
                "Use Ghidra to inspect the table owner and xrefs for 019c0988..019c09c0.",
                "Confirm whether 015d3f64 is code, thunk, table data, or a bad function start before promoting it.",
                "Recover callsites that load the adjacent string refs for receive-roster-ack, receive-full-mesh, receive-roster-element, and host-ack.",
                "Once entry points are confirmed, export field-level decompiles and bind them to packet type 4/5/8/9 builders."
            }
        }, JsonOptions));
    }

    private static string[] NeighborRoles(IEnumerable<ClusterWord> words, string candidateAddress)
    {
        var address = Convert.ToUInt32(candidateAddress, 16);
        return words
            .Where(word =>
            {
                var wordAddress = Convert.ToUInt32(word.Address, 16);
                return wordAddress >= address - 0x10 && wordAddress <= address + 0x20;
            })
            .SelectMany(static word => word.RoleAnchors)
            .Select(static role => (string)role.Role)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    private sealed record Anchor(string Role, string EvidenceKind, string StringAddress, string StringValue, Reference[] References)
    {
        public static Anchor From(JsonElement element)
        {
            return new Anchor(
                GetString(element, "Role"),
                GetString(element, "EvidenceKind"),
                GetString(element, "StringAddress"),
                GetString(element, "StringValue"),
                element.GetProperty("References").EnumerateArray().Select(Reference.From).ToArray());
        }
    }

    private sealed record Reference(string RefAddress, WindowWord[] Window)
    {
        public static Reference From(JsonElement element)
        {
            return new Reference(
                GetString(element, "RefAddress"),
                element.GetProperty("Window").EnumerateArray().Select(WindowWord.From).ToArray());
        }
    }

    private sealed record WindowWord(string Address, string Value, string Annotation)
    {
        public static WindowWord From(JsonElement element)
        {
            return new WindowWord(
                GetString(element, "Address"),
                GetString(element, "Value"),
                GetString(element, "Annotation"));
        }
    }

    private sealed record DispatcherRow(string Role, string EntryPointStatus, int[] PacketTypes)
    {
        public static DispatcherRow From(JsonElement element)
        {
            return new DispatcherRow(
                GetString(element, "Role"),
                GetString(element, "EntryPointStatus"),
                element.GetProperty("PacketTypes").EnumerateArray()
                    .Select(static packet => packet.GetProperty("Type").GetInt32())
                    .ToArray());
        }
    }

    private sealed record ClusterWord(string Address, string Value, string Annotation, RoleAnchor[] RoleAnchors);
    private sealed record RoleAnchor(string Role, string StringAddress, string StringValue, string EvidenceKind, string DispatcherStatus, int[] PacketTypes);

    private static string GetString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) ? value.GetString() ?? "" : "";
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}
