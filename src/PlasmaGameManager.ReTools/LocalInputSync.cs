namespace PlasmaGameManager.ReTools;

public static class LocalInputSync
{
    private static readonly string[] RequiredPcapRelativePaths =
    [
        "TF2_PS3_network_traffic/packets/server/connections/quick_match_to_motd_2fort_1.pcapng",
        "TF2_PS3_network_traffic/packets/server/connections/quick_match_to_motd_2fort_2.pcapng",
        "TF2_PS3_network_traffic/packets/server/connections/custom_match_joining_cp_db_to_motd_1.pcapng",
        "TF2_PS3_network_traffic/packets/server/creation/creating_and_join_cp_db_unranked_1.pcapng",
        "2Fort.PCAPNG",
        "dustbowl_final.PCAPNG",
        "tf2-ps3-packets/connect.pcapng",
        "tf2-ps3-packets/connecting.pcapng"
    ];

    public static LocalInputReport Sync(string repoRoot)
    {
        return Sync(repoRoot, LocalInputSourcePaths.FromEnvironment());
    }

    public static LocalInputReport Sync(string repoRoot, LocalInputSourcePaths sources)
    {
        Directory.CreateDirectory(Path.Combine(repoRoot, ".local/ghidra"));
        Directory.CreateDirectory(Path.Combine(repoRoot, ".local/ooanalyzer"));
        CopyDirectory(sources.Bfbc2R34Directory, Path.Combine(repoRoot, ".local/input/BFBC2_R34"));
        CopyIfExists(
            Path.Combine(sources.Tf2Ps3Usrdir, "BIN/TF.elf"),
            Path.Combine(repoRoot, ".local/input/TF2PS3/TF.elf"));
        CopyIfExists(
            Path.Combine(sources.Tf2Ps3Usrdir, "EBOOT.elf"),
            Path.Combine(repoRoot, ".local/input/TF2PS3/EBOOT.elf"));
        CopyDirectory(
            sources.PcapCorpusDirectory,
            Path.Combine(repoRoot, ".local/input/pcaps"));

        var report = ValidateSynced(repoRoot, sources);
        WriteReport(repoRoot, report);
        return report;
    }

    public static LocalInputReport ValidateSynced(string repoRoot)
    {
        var report = ValidateSynced(repoRoot, LocalInputSourcePaths.FromEnvironment());
        WriteReport(repoRoot, report);
        return report;
    }

    public static LocalInputReport ValidateSynced(string repoRoot, LocalInputSourcePaths sources)
    {
        var root = Path.Combine(repoRoot, ".local/input");
        var pcaps = Path.Combine(root, "pcaps");
        var inputs = new List<LocalInputStatus>
        {
            FileStatus("bfbc2-main-exe", sources.Bfbc2R34Directory, Path.Combine(root, "BFBC2_R34/Frost.Game.Main_Win32_Final.exe"), required: true),
            FileStatus("tf2ps3-tf-elf", Path.Combine(sources.Tf2Ps3Usrdir, "BIN/TF.elf"), Path.Combine(root, "TF2PS3/TF.elf"), required: true),
            FileStatus("tf2ps3-eboot-elf", Path.Combine(sources.Tf2Ps3Usrdir, "EBOOT.elf"), Path.Combine(root, "TF2PS3/EBOOT.elf"), required: false),
            DirectoryStatus("pcap-corpus", sources.PcapCorpusDirectory, pcaps, required: true),
            DirectoryStatus("ghidra-scratch", ".local/ghidra", Path.Combine(repoRoot, ".local/ghidra"), required: true),
            DirectoryStatus("ooanalyzer-scratch", ".local/ooanalyzer", Path.Combine(repoRoot, ".local/ooanalyzer"), required: true)
        };

        foreach (var relativePath in RequiredPcapRelativePaths)
        {
            inputs.Add(FileStatus($"pcap:{relativePath}", Path.Combine(sources.PcapCorpusDirectory, relativePath), Path.Combine(pcaps, relativePath), required: true));
        }

        var required = inputs.Where(static input => input.Required).ToArray();
        return new LocalInputReport(
            "local-input-sync-report",
            required.All(static input => input.Exists) ? "ready" : "missing-required-inputs",
            new LocalInputSummary(
                inputs.Count,
                required.Length,
                required.Count(static input => input.Exists),
                required.Count(static input => !input.Exists),
                Directory.Exists(pcaps) ? CountPcapFiles(pcaps) : 0),
            inputs);
    }

    private static void CopyDirectory(string source, string destination)
    {
        if (!Directory.Exists(source))
        {
            Console.WriteLine($"missing: {source}");
            return;
        }

        foreach (var directory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(Path.Combine(destination, Path.GetRelativePath(source, directory)));
        }

        Directory.CreateDirectory(destination);
        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            var target = Path.Combine(destination, Path.GetRelativePath(source, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
        }
    }

    private static void CopyIfExists(string source, string destination)
    {
        if (!File.Exists(source))
        {
            Console.WriteLine($"missing: {source}");
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.Copy(source, destination, overwrite: true);
    }

    private static LocalInputStatus FileStatus(string name, string source, string destination, bool required)
    {
        var info = new FileInfo(destination);
        return new LocalInputStatus(name, "file", source, destination, required, info.Exists, info.Exists ? info.Length : 0, 0);
    }

    private static LocalInputStatus DirectoryStatus(string name, string source, string destination, bool required)
    {
        var exists = Directory.Exists(destination);
        return new LocalInputStatus(name, "directory", source, destination, required, exists, 0, exists ? Directory.EnumerateFiles(destination, "*", SearchOption.AllDirectories).Count() : 0);
    }

    private static int CountPcapFiles(string directory)
    {
        return Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
            .Count(static file => file.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase)
                || file.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase));
    }

    private static void WriteReport(string repoRoot, LocalInputReport report)
    {
        var output = Path.Combine(repoRoot, "artifacts/local-input-status.json");
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        File.WriteAllText(output, System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }
}

public sealed record LocalInputSourcePaths(
    string Bfbc2R34Directory,
    string Tf2Ps3Usrdir,
    string PcapCorpusDirectory)
{
    public static LocalInputSourcePaths FromEnvironment()
    {
        return new LocalInputSourcePaths(
            Environment.GetEnvironmentVariable("PLASMA_BFBC2_R34_SOURCE")
                ?? "/home/deck/Downloads/BFBC2_R34",
            Environment.GetEnvironmentVariable("PLASMA_TF2PS3_USRDIR_SOURCE")
                ?? "/home/deck/Emulation/storage/rpcs3/dev_hdd0/game/BLES00153/USRDIR",
            Environment.GetEnvironmentVariable("PLASMA_PCAP_CORPUS_SOURCE")
                ?? "/home/deck/Downloads/drive-download-20260603T151509Z-3-001");
    }
}

public sealed record LocalInputReport(
    string Status,
    string OverallStatus,
    LocalInputSummary Summary,
    IReadOnlyList<LocalInputStatus> Inputs);

public sealed record LocalInputSummary(
    int InputCount,
    int RequiredInputCount,
    int RequiredPresentCount,
    int RequiredMissingCount,
    int PcapFileCount);

public sealed record LocalInputStatus(
    string Name,
    string Kind,
    string Source,
    string Destination,
    bool Required,
    bool Exists,
    long Bytes,
    int FileCount);
