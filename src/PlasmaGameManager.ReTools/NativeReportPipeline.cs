using System.Diagnostics;
using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class NativeReportPipeline
{
    private static readonly string[] ReducerScripts =
    [
        "reduce-bfbc2-evidence.sh",
        "export-bfbc2-log-evidence.sh",
        "reduce-bfbc2-decompiles.sh",
        "reduce-bfbc2-pointer-evidence.sh",
        "reduce-bfbc2-recovered-callsites.sh",
        "reduce-bfbc2-recovered-pointers.sh",
        "reduce-bfbc2-server-send.sh",
        "reduce-bfbc2-transport-map.sh",
        "reduce-bfbc2-gamemanager-phases.sh",
        "reduce-bfbc2-server-gamemanager-listener.sh",
        "reduce-bfbc2-server-gamemanager-listener-complete.sh",
        "reduce-bfbc2-handle-message.sh",
        "reduce-bfbc2-handle-message-callees.sh",
        "reduce-bfbc2-switch-squad-mutation.sh",
        "reduce-bfbc2-join-chain.sh",
        "reduce-bfbc2-dispatcher-table.sh",
        "reduce-tf2ps3-gamemanager.sh",
        "reduce-tf2ps3-data-neighborhood.sh",
        "reduce-tf2ps3-dispatcher-map.sh",
        "reduce-tf2ps3-anchor-table.sh",
        "reduce-tf2ps3-anchor-context.sh",
        "reduce-tf2ps3-reader-functions.sh",
        "reduce-tf2ps3-reader-helpers.sh",
        "reduce-tf2ps3-second-level-helpers.sh",
        "reduce-tf2ps3-helper-callers.sh",
        "reduce-tf2ps3-dispatcher-map.sh",
        "reduce-tf2ps3-unresolved-targets.sh",
        "reduce-tf2ps3-unresolved-function-context.sh",
        "reduce-tf2ps3-source-network-anchors.sh",
        "analyze-pcaps.sh",
        "analyze-pcap-corpus.sh",
        "analyze-handoff-topology.sh",
        "analyze-source-streams.sh",
        "analyze-source-turn-contract.sh",
        "analyze-source-packet-shapes.sh",
        "analyze-source-replay-corpus.sh",
        "analyze-source-native-builder-correlation.sh",
        "analyze-source-transport.sh",
        "analyze-source-transport-fields.sh",
        "analyze-source-bridge-contract.sh",
        "analyze-client-visible-source-endpoints.sh",
        "analyze-source-backend-boundary.sh",
        "analyze-source-translation-readiness.sh",
        "reduce-acceptance-gates.sh"
    ];

    public static async Task RunAsync(string repoRoot, string outputPath, bool continueOnFailure)
    {
        var steps = new List<NativeReportPipelineStep>();
        foreach (var script in ReducerScripts)
        {
            var path = Path.Combine(repoRoot, "scripts", script);
            if (!File.Exists(path))
            {
                steps.Add(new NativeReportPipelineStep(script, "missing", 0, "script does not exist"));
                if (!continueOnFailure)
                {
                    break;
                }

                continue;
            }

            var result = await RunScriptAsync(repoRoot, path);
            steps.Add(new NativeReportPipelineStep(script, result.ExitCode == 0 ? "passed" : "failed", result.ExitCode, result.Output));
            if (result.ExitCode != 0 && !continueOnFailure)
            {
                break;
            }
        }

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            Status = "native-report-pipeline",
            ContinueOnFailure = continueOnFailure,
            StartedAt = DateTimeOffset.UtcNow,
            StepCount = steps.Count,
            Passed = steps.Count(static step => step.Status == "passed"),
            Failed = steps.Count(static step => step.Status == "failed"),
            Missing = steps.Count(static step => step.Status == "missing"),
            Steps = steps
        }, new JsonSerializerOptions { WriteIndented = true }));

        if (steps.Any(static step => step.Status is "failed" or "missing") && !continueOnFailure)
        {
            throw new InvalidOperationException($"Native report pipeline stopped at {steps.Last().Script}: {steps.Last().Status}");
        }
    }

    private static async Task<(int ExitCode, string Output)> RunScriptAsync(string repoRoot, string scriptPath)
    {
        var start = new ProcessStartInfo
        {
            FileName = "sh",
            WorkingDirectory = repoRoot,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false
        };
        start.ArgumentList.Add(scriptPath);

        using var process = Process.Start(start) ?? throw new InvalidOperationException($"Failed to start {scriptPath}");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        var output = ((await stdout) + (await stderr)).Trim();
        if (output.Length > 8000)
        {
            output = output[..8000] + "\n... truncated ...";
        }

        return (process.ExitCode, output);
    }
}

public sealed record NativeReportPipelineStep(
    string Script,
    string Status,
    int ExitCode,
    string Output);
