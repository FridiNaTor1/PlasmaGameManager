using System.Net;
using PlasmaGameManager.Protocol;
using PlasmaGameManager.ReTools;

var command = args.Length > 0 ? args[0] : "help";
var repoRoot = FindRepoRoot();

switch (command)
{
    case "sync-inputs":
    {
        var report = LocalInputSync.Sync(repoRoot);
        Console.WriteLine($"local inputs synced into .local/input: {report.OverallStatus} ({report.Summary.RequiredPresentCount}/{report.Summary.RequiredInputCount} required)");
        break;
    }
    case "validate-inputs":
    {
        var report = LocalInputSync.ValidateSynced(repoRoot);
        Console.WriteLine($"local input status: {report.OverallStatus} ({report.Summary.RequiredPresentCount}/{report.Summary.RequiredInputCount} required)");
        break;
    }
    case "analyze-pcaps":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/pcaps");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-semantic-summary.json");
        var dispatcherMap = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/tf2ps3/dispatcher-map.json");
        await new PcapSemanticAnalyzer().AnalyzeDirectoryAsync(input, output, dispatcherMap);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "analyze-pcap-corpus":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/pcaps");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-corpus-coverage.json");
        var dispatcherMap = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/tf2ps3/dispatcher-map.json");
        await new PcapCorpusCoverageAnalyzer().AnalyzeDirectoryAsync(input, output, dispatcherMap);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "analyze-handoff-topology":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/pcaps");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-handoff-topology.json");
        var dispatcherMap = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/tf2ps3/dispatcher-map.json");
        await new PcapHandoffTopologyAnalyzer().AnalyzeDirectoryAsync(input, output, dispatcherMap);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "analyze-source-streams":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/pcaps");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-source-streams.json");
        await new PcapSourceStreamAnalyzer().AnalyzeDirectoryAsync(input, output);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "analyze-source-transport":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/pcaps");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-source-transport-semantics.json");
        await new PcapSourceTransportSemanticsAnalyzer().AnalyzeDirectoryAsync(input, output);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "analyze-source-transport-fields":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/pcaps");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-source-transport-fields.json");
        await new PcapSourceTransportFieldAnalyzer().AnalyzeDirectoryAsync(input, output);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "analyze-source-packet-shapes":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/pcaps");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-source-packet-shapes.json");
        await new PcapSourcePacketShapeAnalyzer().AnalyzeDirectoryAsync(input, output);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "analyze-source-replay-corpus":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/pcaps");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-source-replay-corpus.json");
        await new PcapSourceReplayCorpusAnalyzer().AnalyzeDirectoryAsync(input, output);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "analyze-source-turn-contract":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/pcaps");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-source-turn-contract.json");
        await new PcapSourceTurnContractAnalyzer().AnalyzeDirectoryAsync(input, output);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "analyze-source-native-builder-correlation":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/pcaps");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-source-native-builder-correlation.json");
        var sourceNetworkAnchorMap = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/tf2ps3/source-network-anchor-map.json");
        await new PcapSourceNativeBuilderCorrelationAnalyzer().AnalyzeDirectoryAsync(input, output, sourceNetworkAnchorMap);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "analyze-source-bridge-contract":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/pcaps");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-source-bridge-contract.json");
        await new PcapSourceBridgeContractAnalyzer().AnalyzeDirectoryAsync(input, output);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "analyze-client-visible-source-endpoints":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/pcaps");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-client-visible-source-endpoints.json");
        await new PcapClientVisibleSourceEndpointAnalyzer().AnalyzeDirectoryAsync(input, output);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "analyze-source-backend-boundary":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/pcaps");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-source-backend-boundary.json");
        var sourceNetworkAnchorMap = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/tf2ps3/source-network-anchor-map.json");
        await new PcapSourceBackendBoundaryAnalyzer().AnalyzeDirectoryAsync(input, output, sourceNetworkAnchorMap);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "analyze-source-translation-readiness":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/pcaps");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-source-translation-readiness.json");
        await new PcapSourceTranslationReadinessAnalyzer().AnalyzeDirectoryAsync(input, output);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "reduce-acceptance-gates":
    {
        var bfbc2Dispatcher = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/dispatcher-table.json");
        var tf2Dispatcher = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/tf2ps3/dispatcher-map.json");
        var pcapCorpus = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "artifacts/pcap-corpus-coverage.json");
        var output = args.Length > 4 ? args[4] : Path.Combine(repoRoot, "re/native-acceptance-gates.json");
        var liveHandoffEvidence = args.Length > 5 ? args[5] : Path.Combine(repoRoot, "artifacts/live-handoff-evidence.json");
        var sourceBridgeContract = args.Length > 6 ? args[6] : Path.Combine(repoRoot, "artifacts/pcap-source-bridge-contract.json");
        await NativeAcceptanceGateReducer.ReduceAsync(bfbc2Dispatcher, tf2Dispatcher, pcapCorpus, output, liveHandoffEvidence, sourceBridgeContract);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "rebuild-native-reports":
    {
        var output = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "artifacts/native-report-pipeline.json");
        var continueOnFailure = args.Any(static arg => arg == "--continue-on-failure");
        await NativeReportPipeline.RunAsync(repoRoot, output, continueOnFailure);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "analyze-live-handoff":
    {
        var eventLog = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "artifacts/live-gamemanager-events.jsonl");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/live-handoff-evidence.json");
        var sourceEvidence = args.Skip(3).ToArray();
        await new LiveHandoffEvidenceAnalyzer().AnalyzeAsync(eventLog, output, sourceEvidence);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "match-live-source-turns":
    {
        var eventLog = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "logs/gamemanager-events.jsonl");
        var contract = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/pcap-source-turn-contract.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "artifacts/live-source-turn-contract-match.json");
        await new LiveSourceTurnContractMatcher().MatchAsync(eventLog, contract, output);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "run-source-replay-backend":
    {
        var pcap = args.Length > 1
            ? args[1]
            : Path.Combine(repoRoot, ".local/input/pcaps/TF2_PS3_network_traffic/packets/server/connections/quick_match_to_motd_2fort_1.pcapng");
        var bind = IPAddress.Parse(args.Length > 2 ? args[2] : "127.0.0.1");
        var port = args.Length > 3 ? int.Parse(args[3]) : 27016;
        var evidenceLog = args.Length > 4 ? args[4] : "";
        var matchMode = args.Length > 5
            ? ParseReplayMatchMode(args[5])
            : ParseReplayMatchMode(Environment.GetEnvironmentVariable("PLASMA_SOURCE_REPLAY_MATCH_MODE") ?? "exact");
        var clientSearchWindow = args.Length > 6
            ? int.Parse(args[6])
            : int.Parse(Environment.GetEnvironmentVariable("PLASMA_SOURCE_REPLAY_SEARCH_WINDOW") ?? "0");
        var pacingMode = args.Length > 7
            ? ParseReplayPacingMode(args[7])
            : ParseReplayPacingMode(Environment.GetEnvironmentVariable("PLASMA_SOURCE_REPLAY_PACING") ?? "none");
        var maxReplayDelayMilliseconds = args.Length > 8
            ? int.Parse(args[8])
            : int.Parse(Environment.GetEnvironmentVariable("PLASMA_SOURCE_REPLAY_MAX_DELAY_MS") ?? "250");
        var backendMode = args.Length > 9
            ? ParseReplayBackendMode(args[9])
            : ParseReplayBackendMode(Environment.GetEnvironmentVariable("PLASMA_SOURCE_REPLAY_BACKEND_MODE") ?? "packet");
        if (!string.IsNullOrWhiteSpace(evidenceLog))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(evidenceLog)) ?? ".");
            await using var writer = File.AppendText(evidenceLog);
            await new PcapSourceReplayBackend().RunAsync(pcap, bind, port, CancellationToken.None, writer, matchMode, clientSearchWindow, pacingMode, maxReplayDelayMilliseconds, backendMode);
        }
        else
        {
            await new PcapSourceReplayBackend().RunAsync(pcap, bind, port, CancellationToken.None, matchMode: matchMode, clientSearchWindow: clientSearchWindow, pacingMode: pacingMode, maxReplayDelayMilliseconds: maxReplayDelayMilliseconds, backendMode: backendMode);
        }
        break;
    }
    case "run-source-turn-contract-backend":
    {
        var pcap = args.Length > 1
            ? args[1]
            : Path.Combine(repoRoot, ".local/input/pcaps");
        var bind = IPAddress.Parse(args.Length > 2 ? args[2] : "127.0.0.1");
        var port = args.Length > 3 ? int.Parse(args[3]) : 27016;
        var evidenceLog = args.Length > 4 ? args[4] : "";
        if (!string.IsNullOrWhiteSpace(evidenceLog))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(evidenceLog)) ?? ".");
            await using var writer = File.AppendText(evidenceLog);
            await new PcapSourceTurnContractBackend().RunAsync(pcap, bind, port, CancellationToken.None, writer);
        }
        else
        {
            await new PcapSourceTurnContractBackend().RunAsync(pcap, bind, port, CancellationToken.None);
        }
        break;
    }
    case "write-report-templates":
        await ReportTemplateWriter.WriteAsync(repoRoot);
        Console.WriteLine("wrote re/bfbc2 and re/tf2ps3 report templates");
        break;
    case "bfbc2-log-evidence":
    {
        var input = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/BFBC2_R34/RuntimeLog_FRIDIS-STEAMMAC_server.log");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/runtime-log-evidence.json");
        await Bfbc2LogEvidence.ExportAsync(input, output);
        Console.WriteLine($"wrote {output}");
        break;
    }
    case "reduce-bfbc2-evidence":
    {
        var focused = Path.Combine(repoRoot, "re/bfbc2/game-manager-focused-evidence.json");
        var fast = Path.Combine(repoRoot, "re/bfbc2/game-manager-evidence.json");
        var input = args.Length > 1 ? args[1] : File.Exists(focused) ? focused : fast;
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2");
        await Bfbc2EvidenceReducer.ReduceAsync(input, output);
        Console.WriteLine($"updated BFBC2 reports in {output}");
        break;
    }
    case "reduce-bfbc2-decompiles":
    {
        var handlers = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/handlers.json");
        var decompiles = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/server-function-decompiles.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/bfbc2/class-map.json");
        await Bfbc2DecompileReducer.ReduceAsync(handlers, decompiles, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-bfbc2-pointer-evidence":
    {
        var handlers = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/handlers.json");
        var pointers = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/function-pointer-evidence.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/bfbc2/dispatcher-table.json");
        await Bfbc2PointerEvidenceReducer.ReduceAsync(handlers, pointers, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-bfbc2-dispatcher-table":
    {
        var listenerComplete = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/server-gamemanager-listener-complete-map.json");
        var handleMessage = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/handle-message-branch-map.json");
        var phaseMap = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/bfbc2/gamemanager-phase-map.json");
        var output = args.Length > 4 ? args[4] : Path.Combine(repoRoot, "re/bfbc2/dispatcher-table.json");
        await Bfbc2DispatcherTableReducer.ReduceAsync(listenerComplete, handleMessage, phaseMap, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-bfbc2-caller-decompiles":
    {
        var dispatcher = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/dispatcher-table.json");
        var callers = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/caller-function-decompiles.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/bfbc2/caller-layer-summary.json");
        await Bfbc2CallerDecompileReducer.ReduceAsync(dispatcher, callers, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-bfbc2-recovered-callsites":
    {
        var recovered = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/recovered-callsite-functions.json");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/recovered-callsite-summary.json");
        await Bfbc2RecoveredCallsiteReducer.ReduceAsync(recovered, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-bfbc2-recovered-pointers":
    {
        var recovered = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/recovered-callsite-summary.json");
        var pointers = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/recovered-function-pointer-evidence.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/bfbc2/callback-table-map.json");
        await Bfbc2RecoveredPointerReducer.ReduceAsync(recovered, pointers, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-bfbc2-server-send":
    {
        var sendFunctions = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/server-send-functions.json");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/send-path-map.json");
        await Bfbc2ServerSendReducer.ReduceAsync(sendFunctions, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-bfbc2-transport-map":
    {
        var sendPointers = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/send-pointer-evidence.json");
        var lowLevelSend = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/low-level-send-decompiles.json");
        var packetParser = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/bfbc2/packet-parser-decompiles.json");
        var output = args.Length > 4 ? args[4] : Path.Combine(repoRoot, "re/bfbc2/transport-map.json");
        await Bfbc2TransportMapReducer.ReduceAsync(sendPointers, lowLevelSend, packetParser, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-bfbc2-gamemanager-phases":
    {
        var logFunctions = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/gamemanager-log-functions.json");
        var builderFunctions = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/gamemanager-builder-decompiles.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/bfbc2/gamemanager-phase-map.json");
        await Bfbc2GameManagerPhaseReducer.ReduceAsync(logFunctions, builderFunctions, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-bfbc2-server-gamemanager-listener":
    {
        var functions = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/server-gamemanager-listener-functions.json");
        var pointers = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/server-gamemanager-listener-pointer-evidence.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/bfbc2/server-gamemanager-listener-map.json");
        await Bfbc2ServerGameManagerListenerReducer.ReduceAsync(functions, pointers, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-bfbc2-server-gamemanager-listener-complete":
    {
        var exe = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/BFBC2_R34/Frost.Game.Main_Win32_Final.exe");
        var listenerMap = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/server-gamemanager-listener-map.json");
        var missingSlots = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/bfbc2/listener-missing-slot-decompiles.json");
        var output = args.Length > 4 ? args[4] : Path.Combine(repoRoot, "re/bfbc2/server-gamemanager-listener-complete-map.json");
        await Bfbc2ServerGameManagerListenerCompleteReducer.ReduceAsync(exe, listenerMap, missingSlots, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-bfbc2-handle-message":
    {
        var decompiles = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/listener-missing-slot-decompiles.json");
        var listenerMap = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/server-gamemanager-listener-complete-map.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/bfbc2/handle-message-branch-map.json");
        await Bfbc2HandleMessageReducer.ReduceAsync(decompiles, listenerMap, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-bfbc2-handle-message-callees":
    {
        var decompiles = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/handle-message-callee-decompiles.json");
        var handleMessageMap = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/handle-message-branch-map.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/bfbc2/handle-message-callee-map.json");
        await Bfbc2HandleMessageCalleeReducer.ReduceAsync(decompiles, handleMessageMap, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-bfbc2-switch-squad-mutation":
    {
        var decompiles = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/switch-squad-mutation-decompiles.json");
        var calleeMap = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/handle-message-callee-map.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/bfbc2/switch-squad-mutation-map.json");
        await Bfbc2SwitchSquadMutationReducer.ReduceAsync(decompiles, calleeMap, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-bfbc2-join-chain":
    {
        var functions = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/bfbc2/join-chain-functions.json");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/bfbc2/join-chain-map.json");
        await Bfbc2JoinChainReducer.ReduceAsync(functions, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-tf2ps3-gamemanager":
    {
        var evidence = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/tf2ps3/game-manager-analyzed-evidence.json");
        var functions = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/tf2ps3/gamemanager-function-decompiles.json");
        var bfbc2Phases = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/bfbc2/gamemanager-phase-map.json");
        var outputDir = args.Length > 4 ? args[4] : Path.Combine(repoRoot, "re/tf2ps3");
        await Tf2Ps3GameManagerReducer.ReduceAsync(evidence, functions, bfbc2Phases, outputDir);
        Console.WriteLine($"updated TF2 PS3 GameManager reports in {outputDir}");
        break;
    }
    case "reduce-tf2ps3-data-neighborhood":
    {
        var elf = args.Length > 1 ? args[1] : Path.Combine(repoRoot, ".local/input/TF2PS3/TF.elf");
        var handlerMap = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/tf2ps3/handler-map.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/tf2ps3/data-neighborhood-map.json");
        await Tf2Ps3DataNeighborhoodReducer.ReduceAsync(elf, handlerMap, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-tf2ps3-dispatcher-map":
    {
        var handlerMap = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/tf2ps3/handler-map.json");
        var dataNeighborhood = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/tf2ps3/data-neighborhood-map.json");
        var bfbc2Dispatcher = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/bfbc2/dispatcher-table.json");
        var defaultHelperCallerMap = Path.Combine(repoRoot, "re/tf2ps3/helper-caller-map.json");
        var helperCallerMap = args.Length > 5 ? args[4] : File.Exists(defaultHelperCallerMap) ? defaultHelperCallerMap : "";
        var output = args.Length > 5
            ? args[5]
            : args.Length > 4
                ? args[4]
                : Path.Combine(repoRoot, "re/tf2ps3/dispatcher-map.json");
        await Tf2Ps3DispatcherMapReducer.ReduceAsync(handlerMap, dataNeighborhood, bfbc2Dispatcher, output, helperCallerMap);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-tf2ps3-anchor-table":
    {
        var dataNeighborhood = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/tf2ps3/data-neighborhood-map.json");
        var dispatcherMap = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/tf2ps3/dispatcher-map.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/tf2ps3/anchor-table-map.json");
        await Tf2Ps3AnchorTableReducer.ReduceAsync(dataNeighborhood, dispatcherMap, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-tf2ps3-anchor-context":
    {
        var anchorContext = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/tf2ps3/anchor-context.json");
        var anchorTable = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/tf2ps3/anchor-table-map.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/tf2ps3/anchor-context-map.json");
        await Tf2Ps3AnchorContextReducer.ReduceAsync(anchorContext, anchorTable, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-tf2ps3-reader-functions":
    {
        var anchorContextMap = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/tf2ps3/anchor-context-map.json");
        var dispatcherMap = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/tf2ps3/dispatcher-map.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/tf2ps3/reader-function-map.json");
        await Tf2Ps3ReaderFunctionReducer.ReduceAsync(anchorContextMap, dispatcherMap, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-tf2ps3-reader-helpers":
    {
        var helperDecompiles = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/tf2ps3/reader-helper-function-decompiles.json");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/tf2ps3/reader-helper-map.json");
        await Tf2Ps3ReaderHelperReducer.ReduceAsync(helperDecompiles, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-tf2ps3-second-level-helpers":
    {
        var helperDecompiles = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/tf2ps3/second-level-helper-function-decompiles.json");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/tf2ps3/second-level-helper-map.json");
        await Tf2Ps3SecondLevelHelperReducer.ReduceAsync(helperDecompiles, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-tf2ps3-helper-callers":
    {
        var callerContext = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/tf2ps3/helper-caller-context.json");
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/tf2ps3/helper-caller-map.json");
        await Tf2Ps3HelperCallerReducer.ReduceAsync(callerContext, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-tf2ps3-unresolved-targets":
    {
        var dispatcherMap = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/tf2ps3/dispatcher-map.json");
        var dataNeighborhood = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/tf2ps3/data-neighborhood-map.json");
        var anchorTable = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/tf2ps3/anchor-table-map.json");
        var anchorContext = args.Length > 4 ? args[4] : Path.Combine(repoRoot, "re/tf2ps3/anchor-context-map.json");
        var readerFunctions = args.Length > 5 ? args[5] : Path.Combine(repoRoot, "re/tf2ps3/reader-function-map.json");
        var helperCallers = args.Length > 6 ? args[6] : Path.Combine(repoRoot, "re/tf2ps3/helper-caller-map.json");
        var output = args.Length > 7 ? args[7] : Path.Combine(repoRoot, "re/tf2ps3/unresolved-targets.json");
        await Tf2Ps3UnresolvedTargetReducer.ReduceAsync(dispatcherMap, dataNeighborhood, anchorTable, anchorContext, readerFunctions, helperCallers, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-tf2ps3-unresolved-function-context":
    {
        var functionContext = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/tf2ps3/unresolved-function-context.json");
        var unresolvedTargets = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/tf2ps3/unresolved-targets.json");
        var output = args.Length > 3 ? args[3] : Path.Combine(repoRoot, "re/tf2ps3/unresolved-function-context-map.json");
        await Tf2Ps3UnresolvedFunctionContextReducer.ReduceAsync(functionContext, unresolvedTargets, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "reduce-tf2ps3-source-network-anchors":
    {
        var cExport = args.Length > 1 ? args[1] : "/home/deck/TF.elf.c";
        var output = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "re/tf2ps3/source-network-anchor-map.json");
        await Tf2Ps3SourceNetworkAnchorReducer.ReduceAsync(cExport, output);
        Console.WriteLine($"updated {output}");
        break;
    }
    case "write-tf2ps3-unresolved-export-plan":
    {
        var unresolvedTargets = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "re/tf2ps3/unresolved-targets.json");
        var outputDir = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "artifacts/ghidra");
        await Tf2Ps3UnresolvedExportPlanWriter.WriteAsync(unresolvedTargets, outputDir);
        Console.WriteLine($"wrote TF2 unresolved export targets to {outputDir}");
        break;
    }
    case "ghidra-commands":
        PrintGhidraCommands(repoRoot);
        break;
    default:
        Console.WriteLine("""
            Usage:
              PlasmaGameManager.ReTools sync-inputs
              PlasmaGameManager.ReTools validate-inputs
              PlasmaGameManager.ReTools analyze-pcaps [input-dir] [output-json] [tf2-dispatcher-map-json]
              PlasmaGameManager.ReTools analyze-pcap-corpus [input-dir] [output-json] [tf2-dispatcher-map-json]
              PlasmaGameManager.ReTools analyze-handoff-topology [input-dir] [output-json] [tf2-dispatcher-map-json]
              PlasmaGameManager.ReTools analyze-source-streams [input-dir] [output-json]
              PlasmaGameManager.ReTools analyze-source-packet-shapes [input-dir] [output-json]
              PlasmaGameManager.ReTools analyze-source-replay-corpus [input-dir] [output-json]
              PlasmaGameManager.ReTools analyze-source-turn-contract [input-dir] [output-json]
              PlasmaGameManager.ReTools analyze-source-native-builder-correlation [input-dir] [output-json] [source-network-anchor-map-json]
              PlasmaGameManager.ReTools analyze-source-transport [input-dir] [output-json]
              PlasmaGameManager.ReTools analyze-source-transport-fields [input-dir] [output-json]
              PlasmaGameManager.ReTools analyze-source-bridge-contract [input-dir] [output-json]
              PlasmaGameManager.ReTools analyze-client-visible-source-endpoints [input-dir] [output-json]
              PlasmaGameManager.ReTools analyze-source-backend-boundary [input-dir] [output-json] [source-network-anchor-map-json]
              PlasmaGameManager.ReTools analyze-source-translation-readiness [input-dir] [output-json]
              PlasmaGameManager.ReTools analyze-live-handoff [gamemanager-events-jsonl] [output-json] [source-log-or-pcap ...]
              PlasmaGameManager.ReTools match-live-source-turns [gamemanager-events-jsonl] [turn-contract-json] [output-json]
              PlasmaGameManager.ReTools run-source-replay-backend [pcap] [bind-ip] [port] [evidence-jsonl] [exact|transport-shape] [client-search-window] [none|capture-timing] [max-delay-ms] [packet|turn]
              PlasmaGameManager.ReTools run-source-turn-contract-backend [pcap-or-dir] [bind-ip] [port] [evidence-jsonl]
              PlasmaGameManager.ReTools reduce-acceptance-gates [bfbc2-dispatcher-json] [tf2-dispatcher-json] [pcap-corpus-json] [output-json] [live-handoff-evidence-json] [source-bridge-contract-json]
              PlasmaGameManager.ReTools rebuild-native-reports [output-json] [--continue-on-failure]
              PlasmaGameManager.ReTools bfbc2-log-evidence [input-log] [output-json]
              PlasmaGameManager.ReTools reduce-bfbc2-evidence [evidence-json] [report-dir]
              PlasmaGameManager.ReTools reduce-bfbc2-decompiles [handlers-json] [decompiles-json] [class-map-json]
              PlasmaGameManager.ReTools reduce-bfbc2-pointer-evidence [handlers-json] [pointer-evidence-json] [dispatcher-table-json]
              PlasmaGameManager.ReTools reduce-bfbc2-dispatcher-table [listener-complete-json] [handle-message-json] [phase-map-json] [dispatcher-table-json]
              PlasmaGameManager.ReTools reduce-bfbc2-caller-decompiles [dispatcher-table-json] [caller-decompiles-json] [caller-summary-json]
              PlasmaGameManager.ReTools reduce-bfbc2-recovered-callsites [recovered-callsite-functions-json] [recovered-callsite-summary-json]
              PlasmaGameManager.ReTools reduce-bfbc2-recovered-pointers [recovered-callsite-summary-json] [recovered-function-pointer-evidence-json] [callback-table-map-json]
              PlasmaGameManager.ReTools reduce-bfbc2-server-send [server-send-functions-json] [send-path-map-json]
              PlasmaGameManager.ReTools reduce-bfbc2-transport-map [send-pointer-evidence-json] [low-level-send-decompiles-json] [packet-parser-decompiles-json] [transport-map-json]
              PlasmaGameManager.ReTools reduce-bfbc2-gamemanager-phases [gamemanager-log-functions-json] [gamemanager-builder-decompiles-json] [gamemanager-phase-map-json]
              PlasmaGameManager.ReTools reduce-bfbc2-server-gamemanager-listener [listener-functions-json] [listener-pointer-evidence-json] [listener-map-json]
              PlasmaGameManager.ReTools reduce-bfbc2-server-gamemanager-listener-complete [bfbc2-exe] [listener-map-json] [missing-slot-decompiles-json] [output-json]
              PlasmaGameManager.ReTools reduce-bfbc2-handle-message [missing-slot-decompiles-json] [listener-complete-map-json] [handle-message-map-json]
              PlasmaGameManager.ReTools reduce-bfbc2-handle-message-callees [callee-decompiles-json] [handle-message-map-json] [callee-map-json]
              PlasmaGameManager.ReTools reduce-bfbc2-switch-squad-mutation [mutation-decompiles-json] [callee-map-json] [mutation-map-json]
              PlasmaGameManager.ReTools reduce-bfbc2-join-chain [join-chain-functions-json] [join-chain-map-json]
              PlasmaGameManager.ReTools reduce-tf2ps3-gamemanager [tf-evidence-json] [tf-function-decompiles-json] [bfbc2-phase-map-json] [tf-output-dir]
              PlasmaGameManager.ReTools reduce-tf2ps3-data-neighborhood [tf-elf] [handler-map-json] [output-json]
              PlasmaGameManager.ReTools reduce-tf2ps3-dispatcher-map [handler-map-json] [data-neighborhood-json] [bfbc2-dispatcher-json] [helper-caller-map-json] [output-json]
              PlasmaGameManager.ReTools reduce-tf2ps3-anchor-table [data-neighborhood-json] [dispatcher-map-json] [output-json]
              PlasmaGameManager.ReTools reduce-tf2ps3-anchor-context [anchor-context-json] [anchor-table-json] [output-json]
              PlasmaGameManager.ReTools reduce-tf2ps3-reader-functions [anchor-context-map-json] [dispatcher-map-json] [output-json]
              PlasmaGameManager.ReTools reduce-tf2ps3-reader-helpers [helper-decompiles-json] [output-json]
              PlasmaGameManager.ReTools reduce-tf2ps3-second-level-helpers [helper-decompiles-json] [output-json]
              PlasmaGameManager.ReTools reduce-tf2ps3-helper-callers [caller-context-json] [output-json]
              PlasmaGameManager.ReTools reduce-tf2ps3-unresolved-targets [dispatcher-map-json] [data-neighborhood-json] [anchor-table-json] [anchor-context-map-json] [reader-function-map-json] [helper-caller-map-json] [output-json]
              PlasmaGameManager.ReTools reduce-tf2ps3-unresolved-function-context [function-context-json] [unresolved-targets-json] [output-json]
              PlasmaGameManager.ReTools reduce-tf2ps3-source-network-anchors [tf-elf-c-export] [output-json]
              PlasmaGameManager.ReTools write-tf2ps3-unresolved-export-plan [unresolved-targets-json] [output-dir]
              PlasmaGameManager.ReTools write-report-templates
              PlasmaGameManager.ReTools ghidra-commands
            """);
        break;
}

static Ps3SourceGameplayReplayMatchMode ParseReplayMatchMode(string value)
{
    return value.Trim().ToLowerInvariant() switch
    {
        "" or "exact" or "exact-payload" => Ps3SourceGameplayReplayMatchMode.ExactPayload,
        "shape" or "transport-shape" or "ps3-transport-shape" => Ps3SourceGameplayReplayMatchMode.TransportShape,
        _ => throw new ArgumentException($"Unsupported Source replay match mode: {value}")
    };
}

static PcapSourceReplayPacingMode ParseReplayPacingMode(string value)
{
    return value.Trim().ToLowerInvariant() switch
    {
        "" or "none" or "off" => PcapSourceReplayPacingMode.None,
        "pcap" or "capture" or "capture-timing" => PcapSourceReplayPacingMode.CaptureTiming,
        _ => throw new ArgumentException($"Unsupported Source replay pacing mode: {value}")
    };
}

static PcapSourceReplayBackendMode ParseReplayBackendMode(string value)
{
    return value.Trim().ToLowerInvariant() switch
    {
        "" or "packet" or "packet-replay" => PcapSourceReplayBackendMode.Packet,
        "turn" or "turn-replay" or "burst" or "client-turn" => PcapSourceReplayBackendMode.Turn,
        _ => throw new ArgumentException($"Unsupported Source replay backend mode: {value}")
    };
}

static string FindRepoRoot()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null)
    {
        if (Directory.Exists(Path.Combine(dir.FullName, ".git")))
        {
            return dir.FullName;
        }

        dir = dir.Parent;
    }

    return Directory.GetCurrentDirectory();
}

static void PrintGhidraCommands(string repoRoot)
{
    var ghidraProject = Path.Combine(repoRoot, "local-ghidra");
    Console.WriteLine($"""
        BFBC2 headless import target:
          analyzeHeadless "{ghidraProject}" BFBC2_R34 -import "{repoRoot}/.local/input/BFBC2_R34/Frost.Game.Main_Win32_Final.exe" -overwrite -analysisTimeoutPerFile 1800

        TF2 PS3 import target:
          Use /home/deck/Documents/Decomp projects/Projects/Ps3GhidraScripts/
          Language: PowerISA-Altivec-64-32addr, big-endian.
          Apply ppc_64_32.cspec r2 unaffected-register fix first.
          Run AnalyzePs3Binary.java before auto-analysis, then DefinePs3Syscalls.java after.
          analyzeHeadless "{ghidraProject}" TF2_PS3 -import "{repoRoot}/.local/input/TF2PS3/TF.elf" -processor PowerISA-Altivec-64-32addr -overwrite

        OOAnalyzer host route:
          flatpak-spawn --host podman --version
          Input binary: {repoRoot}/.local/input/BFBC2_R34/Frost.Game.Main_Win32_Final.exe
        """);
}
