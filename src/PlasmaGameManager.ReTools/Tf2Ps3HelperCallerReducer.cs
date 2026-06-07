using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Tf2Ps3HelperCallerReducer
{
    public static async Task ReduceAsync(string callerContextPath, string outputPath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(callerContextPath));
        var targets = doc.RootElement.GetProperty("addresses").EnumerateArray()
            .Select(TargetAddress.From)
            .ToArray();
        var functions = doc.RootElement.GetProperty("decompiledFunctions").EnumerateArray()
            .Select(DecompiledFunction.From)
            .ToArray();

        var callerRows = functions
            .SelectMany(function => Classify(function, targets))
            .Where(static row => row.Role != "native-helper-body")
            .OrderBy(static row => row.Entry, StringComparer.Ordinal)
            .ThenBy(static row => row.DispatcherRole, StringComparer.Ordinal)
            .ToArray();

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath) ?? ".");
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "seeded-from-tf2ps3-helper-caller-context",
            note = "Maps caller/callsite context around TF2 GameManager helpers back to native inbound phases. This report promotes newly recovered caller functions only where the decompile body carries concrete counter/state/packet-builder evidence.",
            input = callerContextPath,
            summary = new
            {
                TargetAddressCount = targets.Length,
                DecompiledFunctionCount = functions.Length,
                ClassifiedCallerCount = callerRows.Count(static row => row.Role != "unclassified-helper-caller"),
                NewlyResolvedDispatcherRoles = callerRows
                    .Where(static row => row.DispatcherRole.Length > 0)
                    .Select(static row => new { row.Entry, row.DispatcherRole, row.Confidence })
                    .ToArray(),
                DataTableTargetCount = targets.Count(static target => target.DataRefs.Length > 0),
                DirectCallTargetCount = targets.Count(static target => target.DirectCallRefs.Length > 0)
            },
            targetRefs = targets.Select(static target => new
            {
                target.Address,
                target.FunctionName,
                target.DataRefs,
                target.DirectCallRefs
            }).ToArray(),
            callers = callerRows,
            nextNativeTargets = new[]
            {
                "Update the canonical TF2 dispatcher reducer to consume this caller map and promote 015d5fa0 for process-roster-notice-and-send-host-ack once the inbound table slot is tied to that entry.",
                "Export/decompile pointer-table region around 01964418..01964420 to bind entries 015d5a00, 015d5d50, and 015d5fa0 to exact dispatcher indices.",
                "Classify 015d8580 more deeply; it parses the large session/create payload and may cover reservation/session bootstrap fields."
            }
        }, JsonOptions));
    }

    private static CallerRow[] Classify(DecompiledFunction function, TargetAddress[] targets)
    {
        var classified = function.Entry switch
        {
            "015ae358" => new[] { Row(function, "make-connection-id-and-outbound-session", "make-connection-id", "high", "TF2 split equivalent of BFBC2 MakeConnId/outbound association creation: builds descriptor structures, formats the 0x20-byte connident through 0158e430, selects outbound mode through 01589140, opens the manager at player-session +0x94 with player +0x150 and byte +0x169, stores the outbound session object in join object slot 10, then submits setup payloads.", new[]
            {
                "015ad060",
                "015acfb0",
                "015ae2a8",
                "0158e430",
                "01589140"
            }, targets) },
            "015d5d50" => new[] { Row(function, "receive-join-announcement-and-propagate-player-join", "receive-roster-ack", "high", "TF2 split equivalent of BFBC2 roster-ack/join-announcement handling: reads the incoming join player tuple with 01587ed8, logs the joining player id, rejects duplicate/local-player joins through 0158e1a0 and the local player in slot 0x5d, builds or resolves the join object through 015d5a00, marks it ready with 0158f078, and either creates an outbound join session with 015ae358 or broadcasts the built join object to listeners when session state is 5.", new[]
            {
                "01587ed8",
                "0158e1a0",
                "015d5a00",
                "0158f078",
                "015ae358"
            }, targets) },
            "015d5fa0" => new[]
            {
                Row(function, "receive-roster-element-and-update-counter", "receive-roster-element", "high", "Receives a roster element/player object through 015d5a00, compares it to the current host/player object, stores it in slot 0x5d or marks it ready via 0158f078, increments processed roster count slot 0x85, and logs progress against expected count slot 0x86.", new[]
                {
                    "015d5a00",
                    "0158f078"
                }, targets),
                Row(function, "roster-notice-counter-and-host-ack", "process-roster-notice-and-send-host-ack", "high", "After all roster elements arrive, fans out outbound join sessions with 015ae358, builds native type 4, sends it through vtable +0xb8, and logs host roster ack completion.", new[]
                {
                    "015d5a00",
                    "0158f078",
                    "015ae358",
                    "0158d800",
                    "0158d530"
                }, targets)
            },
            "015d6388" => new[] { Row(function, "full-mesh-complete-and-start-transition", "receive-full-mesh", "medium", "Reads a player id tuple, requires it to match session slot 0x31, completes the local/current player through 015d01f8, toggles completed outbound/session objects, advances state with 01589610(param_1, 5), and notifies listeners through vtable +8. This matches the full-mesh completion/start transition but needs table-slot binding.", new[]
            {
                "01587ed8",
                "0158fa18",
                "015d01f8",
                "01589610",
                "015949c8"
            }, targets) },
            "015d8580" => new[] { Row(function, "reservation-take-and-session-bootstrap", "reservation-take", "high", "Parses the large session bootstrap/create payload behind the recovered reservation log slot: reads multiple bytes/shorts/strings, resets roster and completion pools, reads expected roster notice count into slot 0x86, optionally creates the local player object through 015d5a00, and finalizes bootstrap state through 0158fa18.", new[]
            {
                "01587e20",
                "01590a18",
                "01587dd0",
                "01587dd8",
                "01587cf0",
                "01589378",
                "015d5a00",
                "0158f078",
                "0158fa18"
            }, targets) },
            "015ae698" => new[] { Row(function, "outbound-join-session-wrapper", "", "medium", "Wrapper around outbound join-session creation for an existing player object. It looks up the player by id, checks vtable +0x2c, builds the same descriptor set as 015ae358, and stores the outbound object in player slot 10.", new[]
            {
                "015a7178",
                "015ad060",
                "015acfb0",
                "015ae2a8",
                "0158e430",
                "01589140"
            }, targets) },
            _ => new[] { Row(function, "unclassified-helper-caller", "", "low", "Caller function exported through helper xrefs but not yet classified into a TF2 GameManager phase.", Callees(function.Body), targets) }
        };

        if (classified.Length == 1 && classified[0].Role == "unclassified-helper-caller" && KnownHelperBodies.Contains(function.Entry))
        {
            return new[] { Row(function, "native-helper-body", "", "none", "Exported target helper body, not a caller phase.", Array.Empty<string>(), targets) };
        }

        return classified;
    }

    private static CallerRow Row(DecompiledFunction function, string role, string dispatcherRole, string confidence, string semantics, string[] expectedCallees, TargetAddress[] targets)
    {
        var callees = Callees(function.Body);
        var refs = targets
            .Where(target => target.DirectCallRefs.Any(reference => reference.FromFunction == function.Entry) || target.DataRefs.Any(reference => reference.FromFunction == function.Entry))
            .Select(target => new CallerTargetRef(
                target.Address,
                target.FunctionName,
                target.DirectCallRefs.Where(reference => reference.FromFunction == function.Entry).Select(reference => reference.From).ToArray(),
                target.DataRefs.Where(reference => reference.FromFunction == function.Entry).Select(reference => reference.From).ToArray()))
            .ToArray();

        return new CallerRow(
            function.Entry,
            function.Name,
            role,
            dispatcherRole,
            confidence,
            semantics,
            expectedCallees.Where(callee => callees.Contains(callee, StringComparer.Ordinal)).ToArray(),
            callees,
            refs,
            ExtractSlotEvidence(function.Body),
            function.Body.Length);
    }

    private static string[] ExtractSlotEvidence(string body)
    {
        var evidence = new List<string>();
        foreach (var marker in new[] { "0x85", "0x86", "0x31", "0x5d", "0x5b", "0xb8", "0x94", "0x150", "0x169", "0x20", "0x782c", "0x7830", "0x7834", "0x7838", "0x7840", "0x783c" })
        {
            if (body.Contains(marker, StringComparison.Ordinal))
            {
                evidence.Add(marker);
            }
        }

        if (body.Contains("_opd_FUN_0158d800(auStack_460,4)", StringComparison.Ordinal))
        {
            evidence.Add("builds native packet type 4");
        }

        if (body.Contains("param_1[0x85] != param_1[0x86]", StringComparison.Ordinal))
        {
            evidence.Add("processed-count gate 0x85 == 0x86");
        }

        return evidence.ToArray();
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

    private sealed record TargetAddress(string Address, string FunctionName, ReferenceRow[] DataRefs, ReferenceRow[] DirectCallRefs)
    {
        public static TargetAddress From(JsonElement element)
        {
            var refs = element.GetProperty("refsTo").EnumerateArray().Select(ReferenceRow.Parse).ToArray();
            var functionName = "";
            if (element.TryGetProperty("functionAt", out var functionAt) && functionAt.ValueKind != JsonValueKind.Null)
            {
                functionName = GetString(functionAt, "name");
            }

            return new TargetAddress(
                GetString(element, "address"),
                functionName,
                refs.Where(static reference => reference.Type == "DATA").ToArray(),
                refs.Where(static reference => reference.Type.Contains("CALL", StringComparison.Ordinal) || reference.Type.Contains("JUMP", StringComparison.Ordinal)).ToArray());
        }
    }

    private sealed record ReferenceRow(string From, string To, string Type, string FromFunction)
    {
        public static ReferenceRow Parse(JsonElement element)
        {
            return new ReferenceRow(
                GetString(element, "from"),
                GetString(element, "to"),
                GetString(element, "type"),
                GetString(element, "fromFunction"));
        }
    }

    private sealed record DecompiledFunction(string Entry, string Name, string Body)
    {
        public static DecompiledFunction From(JsonElement element)
        {
            return new DecompiledFunction(
                GetString(element, "entry"),
                GetString(element, "name"),
                GetString(element, "body"));
        }
    }

    private sealed record CallerTargetRef(string TargetAddress, string TargetFunctionName, string[] DirectCallSites, string[] DataRefSites);

    private sealed record CallerRow(
        string Entry,
        string Name,
        string Role,
        string DispatcherRole,
        string Confidence,
        string Semantics,
        string[] MatchedExpectedCallees,
        string[] AllCallees,
        CallerTargetRef[] TargetRefs,
        string[] SlotEvidence,
        int BodyLength);

    private static string GetString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) ? value.GetString() ?? "" : "";
    }

    private static readonly HashSet<string> KnownHelperBodies = new(StringComparer.Ordinal)
    {
        "015d4e20",
        "015d5d50",
        "015a2220",
        "015a2300",
        "015a7178",
        "015d5a00",
        "015938f8",
        "015d01f8",
        "015ae358",
        "0158e430",
        "01589140"
    };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}
