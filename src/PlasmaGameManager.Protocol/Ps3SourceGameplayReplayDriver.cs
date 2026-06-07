namespace PlasmaGameManager.Protocol;

public sealed class Ps3SourceGameplayReplayDriver
{
    private readonly Ps3SourceGameplayReplayStep[] _steps;
    private readonly Ps3SourceGameplayReplayMatchMode _matchMode;
    private readonly int _clientSearchWindow;
    private int _cursor;

    public Ps3SourceGameplayReplayDriver(
        IEnumerable<Ps3SourceGameplayReplayStep> steps,
        Ps3SourceGameplayReplayMatchMode matchMode = Ps3SourceGameplayReplayMatchMode.ExactPayload,
        int clientSearchWindow = 0)
    {
        _steps = steps.ToArray();
        _matchMode = matchMode;
        _clientSearchWindow = Math.Max(0, clientSearchWindow);
    }

    public int Cursor => _cursor;

    public bool IsComplete => _cursor >= _steps.Length;

    public Ps3SourceGameplayReplayResult HandleClientPacket(ReadOnlySpan<byte> payload)
    {
        SkipLeadingServerPackets();
        if (_cursor >= _steps.Length)
        {
            return new Ps3SourceGameplayReplayResult(
            false,
            true,
            _cursor,
            null,
            null,
            [],
            Ps3SourceGameplayReplayMatchKind.None,
            "Replay script is complete; no client packet was expected.");
        }

        var search = FindMatchingClientStep(payload);
        if (!search.Found)
        {
            return new Ps3SourceGameplayReplayResult(
                false,
                false,
                _cursor,
                null,
                null,
                [],
                Ps3SourceGameplayReplayMatchKind.None,
                search.Explanation);
        }

        if (search.StepIndex > _cursor)
        {
            _cursor = search.StepIndex;
        }

        var expected = _steps[_cursor];
        if (expected.Direction != Ps3SourceGameplayDirection.ClientToServer)
        {
            return new Ps3SourceGameplayReplayResult(
                false,
                false,
                _cursor,
                null,
                null,
                [],
                Ps3SourceGameplayReplayMatchKind.None,
                $"Expected {expected.Direction} at replay step {_cursor}, not a client packet.");
        }

        var match = search.Match;

        _cursor++;
        var responses = DrainContiguousServerPackets();
        return new Ps3SourceGameplayReplayResult(
            true,
            IsComplete,
            _cursor,
            expected.PacketIndex,
            expected.TimestampMicroseconds,
            responses,
            match.MatchKind,
            responses.Length == 0
                ? $"{search.Explanation}; no immediate server packets before the next client packet."
                : $"{search.Explanation}; emitted {responses.Length} captured server packet(s).");
    }

    private ReplayClientSearch FindMatchingClientStep(ReadOnlySpan<byte> payload)
    {
        var checkedClientSteps = 0;
        ReplayPayloadMatch? firstMismatch = null;
        for (var index = _cursor; index < _steps.Length; index++)
        {
            if (_steps[index].Direction != Ps3SourceGameplayDirection.ClientToServer)
            {
                continue;
            }

            if (checkedClientSteps > _clientSearchWindow)
            {
                break;
            }

            var match = MatchPayload(payload, _steps[index].Payload);
            if (match.Matched)
            {
                return new ReplayClientSearch(true, index, match, index == _cursor
                    ? $"Matched expected client replay step {_cursor}: {match.Explanation}"
                    : $"Resynchronized from replay step {_cursor} to client step {index}: {match.Explanation}");
            }

            firstMismatch ??= match;
            checkedClientSteps++;
        }

        var searchDescription = _clientSearchWindow == 0
            ? $"Client packet did not match replay step {_cursor}"
            : $"Client packet did not match replay step {_cursor} or the next {_clientSearchWindow} client step(s)";
        return new ReplayClientSearch(
            false,
            _cursor,
            firstMismatch ?? new ReplayPayloadMatch(false, Ps3SourceGameplayReplayMatchKind.None, "no client replay step was available"),
            $"{searchDescription}: {(firstMismatch?.Explanation ?? "no client replay step was available")}");
    }

    private ReplayPayloadMatch MatchPayload(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected)
    {
        if (actual.SequenceEqual(expected))
        {
            return new ReplayPayloadMatch(true, Ps3SourceGameplayReplayMatchKind.ExactPayload, "exact payload");
        }

        if (_matchMode == Ps3SourceGameplayReplayMatchMode.ExactPayload)
        {
            return new ReplayPayloadMatch(false, Ps3SourceGameplayReplayMatchKind.None, "exact payload mode");
        }

        if (!Ps3SourceTransportPacket.TryDecode(actual, out var actualTransport)
            || !Ps3SourceTransportPacket.TryDecode(expected, out var expectedTransport))
        {
            return new ReplayPayloadMatch(false, Ps3SourceGameplayReplayMatchKind.None, "one or both payloads are not PS3 Source transport packets");
        }

        if (actualTransport.PayloadLength != expectedTransport.PayloadLength)
        {
            return new ReplayPayloadMatch(
                false,
                Ps3SourceGameplayReplayMatchKind.None,
                $"payload length differs actual={actualTransport.PayloadLength} expected={expectedTransport.PayloadLength}");
        }

        if (actualTransport.Body.Length != expectedTransport.Body.Length)
        {
            return new ReplayPayloadMatch(
                false,
                Ps3SourceGameplayReplayMatchKind.None,
                $"body length differs actual={actualTransport.Body.Length} expected={expectedTransport.Body.Length}");
        }

        var actualShape = Ps3SourceGameplaySession.ClassifyShape(actualTransport);
        var expectedShape = Ps3SourceGameplaySession.ClassifyShape(expectedTransport);
        if (actualShape != expectedShape)
        {
            return new ReplayPayloadMatch(false, Ps3SourceGameplayReplayMatchKind.None, $"packet shape differs actual={actualShape} expected={expectedShape}");
        }

        if (actualTransport.Body.SequenceEqual(expectedTransport.Body))
        {
            return new ReplayPayloadMatch(
                true,
                Ps3SourceGameplayReplayMatchKind.ExactTransportBody,
                $"transport body exact, sequence actual={actualTransport.CandidateSequence} expected={expectedTransport.CandidateSequence}, shape={actualShape}, len={actualTransport.PayloadLength}");
        }

        return new ReplayPayloadMatch(true, Ps3SourceGameplayReplayMatchKind.TransportShape, $"transport shape {actualShape}, len={actualTransport.PayloadLength}");
    }

    private void SkipLeadingServerPackets()
    {
        while (_cursor < _steps.Length && _steps[_cursor].Direction == Ps3SourceGameplayDirection.ServerToClient)
        {
            _cursor++;
        }
    }

    private Ps3SourceGameplayReplayStep[] DrainContiguousServerPackets()
    {
        var start = _cursor;
        while (_cursor < _steps.Length && _steps[_cursor].Direction == Ps3SourceGameplayDirection.ServerToClient)
        {
            _cursor++;
        }

        return _steps[start.._cursor];
    }

    private sealed record ReplayPayloadMatch(
        bool Matched,
        Ps3SourceGameplayReplayMatchKind MatchKind,
        string Explanation);

    private sealed record ReplayClientSearch(
        bool Found,
        int StepIndex,
        ReplayPayloadMatch Match,
        string Explanation);
}

public enum Ps3SourceGameplayReplayMatchMode
{
    ExactPayload,
    TransportShape
}

public enum Ps3SourceGameplayReplayMatchKind
{
    None,
    TransportShape,
    ExactTransportBody,
    ExactPayload
}

public sealed record Ps3SourceGameplayReplayStep(
    Ps3SourceGameplayDirection Direction,
    byte[] Payload,
    long PacketIndex,
    long TimestampMicroseconds);

public sealed record Ps3SourceGameplayReplayResult(
    bool Matched,
    bool IsComplete,
    int Cursor,
    long? MatchedClientPacketIndex,
    long? MatchedClientTimestampMicroseconds,
    Ps3SourceGameplayReplayStep[] ServerResponses,
    Ps3SourceGameplayReplayMatchKind MatchKind,
    string Explanation);
