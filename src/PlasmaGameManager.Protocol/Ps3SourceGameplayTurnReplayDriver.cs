namespace PlasmaGameManager.Protocol;

public sealed class Ps3SourceGameplayTurnReplayDriver
{
    private readonly Ps3SourceGameplayReplayTurn[] _turns;
    private readonly Ps3SourceGameplayReplayMatchMode _matchMode;
    private int _turnCursor;
    private int _clientCursor;

    public Ps3SourceGameplayTurnReplayDriver(
        IEnumerable<Ps3SourceGameplayReplayStep> steps,
        Ps3SourceGameplayReplayMatchMode matchMode = Ps3SourceGameplayReplayMatchMode.ExactPayload)
    {
        _turns = BuildTurns(steps.ToArray());
        _matchMode = matchMode;
    }

    public int TurnCursor => _turnCursor;

    public int ClientCursor => _clientCursor;

    public bool IsComplete => _turnCursor >= _turns.Length;

    public IReadOnlyList<Ps3SourceGameplayReplayTurn> Turns => _turns;

    public Ps3SourceGameplayTurnReplayResult HandleClientPacket(ReadOnlySpan<byte> payload)
    {
        if (IsComplete)
        {
            return new Ps3SourceGameplayTurnReplayResult(
                false,
                true,
                _turnCursor,
                _clientCursor,
                0,
                null,
                null,
                [],
                Ps3SourceGameplaySignatures.BodyRunSignature([]),
                Ps3SourceGameplaySignatures.BodyRunSignature([]),
                Ps3SourceGameplaySignatures.TurnBodySignature([], []),
                Ps3SourceGameplayReplayMatchKind.None,
                "Turn replay script is complete; no client packet was expected.");
        }

        var turn = _turns[_turnCursor];
        var turnSignature = BuildTurnSignature(turn);
        var expected = turn.ClientPackets[_clientCursor];
        var match = MatchPayload(payload, expected.Payload);
        if (!match.Matched)
        {
            return new Ps3SourceGameplayTurnReplayResult(
                false,
                false,
                _turnCursor,
                _clientCursor,
                turn.ClientPackets.Length,
                null,
                null,
                [],
                turnSignature.ClientBodySignature,
                turnSignature.ServerBodySignature,
                turnSignature.TurnBodySignature,
                Ps3SourceGameplayReplayMatchKind.None,
                $"Client packet did not match turn {_turnCursor} client packet {_clientCursor}: {match.Explanation}");
        }

        _clientCursor++;
        if (_clientCursor < turn.ClientPackets.Length)
        {
            return new Ps3SourceGameplayTurnReplayResult(
                true,
                false,
                _turnCursor,
                _clientCursor,
                turn.ClientPackets.Length,
                expected.PacketIndex,
                expected.TimestampMicroseconds,
                [],
                turnSignature.ClientBodySignature,
                turnSignature.ServerBodySignature,
                turnSignature.TurnBodySignature,
                match.MatchKind,
                $"Matched turn {_turnCursor} client packet {_clientCursor - 1}/{turn.ClientPackets.Length - 1}: {match.Explanation}; waiting for {turn.ClientPackets.Length - _clientCursor} more client packet(s).");
        }

        var responses = turn.ServerResponses;
        _turnCursor++;
        _clientCursor = 0;
        return new Ps3SourceGameplayTurnReplayResult(
            true,
            IsComplete,
            _turnCursor,
            _clientCursor,
            0,
            expected.PacketIndex,
            expected.TimestampMicroseconds,
            responses,
            turnSignature.ClientBodySignature,
            turnSignature.ServerBodySignature,
            turnSignature.TurnBodySignature,
            match.MatchKind,
            responses.Length == 0
                ? $"Matched complete turn {_turnCursor - 1}: {match.Explanation}; no server response packets were captured."
                : $"Matched complete turn {_turnCursor - 1}: {match.Explanation}; emitted {responses.Length} captured server response packet(s).");
    }

    public static Ps3SourceGameplayReplayTurn[] BuildTurns(IReadOnlyList<Ps3SourceGameplayReplayStep> steps)
    {
        var turns = new List<Ps3SourceGameplayReplayTurn>();
        var index = 0;
        while (index < steps.Count)
        {
            while (index < steps.Count && steps[index].Direction != Ps3SourceGameplayDirection.ClientToServer)
            {
                index++;
            }

            if (index >= steps.Count)
            {
                break;
            }

            var clientStart = index;
            while (index < steps.Count && steps[index].Direction == Ps3SourceGameplayDirection.ClientToServer)
            {
                index++;
            }

            var serverStart = index;
            while (index < steps.Count && steps[index].Direction == Ps3SourceGameplayDirection.ServerToClient)
            {
                index++;
            }

            turns.Add(new Ps3SourceGameplayReplayTurn(
                turns.Count,
                steps.Skip(clientStart).Take(serverStart - clientStart).ToArray(),
                steps.Skip(serverStart).Take(index - serverStart).ToArray()));
        }

        return turns.ToArray();
    }

    private static Ps3SourceGameplayReplayTurnSignature BuildTurnSignature(Ps3SourceGameplayReplayTurn turn)
    {
        return new Ps3SourceGameplayReplayTurnSignature(
            Ps3SourceGameplaySignatures.BodyRunSignature(turn.ClientPackets.Select(static step => step.Payload)),
            Ps3SourceGameplaySignatures.BodyRunSignature(turn.ServerResponses.Select(static step => step.Payload)),
            Ps3SourceGameplaySignatures.TurnBodySignature(
                turn.ClientPackets.Select(static step => step.Payload),
                turn.ServerResponses.Select(static step => step.Payload)));
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

    private sealed record ReplayPayloadMatch(
        bool Matched,
        Ps3SourceGameplayReplayMatchKind MatchKind,
        string Explanation);
}

public sealed record Ps3SourceGameplayReplayTurn(
    int TurnIndex,
    Ps3SourceGameplayReplayStep[] ClientPackets,
    Ps3SourceGameplayReplayStep[] ServerResponses);

public sealed record Ps3SourceGameplayReplayTurnSignature(
    string ClientBodySignature,
    string ServerBodySignature,
    string TurnBodySignature);

public sealed record Ps3SourceGameplayTurnReplayResult(
    bool Matched,
    bool IsComplete,
    int TurnCursor,
    int ClientCursor,
    int ExpectedClientPacketsInTurn,
    long? MatchedClientPacketIndex,
    long? MatchedClientTimestampMicroseconds,
    Ps3SourceGameplayReplayStep[] ServerResponses,
    string ClientBodySignature,
    string ServerBodySignature,
    string TurnBodySignature,
    Ps3SourceGameplayReplayMatchKind MatchKind,
    string Explanation);
