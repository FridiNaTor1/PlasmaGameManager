using System.Net;
using System.Net.Sockets;
using PlasmaGameManager.Protocol;

namespace PlasmaGameManager.Server;

public sealed class UdpGameManagerServer
{
    private readonly IGameManagerProfile _profile;
    private readonly IGameManagerEventSink? _eventSink;
    private readonly SourceBackendProxy _sourceProxy;
    private readonly PlasmaPacketClassifier _classifier = new();
    private readonly GameManagerCommandDecoder _commandDecoder = new();
    private readonly GameManagerSession _game = new();
    private readonly SemaphoreSlim _packetGate = new(1, 1);

    public UdpGameManagerServer(IGameManagerProfile profile, IGameManagerEventSink? eventSink = null, SourceBackendOptions? sourceBackend = null)
    {
        _profile = profile;
        _eventSink = eventSink;
        _sourceProxy = new SourceBackendProxy(sourceBackend ?? SourceBackendOptions.Disabled, RecordSourceProxyError);
    }

    public async Task RunAsync(IPAddress address, int port, CancellationToken ct)
    {
        await RunAsync(address, new[] { port }, ct);
    }

    public async Task RunAsync(IPAddress address, IReadOnlyCollection<int> ports, CancellationToken ct)
    {
        if (ports.Count == 0)
        {
            throw new ArgumentException("At least one UDP port must be supplied.", nameof(ports));
        }

        var sockets = ports
            .Distinct()
            .OrderBy(static p => p)
            .Select(port => new UdpClient(new IPEndPoint(address, port)))
            .ToArray();

        try
        {
            var tasks = sockets.Select(socket => RunSocketAsync(socket, address, ((IPEndPoint)socket.Client.LocalEndPoint!).Port, ct)).ToArray();
            await Task.WhenAll(tasks);
        }
        finally
        {
            foreach (var socket in sockets)
            {
                socket.Dispose();
            }

            await _sourceProxy.DisposeAsync();
        }
    }

    private async Task RunSocketAsync(UdpClient socket, IPAddress address, int port, CancellationToken ct)
    {
        Console.WriteLine($"PlasmaGameManager listening on {address}:{port} profile={_profile.Name}");

        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult received;
            try
            {
                received = await socket.ReceiveAsync(ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            await _packetGate.WaitAsync(ct);
            try
            {
                await HandleReceivedAsync(socket, received, ct);
            }
            finally
            {
                _packetGate.Release();
            }
        }
    }

    private async Task HandleReceivedAsync(UdpClient socket, UdpReceiveResult received, CancellationToken ct)
    {
        var endpoint = received.RemoteEndPoint.ToString();
        var player = _game.GetOrAddPlayer(endpoint);
        var packet = _classifier.Decode(received.Buffer, enableNativeBinary: true);
        var command = _commandDecoder.Decode(packet);
        var stateBefore = player.State;
        Console.WriteLine($"{DateTimeOffset.Now:HH:mm:ss.fff} <= {endpoint} {packet.Explanation} hex={packet.HexPrefix()} ascii=\"{packet.AsciiPreview(64)}\"");

        if (stateBefore == PlayerJoinState.SourceHandoff && IsPostHandoffSourceTraffic(packet))
        {
            await HandleSourceTrafficAsync(socket, received, endpoint, player, packet, command, ct);
            return;
        }

        var responses = _profile.Handle(_game, player, packet);
        RecordPacketEvent("receive", endpoint, packet, command, stateBefore, player.State);
        if (stateBefore != PlayerJoinState.SourceHandoff && player.State == PlayerJoinState.SourceHandoff)
        {
            RecordPacketEvent("source-handoff", endpoint, packet, command, stateBefore, player.State);
            Console.WriteLine($"{DateTimeOffset.Now:HH:mm:ss.fff} ** {endpoint} SOURCE_HANDOFF profile={_profile.Name} via={packet.Kind}");
        }

        if (player.State == PlayerJoinState.SourceHandoff && packet.Kind == PlasmaCommandKind.SourceProbe)
        {
            await HandleSourceTrafficAsync(socket, received, endpoint, player, packet, command, ct);
            return;
        }

        if (stateBefore != PlayerJoinState.SourceHandoff
            && player.State == PlayerJoinState.SourceHandoff
            && packet.Kind is PlasmaCommandKind.Unknown or PlasmaCommandKind.TextCommand)
        {
            await HandleSourceTrafficAsync(socket, received, endpoint, player, packet, command, ct);
            return;
        }

        foreach (var response in responses)
        {
            await socket.SendAsync(response.Payload, response.Payload.Length, received.RemoteEndPoint);
            Console.WriteLine($"{DateTimeOffset.Now:HH:mm:ss.fff} => {endpoint} {response.Kind} {response.Explanation} len={response.Payload.Length}");
            var responsePacket = _classifier.Decode(response.Payload, enableNativeBinary: true);
            var responseCommand = _commandDecoder.Decode(responsePacket);
            RecordPacketEvent("send", endpoint, responsePacket, responseCommand, player.State, player.State, response.Explanation);
        }
    }

    private async Task HandleSourceTrafficAsync(
        UdpClient socket,
        UdpReceiveResult received,
        string endpoint,
        PlayerSession player,
        PlasmaPacket packet,
        GameManagerCommand command,
        CancellationToken ct)
    {
        var clientSourceObservation = player.SourceGameplay.Observe(Ps3SourceGameplayDirection.ClientToServer, packet.Payload);
        RecordPacketEvent("source-traffic", endpoint, packet, command, player.State, player.State, sourceObservation: clientSourceObservation);
        Console.WriteLine($"{DateTimeOffset.Now:HH:mm:ss.fff} ~~ {endpoint} SOURCE_TRAFFIC {packet.Explanation} len={packet.Payload.Length}");
        if (_sourceProxy.IsEnabled)
        {
            var forwardResult = await _sourceProxy.ForwardAsync(
                endpoint,
                received.RemoteEndPoint,
                packet.Payload,
                async (datagram, callbackCt) =>
                {
                    var backendObservation = player.SourceGameplay.Observe(Ps3SourceGameplayDirection.ServerToClient, datagram.Payload);
                    await socket.SendAsync(datagram.Payload, datagram.Payload.Length, datagram.ClientRemoteEndpoint);
                    RecordRawEvent(
                        "source-proxy-send",
                        datagram.ClientEndpoint,
                        "SourceBackendDatagram",
                        player.State,
                        player.State,
                        datagram.Payload.Length,
                        $"proxied Source backend datagram from {_sourceProxy.BackendEndpoint}",
                        Convert.ToHexString(datagram.Payload.AsSpan(0, Math.Min(8, datagram.Payload.Length))).ToLowerInvariant(),
                        datagram.Payload,
                        backendObservation);
                    Console.WriteLine($"{DateTimeOffset.Now:HH:mm:ss.fff} ~~> {datagram.ClientEndpoint} proxied Source backend datagram len={datagram.Payload.Length}");
                },
                ct);
            if (forwardResult.Forwarded)
            {
                RecordPacketEvent(
                    "source-proxy-forward",
                    endpoint,
                    packet,
                    command,
                    player.State,
                    player.State,
                    $"proxied client datagram from PS3-facing GameManager flow to Source backend {_sourceProxy.BackendEndpoint} via {_sourceProxy.ProtocolName}: {forwardResult.Explanation}",
                    clientSourceObservation);
                return;
            }

            if (forwardResult.Dropped)
            {
                RecordPacketEvent(
                    "source-proxy-drop",
                    endpoint,
                    packet,
                    command,
                    player.State,
                    player.State,
                    $"did not forward client datagram to Source backend {_sourceProxy.BackendEndpoint} via {_sourceProxy.ProtocolName}: {forwardResult.Explanation}",
                    clientSourceObservation);
                return;
            }
        }

        if (!SourceQueryResponseBuilder.TryBuildInfoResponse(_game, packet.Payload, out var response))
        {
            return;
        }

        await socket.SendAsync(response.Payload, response.Payload.Length, received.RemoteEndPoint);
        RecordRawEvent("source-send", endpoint, response.Kind.ToString(), player.State, player.State, response.Payload.Length, response.Explanation, Convert.ToHexString(response.Payload.AsSpan(0, Math.Min(8, response.Payload.Length))).ToLowerInvariant(), response.Payload);
        Console.WriteLine($"{DateTimeOffset.Now:HH:mm:ss.fff} ~~> {endpoint} {response.Explanation} len={response.Payload.Length}");
    }

    private static bool IsPostHandoffSourceTraffic(PlasmaPacket packet)
    {
        return packet.Kind is PlasmaCommandKind.SourceProbe
            or PlasmaCommandKind.Unknown
            or PlasmaCommandKind.OpaqueControl
            or PlasmaCommandKind.TextCommand;
    }

    private void RecordPacketEvent(
        string eventName,
        string endpoint,
        PlasmaPacket packet,
        GameManagerCommand command,
        PlayerJoinState stateBefore,
        PlayerJoinState stateAfter,
        string? explanationOverride = null,
        Ps3SourceGameplayObservation? sourceObservation = null)
    {
        var sourceTransport = BuildSourceEventData(eventName, packet.Payload, sourceObservation);
        _eventSink?.Record(new GameManagerServerEvent(
            DateTimeOffset.UtcNow,
            _profile.Name,
            eventName,
            endpoint,
            packet.Kind.ToString(),
            stateBefore.ToString(),
            stateAfter.ToString(),
            packet.Payload.Length,
            explanationOverride ?? packet.Explanation,
            packet.HexPrefix(),
            command.Name,
            command.TransactionId,
            command.LocalId,
            command.GameId,
            command.PlayerId,
            command.Fields,
            sourceTransport.Sequence,
            sourceTransport.BodyLength,
            sourceTransport.SequenceDelta,
            sourceTransport.Shape,
            sourceTransport.NativeFrameKind,
            sourceTransport.FitsInlineQueue,
            sourceTransport.FitsNativeQueue,
            sourceTransport.FragmentHeaderHex,
            sourceTransport.DirectionPacketCount,
            sourceTransport.SequenceDecrease,
            sourceTransport.BodySignature));
    }

    private void RecordRawEvent(
        string eventName,
        string endpoint,
        string kind,
        PlayerJoinState stateBefore,
        PlayerJoinState stateAfter,
        int payloadLength,
        string explanation,
        string hexPrefix,
        ReadOnlyMemory<byte> payload = default,
        Ps3SourceGameplayObservation? sourceObservation = null)
    {
        var sourceTransport = BuildSourceEventData(eventName, payload, sourceObservation);
        _eventSink?.Record(new GameManagerServerEvent(
            DateTimeOffset.UtcNow,
            _profile.Name,
            eventName,
            endpoint,
            kind,
            stateBefore.ToString(),
            stateAfter.ToString(),
            payloadLength,
            explanation,
            hexPrefix,
            SourceSequence: sourceTransport.Sequence,
            SourceBodyLength: sourceTransport.BodyLength,
            SourceSequenceDelta: sourceTransport.SequenceDelta,
            SourcePacketShape: sourceTransport.Shape,
            SourceNativeFrameKind: sourceTransport.NativeFrameKind,
            SourceFitsInlineQueue: sourceTransport.FitsInlineQueue,
            SourceFitsNativeQueue: sourceTransport.FitsNativeQueue,
            SourceFragmentHeaderHex: sourceTransport.FragmentHeaderHex,
            SourceDirectionPacketCount: sourceTransport.DirectionPacketCount,
            SourceSequenceDecrease: sourceTransport.SequenceDecrease,
            SourceBodySignature: sourceTransport.BodySignature));
    }

    private static SourceEventData BuildSourceEventData(
        string eventName,
        ReadOnlyMemory<byte> payload,
        Ps3SourceGameplayObservation? observation)
    {
        if (observation is not null)
        {
            Ps3SourceNativeFrameInfo? nativeFrame = null;
            if (Ps3SourceTransportPacket.TryDecode(payload.Span, out var packet))
            {
                nativeFrame = packet.ClassifyNativeFrame();
            }

            return new SourceEventData(
                observation.Sequence,
                observation.BodyLength == 0 ? null : observation.BodyLength,
                observation.SequenceDeltaFromPreviousSameDirection,
                observation.Shape.ToString(),
                observation.NativeFrameKind.ToString(),
                nativeFrame?.FitsInlineQueue,
                nativeFrame?.FitsNativeQueue,
                nativeFrame?.FragmentHeaderHex is { Length: > 0 } ? nativeFrame.FragmentHeaderHex : null,
                observation.DirectionPacketCount,
                observation.SequenceDecrease,
                SourceBodySignature(eventName, payload));
        }

        var fallback = DecodeSourceTransport(eventName, payload);
        return new SourceEventData(
            fallback.Sequence,
            fallback.BodyLength,
            null,
            null,
            fallback.NativeFrameKind,
            fallback.FitsInlineQueue,
            fallback.FitsNativeQueue,
            fallback.FragmentHeaderHex,
            null,
            null,
            SourceBodySignature(eventName, payload));
    }

    private static (int? Sequence, int? BodyLength, string? NativeFrameKind, bool? FitsInlineQueue, bool? FitsNativeQueue, string? FragmentHeaderHex) DecodeSourceTransport(string eventName, ReadOnlyMemory<byte> payload)
    {
        if (!eventName.StartsWith("source-", StringComparison.Ordinal)
            || IsClassicSourceConnectionless(payload.Span)
            || !Ps3SourceTransportPacket.TryDecode(payload.Span, out var packet))
        {
            return (null, null, null, null, null, null);
        }

        var nativeFrame = packet.ClassifyNativeFrame();
        return (
            packet.CandidateSequence,
            packet.Body.Length,
            nativeFrame.Kind.ToString(),
            nativeFrame.FitsInlineQueue,
            nativeFrame.FitsNativeQueue,
            nativeFrame.FragmentHeaderHex is { Length: > 0 } ? nativeFrame.FragmentHeaderHex : null);
    }

    private static string? SourceBodySignature(string eventName, ReadOnlyMemory<byte> payload)
    {
        if (!eventName.StartsWith("source-", StringComparison.Ordinal)
            || payload.IsEmpty
            || IsClassicSourceConnectionless(payload.Span)
            || !Ps3SourceTransportPacket.TryDecode(payload.Span, out _))
        {
            return null;
        }

        return Ps3SourceGameplaySignatures.BodyRunSignature([payload.ToArray()]);
    }

    private sealed record SourceEventData(
        int? Sequence,
        int? BodyLength,
        int? SequenceDelta,
        string? Shape,
        string? NativeFrameKind,
        bool? FitsInlineQueue,
        bool? FitsNativeQueue,
        string? FragmentHeaderHex,
        int? DirectionPacketCount,
        bool? SequenceDecrease,
        string? BodySignature);

    private static bool IsClassicSourceConnectionless(ReadOnlySpan<byte> payload)
    {
        return SourceBackendPayloadAdapter.IsClassicSourceConnectionless(payload);
    }

    private void RecordSourceProxyError(string endpoint, Exception exception)
    {
        _eventSink?.Record(new GameManagerServerEvent(
            DateTimeOffset.UtcNow,
            _profile.Name,
            "source-proxy-error",
            endpoint,
            "SourceBackend",
            PlayerJoinState.SourceHandoff.ToString(),
            PlayerJoinState.SourceHandoff.ToString(),
            0,
            exception.Message,
            ""));
    }
}
