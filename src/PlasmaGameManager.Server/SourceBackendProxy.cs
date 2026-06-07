using System.Net;
using System.Net.Sockets;

namespace PlasmaGameManager.Server;

public sealed class SourceBackendProxy : IAsyncDisposable
{
    private readonly SourceBackendOptions _options;
    private readonly Action<string, Exception>? _errorSink;
    private readonly Dictionary<string, SourceBackendSession> _sessions = new(StringComparer.Ordinal);
    private readonly object _lock = new();

    public SourceBackendProxy(SourceBackendOptions options, Action<string, Exception>? errorSink = null)
    {
        _options = options;
        _errorSink = errorSink;
    }

    public bool IsEnabled => _options.IsEnabled;

    public string BackendEndpoint => _options.Endpoint;

    public string ProtocolName => _options.ProtocolName;

    public async Task<SourceBackendForwardResult> ForwardAsync(
        string clientEndpoint,
        IPEndPoint clientRemoteEndpoint,
        ReadOnlyMemory<byte> payload,
        Func<SourceBackendDatagram, CancellationToken, Task> backendDatagramHandler,
        CancellationToken ct)
    {
        if (!IsEnabled)
        {
            return SourceBackendForwardResult.Disabled;
        }

        var decision = SourceBackendPayloadAdapter.PrepareClientToBackend(_options.Protocol, payload);
        if (!decision.ShouldForward)
        {
            return new SourceBackendForwardResult(false, true, decision.Explanation);
        }

        var session = await GetOrCreateBackendSessionAsync(clientEndpoint, clientRemoteEndpoint, backendDatagramHandler, ct);
        await session.Backend.SendAsync(decision.Payload, ct);
        return new SourceBackendForwardResult(true, false, decision.Explanation);
    }

    public async ValueTask DisposeAsync()
    {
        List<SourceBackendSession> sessions;
        lock (_lock)
        {
            sessions = _sessions.Values.ToList();
            _sessions.Clear();
        }

        foreach (var session in sessions)
        {
            await session.DisposeAsync();
        }
    }

    private async Task<SourceBackendSession> GetOrCreateBackendSessionAsync(
        string clientEndpoint,
        IPEndPoint clientRemoteEndpoint,
        Func<SourceBackendDatagram, CancellationToken, Task> backendDatagramHandler,
        CancellationToken ct)
    {
        lock (_lock)
        {
            if (_sessions.TryGetValue(clientEndpoint, out var existing))
            {
                existing.UpdateClientEndPoint(clientRemoteEndpoint);
                return existing;
            }
        }

        var addresses = await Dns.GetHostAddressesAsync(_options.Host, ct);
        var address = addresses.FirstOrDefault(static candidate => candidate.AddressFamily == AddressFamily.InterNetwork)
            ?? addresses.FirstOrDefault()
            ?? throw new InvalidOperationException($"Could not resolve Source backend host '{_options.Host}'.");
        var backendEndpoint = new IPEndPoint(address, _options.Port);
        var client = new UdpClient(new IPEndPoint(address.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0));
        client.Connect(backendEndpoint);
        var session = new SourceBackendSession(clientEndpoint, clientRemoteEndpoint, client, backendDatagramHandler, _errorSink);

        lock (_lock)
        {
            if (_sessions.TryGetValue(clientEndpoint, out var existing))
            {
                session.DisposeAsync().AsTask().GetAwaiter().GetResult();
                existing.UpdateClientEndPoint(clientRemoteEndpoint);
                return existing;
            }

            _sessions.Add(clientEndpoint, session);
            session.StartReceiveLoop();
            return session;
        }
    }
}

public sealed record SourceBackendDatagram(
    string ClientEndpoint,
    IPEndPoint ClientRemoteEndpoint,
    byte[] Payload);

internal sealed class SourceBackendSession : IAsyncDisposable
{
    private readonly string _clientEndpoint;
    private readonly Func<SourceBackendDatagram, CancellationToken, Task> _backendDatagramHandler;
    private readonly Action<string, Exception>? _errorSink;
    private readonly CancellationTokenSource _stop = new();
    private readonly object _lock = new();
    private Task? _receiveTask;
    private IPEndPoint _clientRemoteEndpoint;

    public SourceBackendSession(
        string clientEndpoint,
        IPEndPoint clientRemoteEndpoint,
        UdpClient backend,
        Func<SourceBackendDatagram, CancellationToken, Task> backendDatagramHandler,
        Action<string, Exception>? errorSink)
    {
        _clientEndpoint = clientEndpoint;
        _clientRemoteEndpoint = clientRemoteEndpoint;
        Backend = backend;
        _backendDatagramHandler = backendDatagramHandler;
        _errorSink = errorSink;
    }

    public UdpClient Backend { get; }

    public void UpdateClientEndPoint(IPEndPoint clientRemoteEndpoint)
    {
        lock (_lock)
        {
            _clientRemoteEndpoint = clientRemoteEndpoint;
        }
    }

    public void StartReceiveLoop()
    {
        _receiveTask ??= Task.Run(ReceiveLoopAsync);
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        Backend.Dispose();
        if (_receiveTask is not null)
        {
            try
            {
                await _receiveTask.WaitAsync(TimeSpan.FromSeconds(2));
            }
            catch (OperationCanceledException)
            {
            }
            catch (TimeoutException)
            {
            }
        }

        _stop.Dispose();
    }

    private async Task ReceiveLoopAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var received = await Backend.ReceiveAsync(_stop.Token);
                IPEndPoint clientRemoteEndpoint;
                lock (_lock)
                {
                    clientRemoteEndpoint = _clientRemoteEndpoint;
                }

                await _backendDatagramHandler(
                    new SourceBackendDatagram(_clientEndpoint, clientRemoteEndpoint, received.Buffer),
                    _stop.Token);
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException) when (_stop.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _errorSink?.Invoke(_clientEndpoint, ex);
        }
    }
}
