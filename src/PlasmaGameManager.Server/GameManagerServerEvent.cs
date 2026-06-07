using System.Text.Json;

namespace PlasmaGameManager.Server;

public interface IGameManagerEventSink : IDisposable
{
    void Record(GameManagerServerEvent gameEvent);
}

public sealed record GameManagerServerEvent(
    DateTimeOffset Timestamp,
    string Profile,
    string Event,
    string Endpoint,
    string Kind,
    string StateBefore,
    string StateAfter,
    int PayloadLength,
    string Explanation,
    string HexPrefix,
    string CommandName = "",
    int? TransactionId = null,
    long? LocalId = null,
    long? GameId = null,
    int? PlayerId = null,
    IReadOnlyDictionary<string, string>? Fields = null,
    int? SourceSequence = null,
    int? SourceBodyLength = null,
    int? SourceSequenceDelta = null,
    string? SourcePacketShape = null,
    string? SourceNativeFrameKind = null,
    bool? SourceFitsInlineQueue = null,
    bool? SourceFitsNativeQueue = null,
    string? SourceFragmentHeaderHex = null,
    int? SourceDirectionPacketCount = null,
    bool? SourceSequenceDecrease = null,
    string? SourceBodySignature = null);

public sealed class JsonLineGameManagerEventSink : IGameManagerEventSink
{
    private readonly TextWriter _writer;
    private readonly object _gate = new();

    public JsonLineGameManagerEventSink(TextWriter writer)
    {
        _writer = writer;
    }

    public void Record(GameManagerServerEvent gameEvent)
    {
        var line = JsonSerializer.Serialize(gameEvent);
        lock (_gate)
        {
            _writer.WriteLine(line);
            _writer.Flush();
        }
    }

    public void Dispose()
    {
        _writer.Dispose();
    }
}
