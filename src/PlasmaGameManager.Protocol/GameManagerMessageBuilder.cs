using System.Text;

namespace PlasmaGameManager.Protocol;

public sealed class GameManagerMessageBuilder
{
    private readonly string _scope;
    private readonly string _name;
    private readonly string? _flags;
    private readonly Dictionary<string, string> _fields = new(StringComparer.Ordinal);

    private GameManagerMessageBuilder(string scope, string name, string? flags)
    {
        _scope = scope;
        _name = name;
        _flags = flags;
    }

    public static GameManagerMessageBuilder Notify(string name, string? flags = null) => new("N", name, flags);

    public static GameManagerMessageBuilder Request(string name, string? flags = null) => new("R", name, flags);

    public static GameManagerMessageBuilder Addressed(string name, string? flags = null) => new("A", name, flags);

    public GameManagerMessageBuilder Field(string key, string value)
    {
        _fields[key] = value;
        return this;
    }

    public GameManagerMessageBuilder Field(string key, int value) => Field(key, value.ToString());

    public GameManagerMessageBuilder Field(string key, long value) => Field(key, value.ToString());

    public string BuildString()
    {
        var header = _flags is null ? $"{_scope} {_name}" : $"{_scope} {_name} {_flags}";
        if (_fields.Count == 0)
        {
            return header;
        }

        var fields = string.Join(",", _fields.Select(static kv => $"{kv.Key}={FormatValue(kv.Value)}"));
        return $"{header} ({fields})";
    }

    public byte[] BuildBytes() => Encoding.ASCII.GetBytes(BuildString());

    private static string FormatValue(string value)
    {
        return value.Any(static c => char.IsWhiteSpace(c) || c is ',' or ')' or '(')
            ? $"\"{value.Replace("\"", "\\\"", StringComparison.Ordinal)}\""
            : value;
    }
}
