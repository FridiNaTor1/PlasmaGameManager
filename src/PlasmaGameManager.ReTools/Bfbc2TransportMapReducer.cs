using System.Text.Json;

namespace PlasmaGameManager.ReTools;

public static class Bfbc2TransportMapReducer
{
    public static async Task ReduceAsync(
        string sendPointerEvidencePath,
        string lowLevelSendDecompilesPath,
        string packetParserDecompilesPath,
        string outputPath)
    {
        using var sendPointerDoc = JsonDocument.Parse(File.ReadAllText(sendPointerEvidencePath));
        using var lowLevelSendDoc = JsonDocument.Parse(File.ReadAllText(lowLevelSendDecompilesPath));
        using var packetParserDoc = JsonDocument.Parse(File.ReadAllText(packetParserDecompilesPath));

        var vtable = ExtractSocketVtable(sendPointerDoc.RootElement);
        var lowLevelFunctions = IndexBodies(lowLevelSendDoc.RootElement);
        var parserFunctions = IndexBodies(packetParserDoc.RootElement);

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
        {
            status = "native-bfbc2-plasma-transport-mapped",
            note = "This maps the BFBC2 Plasma UDP transport frame and socket dispatch layer. It is the layer below GameManager command payload construction/handling.",
            socketVtable = vtable,
            sendPath = new
            {
                Wrapper = new
                {
                    Entry = "009fa5c0",
                    Name = "dice::online::plasma::ServerSocket::send",
                    Semantics = "validates socket state and forwards already-built payload bytes to ServerSocketManager::addOutgoingPacket",
                    Assertions = new[] { "!m_isBroadcasting", "m_peerAddressIsValid", "socketManager" },
                    Downstream = "009ef210"
                },
                AddOutgoingPacket = new
                {
                    Entry = "009ef210",
                    Name = "dice::online::plasma::ServerSocketManager::addOutgoingPacket",
                    Semantics = "looks up the peer by address, limits payload size, copies payload, appends/uses padding, computes MD5 over the body, writes an 8-byte header, then sends through the peer transport vtable",
                    HeaderBytes = 8,
                    MaxPayloadBytes = 0x4a7,
                    MaxFrameBytes = 0x4af,
                    HeaderFields = new[]
                    {
                        "uint32 md5_word_big_endian",
                        "uint16 payload_length_big_endian",
                        "uint16 pad_length_big_endian"
                    },
                    Evidence = EvidenceFlags(lowLevelFunctions.GetValueOrDefault("009ef210", ""))
                }
            },
            receivePath = new
            {
                RawFrameIngress = new
                {
                    Entry = "00a025c0",
                    Semantics = "validates raw UDP frame length, splits the 8-byte header into MD5/payload/pad lengths, recomputes MD5 over body bytes, copies the payload body into an internal packet queue when valid",
                    HeaderBytes = 8,
                    MaxFrameBodyBytes = 0x4a7,
                    Evidence = EvidenceFlags(parserFunctions.GetValueOrDefault("00a025c0", ""))
                },
                DequeuePayload = new
                {
                    Entry = "00a02710",
                    Semantics = "pops validated queued packets under the socket manager lock, runs the peer-specific unpad/decode callback, copies decoded payload bytes to caller buffer, and returns decoded payload length",
                    Evidence = EvidenceFlags(parserFunctions.GetValueOrDefault("00a02710", ""))
                },
                DispatchPayload = new
                {
                    Entry = "00a086a0",
                    Semantics = "calls the dequeue payload helper, then walks listener callbacks at ServerSocket offset 0x58 until one consumes the packet",
                    ListenerListOffset = "0x58",
                    Evidence = EvidenceFlags(parserFunctions.GetValueOrDefault("00a086a0", ""))
                },
                LocalPlayerPacketHelper = new
                {
                    Entry = "00a08630",
                    Semantics = "adjacent player helper; writes a four-byte player/session value into a scratch buffer and feeds the transport parser path when the backing socket object exists",
                    Evidence = EvidenceFlags(parserFunctions.GetValueOrDefault("00a08630", ""))
                }
            },
            implications = new[]
            {
                "GameManager command handlers sit above 00a086a0 listener callbacks, not in the low-level send wrapper.",
                "Server responses must be built as native GameManager payloads first; the BFBC2 transport frame then adds MD5 and length fields.",
                "PCAP payload comparison should strip the 8-byte transport header before semantic GameManager command comparison."
            }
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static object ExtractSocketVtable(JsonElement root)
    {
        var table = root.GetProperty("targets").EnumerateArray()
            .SelectMany(static target => target.GetProperty("pointerTables").EnumerateArray())
            .FirstOrDefault(static table => table.TryGetProperty("base", out var baseElement)
                && baseElement.GetString() == "0177d670");

        if (table.ValueKind == JsonValueKind.Undefined)
        {
            return new
            {
                Status = "missing",
                ExpectedBase = "0177d670"
            };
        }

        var entries = table.GetProperty("entries").EnumerateArray()
            .Select(static entry => new
            {
                Index = entry.GetProperty("index").GetInt32(),
                PointerAddress = entry.GetProperty("pointerAddress").GetString() ?? "",
                FunctionAddress = entry.GetProperty("functionAddress").GetString() ?? "",
                FunctionName = entry.GetProperty("functionName").GetString() ?? "",
                InferredRole = InferSocketRole(entry.GetProperty("functionAddress").GetString() ?? "")
            })
            .ToArray();

        return new
        {
            Base = "0177d670",
            EntryCount = entries.Length,
            Entries = entries
        };
    }

    private static Dictionary<string, string> IndexBodies(JsonElement root)
    {
        return root.GetProperty("functions").EnumerateArray()
            .Where(static function => function.TryGetProperty("entry", out var entry) && entry.GetString() is { Length: > 0 })
            .GroupBy(static function => function.GetProperty("entry").GetString() ?? "", StringComparer.Ordinal)
            .ToDictionary(
                static group => group.Key,
                static group => group.First().TryGetProperty("body", out var body) ? body.GetString() ?? "" : "",
                StringComparer.Ordinal);
    }

    private static string InferSocketRole(string address)
    {
        return address switch
        {
            "009e76b0" => "destructor/free",
            "009fa5c0" => "send",
            "00a086a0" => "receive-dispatch",
            _ => "unknown"
        };
    }

    private static string[] EvidenceFlags(string body)
    {
        var flags = new List<string>();
        AddIf(flags, body.Contains("Md5Buffer", StringComparison.Ordinal), "md5-buffer");
        AddIf(flags, body.Contains("0x4a7", StringComparison.Ordinal), "max-payload-0x4a7");
        AddIf(flags, body.Contains("0x4af", StringComparison.Ordinal), "max-frame-0x4af");
        AddIf(flags, body.Contains("packet->m_size <= uint(size)", StringComparison.Ordinal), "packet-size-check");
        AddIf(flags, body.Contains("lookupPlayerByAddress() failed", StringComparison.Ordinal), "peer-address-lookup");
        AddIf(flags, body.Contains("param_1 + 0x58", StringComparison.Ordinal), "listener-list-0x58");
        return flags.ToArray();
    }

    private static void AddIf(List<string> flags, bool condition, string value)
    {
        if (condition)
        {
            flags.Add(value);
        }
    }
}
