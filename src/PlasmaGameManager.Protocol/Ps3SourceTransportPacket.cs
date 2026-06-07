namespace PlasmaGameManager.Protocol;

public sealed record Ps3SourceTransportPacket(
    ushort CandidateSequence,
    byte[] Body,
    int PayloadLength)
{
    public const int HeaderBytes = 2;
    public const int NativeFragmentHeaderBytes = 10;
    public const int InlineQueuePayloadCeiling = 0x800;
    public const int InlineQueueAllocationBytes = 0x808;
    public const int NativeQueuePayloadCeiling = 0x17700;
    public const int NativeQueueAllocationCeiling = 0x17701;
    public const int NativeStagingBufferBytes = 0x1000;
    public const int ConnectedShortControlPayloadBytes = 5;

    public static bool TryDecode(ReadOnlySpan<byte> payload, out Ps3SourceTransportPacket packet)
    {
        if (payload.Length < HeaderBytes)
        {
            packet = new Ps3SourceTransportPacket(0, Array.Empty<byte>(), payload.Length);
            return false;
        }

        var sequence = (ushort)((payload[0] << 8) | payload[1]);
        packet = new Ps3SourceTransportPacket(sequence, payload[HeaderBytes..].ToArray(), payload.Length);
        return true;
    }

    public static int SequenceDelta(ushort previous, ushort current)
    {
        return (current - previous + 0x10000) & 0xffff;
    }

    public Ps3SourceNativeFrameInfo ClassifyNativeFrame()
    {
        var kind = Body.Length switch
        {
            0 => Ps3SourceNativeFrameKind.EmptyBody,
            <= ConnectedShortControlPayloadBytes - HeaderBytes => Ps3SourceNativeFrameKind.ConnectedShortControlCandidate,
            _ when LooksLikeNativeFragmentCandidate() => Ps3SourceNativeFrameKind.FragmentedSendCandidate,
            _ when LooksLikeBitPayloadSidecarCandidate() => Ps3SourceNativeFrameKind.DirectWithBitPayloadSidecarCandidate,
            _ => Ps3SourceNativeFrameKind.DirectDatagramCandidate
        };

        return new Ps3SourceNativeFrameInfo(
            kind,
            PayloadLength <= InlineQueuePayloadCeiling,
            PayloadLength <= NativeQueuePayloadCeiling,
            PayloadLength >= 1000 || Body.Length >= 998,
            kind == Ps3SourceNativeFrameKind.FragmentedSendCandidate && Body.Length >= NativeFragmentHeaderBytes
                ? Body[7] >= 0x80
                : null,
            Body.Length >= NativeFragmentHeaderBytes
                ? Convert.ToHexString(Body.AsSpan(0, NativeFragmentHeaderBytes)).ToLowerInvariant()
                : "");
    }

    private bool LooksLikeNativeFragmentCandidate()
    {
        // TF.elf 008bc490 emits a 10-byte per-fragment header, then a payload
        // chunk chosen from the configured send threshold. The original PCAP
        // corpus shows these as near-MTU packets after the two-byte sequence
        // field has been stripped.
        return Body.Length >= NativeFragmentHeaderBytes
            && (PayloadLength >= 1000 || Body.Length >= 998);
    }

    private bool LooksLikeBitPayloadSidecarCandidate()
    {
        // TF.elf 008bc978 appends a two-byte big-endian bit-length sidecar when
        // the optional bit payload is present. We cannot prove the sidecar
        // boundary without the caller's original param_5 length, so keep this
        // deliberately conservative: only tiny direct packets with a plausible
        // bit count are marked as candidates.
        if (Body.Length is < 4 or > 64)
        {
            return false;
        }

        var bitCount = (Body[^2] << 8) | Body[^1];
        var maxBitsBeforeSidecar = Math.Max(0, Body.Length - 2) * 8;
        return bitCount > 0 && bitCount <= maxBitsBeforeSidecar;
    }
}

public enum Ps3SourceNativeFrameKind
{
    EmptyBody,
    ConnectedShortControlCandidate,
    DirectDatagramCandidate,
    DirectWithBitPayloadSidecarCandidate,
    FragmentedSendCandidate
}

public sealed record Ps3SourceNativeFrameInfo(
    Ps3SourceNativeFrameKind Kind,
    bool FitsInlineQueue,
    bool FitsNativeQueue,
    bool NearMtu,
    bool? FragmentWrappedOrCompressedFlag,
    string FragmentHeaderHex);
