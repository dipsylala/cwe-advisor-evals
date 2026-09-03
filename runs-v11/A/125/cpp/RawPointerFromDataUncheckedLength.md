## Verdict

The out-of-bounds read occurs because `payloadLength` (from an untrusted frame header) is used directly in `std::memcpy()` without validating it against the actual size of `frameBuffer`. When `payloadLength` exceeds `frameBuffer.size()`, `memcpy` reads past the end of the vector.

## Source

Line 17: `std::memcpy(destination, frameBuffer.data(), payloadLength);`

The vulnerability is that `payloadLength` comes from a frame header field (documented in the comments as potentially lying), but there is no bounds check before the copy operation. The vector's actual size may be smaller than the claimed payload length.

## Fix

Add a length validation check before the `memcpy`:

```cpp
bool extractPayload(std::vector<uint8_t>& frameBuffer, size_t payloadLength, uint8_t* destination) {
    // Validate that claimed payload length does not exceed actual buffer size
    if (payloadLength > frameBuffer.size()) {
        return false;
    }
    
    std::memcpy(destination, frameBuffer.data(), payloadLength);
    lastPayloadSize_ = payloadLength;
    return true;
}
```

## Explanation

The fix validates that `payloadLength` does not exceed the actual size of `frameBuffer` before performing the read. This prevents `memcpy` from accessing memory beyond the vector's bounds. The check rejects frames where the header claims more data than is actually present in the buffer, returning `false` to signal an invalid frame to the caller. This aligns with the documented contract that `payloadLength` is untrusted input from the frame header and may disagree with the actual vector contents.
