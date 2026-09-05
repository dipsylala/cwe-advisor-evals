## Verdict

Exploitable out-of-bounds read confirmed. The `memcpy()` at line 17 copies `payloadLength` bytes from `frameBuffer` without validating that `payloadLength` does not exceed the buffer's actual size. The function comment explicitly states the two values "can disagree if the header lies about how much data follows it," confirming the untrusted source. An attacker can supply a frame header with `payloadLength` larger than the received frame bytes, causing `memcpy()` to read past the buffer's end.

## Source

Line 17: `std::memcpy(destination, frameBuffer.data(), payloadLength);`

- **Untrusted value**: `payloadLength` (size_t parameter)
- **Origin**: Frame header field, read separately from the actual vector and can disagree with it
- **Buffer**: `frameBuffer` (std::vector<uint8_t>&)
- **Unsafe operation**: `memcpy()` with unvalidated length parameter

## Fix

```cpp
bool extractPayload(std::vector<uint8_t>& frameBuffer, size_t payloadLength, uint8_t* destination) {
    // Validate payloadLength against buffer size before reading
    if (payloadLength > frameBuffer.size()) {
        return false;
    }
    
    std::memcpy(destination, frameBuffer.data(), payloadLength);

    lastPayloadSize_ = payloadLength;
    return true;
}
```

## Explanation

The fix adds a bounds check immediately before the `memcpy()` call. It verifies that `payloadLength` does not exceed `frameBuffer.size()` before attempting the copy. The check is placed first and uses the unsigned-safe form `payloadLength > frameBuffer.size()` to avoid arithmetic wrapping when comparing an attacker-supplied length against the container's size. If the check fails, the function returns `false`, signaling to the caller that the frame is malformed, and the dangerous read is prevented. The existing function contract (return type `bool`, success/failure signaling) is preserved and satisfied by this change.

## Behaviour changes

**On valid frames**: No change. When `payloadLength <= frameBuffer.size()`, the condition is false, and the function proceeds exactly as before, copying the payload and returning `true`.

**On oversized payloadLength**: Changed from silent out-of-bounds read to early return. Callers now receive `false` instead of `true` when a frame header claims more data than the buffer contains, allowing them to reject the malformed frame. This is the correct behavior: the frame is untrustworthy and should not be processed further.

**No silent truncation**: The fix does not silently read a smaller amount; it rejects the entire operation. This ensures the caller knows the frame is bad and prevents accidental partial-data processing.
