## Verdict

Confirmed CWE-125 (Out-of-bounds Read) at line 17. The `memcpy` operation reads `payloadLength` bytes from the frame buffer without validating that the buffer contains at least that many bytes. Since `payloadLength` is sourced from an untrusted frame header (as noted in comments), an attacker can supply a length exceeding the buffer size, causing an out-of-bounds read.

## Source

The vulnerability originates at the function's `payloadLength` parameter, which is read from a frame header and passed directly to `memcpy` without validation:

```cpp
bool extractPayload(std::vector<uint8_t>& frameBuffer, size_t payloadLength, uint8_t* destination) {
    std::memcpy(destination, frameBuffer.data(), payloadLength);  // Line 17 - unsafe
    lastPayloadSize_ = payloadLength;
    return true;
}
```

The sink is the `memcpy` call at line 17. The data flow: untrusted `payloadLength` (from frame header) → `memcpy` with no bounds check against `frameBuffer.size()`.

## Fix

Add a bounds check immediately before the `memcpy`, validating that the requested payload length does not exceed the actual buffer size:

```cpp
bool extractPayload(std::vector<uint8_t>& frameBuffer, size_t payloadLength, uint8_t* destination) {
    // Validate that payloadLength does not exceed the actual frame buffer size
    if (payloadLength > frameBuffer.size()) {
        return false;
    }
    
    std::memcpy(destination, frameBuffer.data(), payloadLength);
    lastPayloadSize_ = payloadLength;
    return true;
}
```

## Explanation

The fix adds an explicit bounds check that compares the requested `payloadLength` against the vector's actual `.size()` before performing the read. If the requested length exceeds the buffer's capacity, the function returns `false` to signal failure rather than proceeding with an out-of-bounds read. This aligns with C++ CWE-125 guidance: validate against the container's current `.size()`, not a separately tracked value, and add the bounds check immediately before the read in the same function that performs it. The check is overflow-safe because `size_t` comparison handles the magnitude directly.

## Behaviour changes

- **Return value change on oversized payload**: When `payloadLength > frameBuffer.size()`, the function now returns `false` instead of proceeding with undefined behaviour. Callers must check the return value to detect this error condition.
- **Error handling**: Callers relying on this function must now handle the `false` return value. Without this check, an oversized `payloadLength` would silently read past the buffer's end; with the check, the function explicitly fails and allows the caller to handle the error (log, retry, or abort).
- **No change to success path**: When `payloadLength <= frameBuffer.size()`, the function behaves identically to the original—it copies the payload and returns `true`.
