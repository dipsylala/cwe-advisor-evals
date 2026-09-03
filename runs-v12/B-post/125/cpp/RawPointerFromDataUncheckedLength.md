## Verdict

Exploitable. The function accepts an untrusted `payloadLength` parameter read from a frame header and passes it directly to `std::memcpy()` without validating it against the actual size of `frameBuffer`. If `payloadLength` exceeds `frameBuffer.size()`, the memcpy call reads past the end of the buffer, causing an out-of-bounds read.

## Source

`payloadLength` parameter (line 15), supplied by the caller from untrusted frame header data. The code comment explicitly notes that the header-provided length can disagree with the vector's actual size.

## Fix

**Vulnerable code (line 15-21):**
```cpp
bool extractPayload(std::vector<uint8_t>& frameBuffer, size_t payloadLength, uint8_t* destination) {
    // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
    std::memcpy(destination, frameBuffer.data(), payloadLength);

    lastPayloadSize_ = payloadLength;
    return true;
}
```

**Fixed code:**
```cpp
bool extractPayload(std::vector<uint8_t>& frameBuffer, size_t payloadLength, uint8_t* destination) {
    // Validate payloadLength against actual buffer size before reading
    if (payloadLength > frameBuffer.size()) {
        return false;
    }
    std::memcpy(destination, frameBuffer.data(), payloadLength);

    lastPayloadSize_ = payloadLength;
    return true;
}
```

## Explanation

The fix adds an explicit bounds check immediately before the `memcpy()` call, validating that `payloadLength` does not exceed the actual size of `frameBuffer`. If the check fails, the function returns false to signal to the caller that the copy could not be performed safely. This prevents the memcpy from reading past the end of the buffer. Per the C++ CWE-125 guidance, the bounds check must be performed in the same function as the sink (not delegated to an unrelated caller), and the check is placed immediately before the unsafe read rather than relying on unstated caller preconditions. The check uses unsigned comparison with `buffer.size()` directly, avoiding arithmetic that could overflow.

## Behaviour changes

The function now returns false when `payloadLength` exceeds `frameBuffer.size()`, instead of proceeding with the copy. This is a new control flow branch that did not exist in the original code. Callers must be updated to handle the false return value and take appropriate action (e.g., reject the frame, log an error, or retry). The function's existing return type already permits this outcome, so no API change is required. On successful validation, the function behaves identically to the original: it performs the memcpy and returns true.
