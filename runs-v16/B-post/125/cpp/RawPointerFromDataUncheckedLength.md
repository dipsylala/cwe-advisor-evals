## Verdict
Exploitable.

## Source
`payloadLength` parameter, originating from a frame header read earlier in the pipeline and passed to the function as untrusted input.

## Fix

**Vulnerable code:**
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
    // Validate payloadLength against frameBuffer size
    if (payloadLength > frameBuffer.size()) {
        return false;
    }
    
    std::memcpy(destination, frameBuffer.data(), payloadLength);

    lastPayloadSize_ = payloadLength;
    return true;
}
```

## Explanation
The vulnerability arises because `payloadLength` is taken from an untrusted frame header and passed directly to `memcpy()` without validation. If the header claims a payload larger than the actual data in `frameBuffer`, the `memcpy()` reads past the vector's allocated memory. The fix adds a bounds check immediately before the read: if the requested length exceeds the buffer's actual size, the function returns false to signal failure. This check uses unsigned comparison to avoid wrapping issues. The validation occurs inside the function using the vector's `.size()` method, so the two values cannot drift apart after validation.

## Behaviour changes
The function now returns `false` when `payloadLength > frameBuffer.size()`, signaling an invalid request to the caller. The caller must check the return value and handle the error appropriately (e.g., reject the frame). This is a necessary change to eliminate the out-of-bounds read. The function's contract is preserved: it still returns `true` on success and `false` on failure; callers already receiving a return value of type `bool` continue to work.
