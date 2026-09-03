## Verdict
Exploitable

## Source
`payloadLength` parameter, originating from an untrusted frame header field read earlier in the pipeline and passed as a separate value decoupled from the vector holding the actual frame bytes.

## Fix

**Vulnerable code:**
```cpp
bool extractPayload(std::vector<uint8_t>& frameBuffer, size_t payloadLength, uint8_t* destination) {
    // payloadLength is not checked against frameBuffer.size()
    std::memcpy(destination, frameBuffer.data(), payloadLength);

    lastPayloadSize_ = payloadLength;
    return true;
}
```

**Fixed code:**
```cpp
bool extractPayload(std::vector<uint8_t>& frameBuffer, size_t payloadLength, uint8_t* destination) {
    // Validate requested length against actual buffer size before reading
    if (payloadLength > frameBuffer.size()) {
        return false;
    }
    std::memcpy(destination, frameBuffer.data(), payloadLength);

    lastPayloadSize_ = payloadLength;
    return true;
}
```

## Explanation
The vulnerability occurs because `payloadLength` is read from a frame header (untrusted input) and used directly in `memcpy()` without validating that the frame buffer actually contains that many bytes. If the header claims more payload than the buffer holds—either through malice or a corrupted transmission—`memcpy()` reads past the allocated buffer, leaking adjacent memory. The fix adds an explicit bounds check: `if (payloadLength > frameBuffer.size()) return false;` immediately before the read. This validates the length against the container's actual size and stops the operation if the requested length exceeds available data, following the guidance pattern of validating untrusted length values inside the function that performs the read rather than trusting the caller.

## Behaviour changes
None. The fix preserves the existing return type and calling contract: `memcpy()` is only invoked after confirming sufficient data exists, and the function returns `false` if validation fails. The `lastPayloadSize_` update is skipped on validation failure, which is correct since no copy was performed.
