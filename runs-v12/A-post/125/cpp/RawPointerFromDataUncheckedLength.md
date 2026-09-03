## Verdict
The code performs an out-of-bounds read by copying from `frameBuffer` without verifying that the vector contains at least `payloadLength` bytes.

## Source
```cpp
bool extractPayload(std::vector<uint8_t>& frameBuffer, size_t payloadLength, uint8_t* destination) {
    // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
    std::memcpy(destination, frameBuffer.data(), payloadLength);

    lastPayloadSize_ = payloadLength;
    return true;
}
```

The vulnerability occurs at line 17: `frameBuffer` may contain fewer bytes than `payloadLength`, yet the code unconditionally copies `payloadLength` bytes from it.

## Fix
```cpp
bool extractPayload(std::vector<uint8_t>& frameBuffer, size_t payloadLength, uint8_t* destination) {
    // Verify the frame buffer contains enough data before reading
    if (frameBuffer.size() < payloadLength) {
        return false;
    }
    
    std::memcpy(destination, frameBuffer.data(), payloadLength);

    lastPayloadSize_ = payloadLength;
    return true;
}
```

## Explanation
CWE-125 occurs when code reads beyond the bounds of allocated memory. The original code trusts that `frameBuffer` holds at least `payloadLength` bytes, but the comments acknowledge this assumption can be violated: "if the header lies about how much data follows it."

The fix adds a bounds check before `memcpy`. If the frame buffer is smaller than the claimed payload length, the function returns `false` to signal the error to the caller. This prevents reading from uninitialized or unrelated memory. The caller is responsible for handling the failure and should not assume the copy succeeded.
