## Verdict
Real vulnerability confirmed.

## Source
The `extractPayload()` method reads from `frameBuffer` without validating that it contains sufficient bytes. The frame header's `payloadLength` field may be attacker-controlled and can claim more data than the buffer holds. The `memcpy` on line 17 will then read past the end of the vector.

## Fix
Validate the buffer size before reading:

```cpp
bool extractPayload(std::vector<uint8_t>& frameBuffer, size_t payloadLength, uint8_t* destination) {
    if (frameBuffer.size() < payloadLength) {
        return false;
    }
    std::memcpy(destination, frameBuffer.data(), payloadLength);
    lastPayloadSize_ = payloadLength;
    return true;
}
```

## Explanation
The out-of-bounds read occurs because `memcpy` trusts `payloadLength` to describe the actual bytes available in `frameBuffer`. When a received frame header claims `payloadLength` exceeds the vector's actual size—either through malformed input or an attacker—`memcpy` reads past the vector's allocation, leaking adjacent memory contents.

The fix adds a precondition check: if the frame buffer does not contain enough bytes for the claimed payload, reject the frame by returning `false` rather than attempting an unsafe copy. This stops the read at the vector's boundary, preventing out-of-bounds access.
