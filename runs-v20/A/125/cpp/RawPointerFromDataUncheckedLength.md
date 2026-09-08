## Verdict

Confirmed. `extractPayload` copies `payloadLength` bytes out of `frameBuffer` via `std::memcpy(destination, frameBuffer.data(), payloadLength)` without ever checking that `frameBuffer` actually holds that many bytes. `payloadLength` comes from a frame header field parsed earlier in the pipeline, while `frameBuffer` holds the frame bytes that were actually received; the comment on the class states these can disagree "if the header lies about how much data follows it." A short or truncated frame (or a maliciously crafted header claiming a larger payload than was sent) makes `payloadLength > frameBuffer.size()`, and `memcpy` will read past the end of the vector's underlying heap allocation, an out-of-bounds read (CWE-125). The over-read bytes are heap memory adjacent to the vector's buffer, which then land in `destination` and are handed to downstream protocol handling - an information disclosure / undefined-behavior risk, and a potential crash if the read crosses an unmapped page.

## Source

`payloadLength`, the `size_t` parameter passed into `FrameProcessor::extractPayload` (line 15). It is attacker-influenced: per the class comment it is "read from a frame header field earlier in the pipeline," i.e. derived from bytes of a received frame, and is passed independently of `frameBuffer`, so nothing enforces that it matches the number of bytes `frameBuffer` actually contains.

## Fix

### File: RawPointerFromDataUncheckedLength.cpp
```cpp
#include <cstdint>
#include <cstring>
#include <vector>

// Extracts the payload segment of a received frame into a caller-owned
// output buffer for downstream protocol handling. `payloadLength` is
// read from a frame header field earlier in the pipeline and is passed
// down separately from the vector that actually holds the frame bytes,
// so the two can disagree if the header lies about how much data
// follows it.
class FrameProcessor {
public:
    // `destination` must point to at least `payloadLength` bytes of
    // caller-owned storage; sizing it is the caller's responsibility.
    bool extractPayload(std::vector<uint8_t>& frameBuffer, size_t payloadLength, uint8_t* destination) {
        // The header-declared payloadLength must not exceed the number of
        // bytes actually received in frameBuffer; otherwise memcpy would
        // read past the end of frameBuffer's storage (CWE-125).
        if (payloadLength > frameBuffer.size()) {
            return false;
        }

        std::memcpy(destination, frameBuffer.data(), payloadLength);

        lastPayloadSize_ = payloadLength;
        return true;
    }

    size_t lastPayloadSize() const { return lastPayloadSize_; }

private:
    size_t lastPayloadSize_ = 0;
};
```

## Explanation

The root cause is a length field that is trusted without being checked against the size of the buffer it is supposed to describe. The fix adds an explicit bounds check - `payloadLength > frameBuffer.size()` - before the `memcpy`, and rejects the call by returning `false` when the header's claimed length would read past the actual data. This preserves the function's existing success/failure contract (it already returns `bool`), so callers that check the return value get a clean failure signal instead of undefined behavior, and no valid, correctly-sized frame is affected since the check only rejects lengths that were never safe to copy. `destination` sizing remains the caller's responsibility per the existing contract comment, since `payloadLength` is still used to size the copy into it once validated; the vulnerability being fixed is strictly the over-read from `frameBuffer`, which is now capped at `frameBuffer.size()`.
