## Verdict

exploitable

## Source

`payloadLength`, the second parameter of `FrameProcessor::extractPayload`. Per the class-level comment, it is read from a frame header field earlier in the pipeline and passed down separately from `frameBuffer`, so nothing keeps the two in agreement.

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
        // Reject a claimed payload length that exceeds what the frame
        // actually holds before it ever reaches memcpy.
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

`memcpy(destination, frameBuffer.data(), payloadLength)` reads `payloadLength` bytes starting at `frameBuffer.data()` no matter how large `frameBuffer` actually is, so a header-declared length that exceeds the vector's real size reads past the end of its heap allocation. The fix adds an explicit bounds check - `payloadLength > frameBuffer.size()` - immediately before the read, in the same function that performs it, and fails the call by returning `false` rather than proceeding with a copy that would run off the end of `frameBuffer`. This is the single comparison the case calls for: there is no separate `offset` parameter here, so the two-step offset-then-length check from the guidance collapses to this one length-against-`size()` test, and `frameBuffer.size()` (not a separately tracked variable) is used so the check stays correct across any resize. The destination buffer's capacity is explicitly documented as the caller's responsibility and is not something this function can validate, so that side of the contract is left as-is.

## Behaviour changes

- `extractPayload` now returns `false`, and performs no copy and no update to `lastPayloadSize_`, when `payloadLength` exceeds `frameBuffer.size()`. Previously it always returned `true` (after already invoking undefined behaviour on an oversized length). This is required to fail safely instead of reading out of bounds; any caller must treat a `false` return as "no payload extracted" rather than assuming success. No other input, return value, or side effect changed - `verification`: no C++ compiler was reachable in this environment, so the change was checked by hand: it introduces no new symbols (`size()` is the standard `std::vector` member already usable via `frameBuffer`, and `false` is already returned by the same function elsewhere in its signature), the added `if` block is syntactically self-contained, and it precedes the existing `memcpy` call without altering any of that call's arguments.
