## Verdict

The finding is valid. The code performs a `memcpy()` from `frameBuffer.data()` using a `payloadLength` parameter that originates from a frame header and is not validated against the actual buffer size before the read. An attacker-controlled header value larger than the buffer's actual content will cause an out-of-bounds read.

## Source

`payloadLength` is read from a frame header field earlier in the pipeline and passed to `extractPayload()` as an untrusted parameter. No validation is performed.

## Fix

Add an explicit bounds check inside the function, before the `memcpy()` call, to ensure `payloadLength` does not exceed the buffer's actual size. The check must test the length first to avoid unsigned integer underflow in the subsequent comparison.

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
        // Validate that payloadLength does not exceed the actual buffer size
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

The fix adds an explicit bounds check immediately before the `memcpy()` call. The check `payloadLength > frameBuffer.size()` validates that the requested length does not exceed the buffer's actual size, using unsigned comparison in the safe direction (subtracting smaller from larger avoids underflow). If the length is invalid, the function returns `false` to signal an error to the caller, and execution does not proceed to the unsafe `memcpy()`. This matches the function's existing return-code error pattern and aligns with the CWE-125 remediation guidance: bind and validate the untrusted parameter inside the function rather than trusting the caller.

## Behaviour changes

The function now returns `false` instead of `true` when `payloadLength` exceeds the actual buffer size. Callers must check this return value; existing code that ignores the result will now silently skip the copy and leave `destination` uninitialized. This is safer than the original behavior (which would perform an out-of-bounds read) but requires the caller to handle the error case. The function's contract already documents that sizing `destination` is the caller's responsibility; validating `payloadLength` against the source buffer's size is an additional defensive check inside the function itself, as the guidance prescribes.
