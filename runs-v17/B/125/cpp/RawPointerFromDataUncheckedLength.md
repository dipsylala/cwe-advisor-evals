## Verdict

CONFIRMED: Out-of-bounds read in `memcpy()` call. The `payloadLength` parameter is copied directly from a frame header without validation against the actual size of `frameBuffer`. An attacker controlling the frame header can cause the `memcpy()` to read beyond the vector's allocated memory.

## Source

Line 17 in `RawPointerFromDataUncheckedLength.cpp`:
```
std::memcpy(destination, frameBuffer.data(), payloadLength);
```

The vulnerability is that `payloadLength` is trusted without first checking whether `frameBuffer` actually contains that many bytes. The vector's true size may be smaller than the claimed payload length in the frame header.

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
        // Validate that the claimed payload length does not exceed the buffer's actual size
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

The fix adds an explicit bounds check before the `memcpy()` operation. The check `if (payloadLength > frameBuffer.size())` validates that the requested length does not exceed the vector's actual size. This follows CWE-125's C++ remediation guidance: validate against the container's current `.size()` inside the function rather than trusting the caller's length parameter.

The check is placed before the copy to prevent any read beyond the buffer's boundaries. In unsigned arithmetic, an oversized `payloadLength` would make any subsequent comparison like `offset > buffer.size() - payloadLength` wrap to a huge value and fail to protect. Testing the length first, before arithmetic, prevents this wrapping.

If the header claims more bytes than the vector holds, the function now returns false, signaling to the caller that the frame is malformed. This is the defensive pattern: the function does not assume the frame header is honest but validates the claim against the data actually present.

## Behaviour changes

- If `payloadLength` exceeds `frameBuffer.size()`, the function now returns `false` without reading or copying.
- The function no longer performs an out-of-bounds read when a malformed or adversarial frame header claims a payload length larger than the actual frame data.
- Callers must check the return value; a `false` return indicates the frame should be rejected as malformed.
- Valid frames where `payloadLength <= frameBuffer.size()` behave identically to before: the payload is extracted and the function returns `true`.
