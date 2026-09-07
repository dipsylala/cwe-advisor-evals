## Verdict

Stack-based buffer overflow confirmed. The `buildFrame` function copies `dataLen` bytes into a fixed 32-byte array without validating that `dataLen` does not exceed the buffer capacity.

## Source

Line 16 in `buildFrame()` performs an unbounded copy: `frame.payload[i] = data[i]` where `i` ranges from `0` to `dataLen - 1`. The loop does not check whether `dataLen` exceeds the 32-byte capacity of `frame.payload`, allowing writes beyond the array bounds when `dataLen > 32`.

## Fix

Add bounds checking to the loop condition to prevent overflow:

```cpp
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

struct Frame {
    std::array<std::uint8_t, 32> payload;
    std::size_t length;
};

Frame buildFrame(const std::uint8_t *data, std::size_t dataLen) {
    Frame frame{};
    frame.length = dataLen;

    const std::size_t maxPayload = frame.payload.size();
    const std::size_t copyLen = std::min(dataLen, maxPayload);

    for (std::size_t i = 0; i < copyLen; i++) {
        frame.payload[i] = data[i];
    }

    return frame;
}
```

Alternatively, use `std::copy` with bounds:

```cpp
const std::size_t maxPayload = frame.payload.size();
const std::size_t copyLen = std::min(dataLen, maxPayload);
std::copy(data, data + copyLen, frame.payload.begin());
```

## Explanation

The buffer overflow occurs because the loop condition `i < dataLen` does not respect the fixed size of `frame.payload`. When `dataLen` exceeds 32, the assignment at line 16 writes past the end of the array, corrupting the `length` field or other stack memory.

The fix constrains the copy to the actual buffer size using `std::min(dataLen, maxPayload)`, ensuring no write exceeds the 32-byte boundary. This approach truncates oversized input rather than rejecting it, maintaining usability while eliminating the overflow. If the full payload must be accepted, the caller should increase the array size or use dynamic allocation.
