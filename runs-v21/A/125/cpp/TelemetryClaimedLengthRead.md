## Verdict

CONFIRMED. Out-of-bounds read at line 12 when the requested `length` extends past the vector's allocated size.

## Source

The vulnerability occurs when accessing `frame[offset + i]` in the loop at line 12. The function accepts a `length` parameter without validating that `offset + length <= frame.size()`. If a caller requests a window beyond the frame's bounds, the loop will read past the end of the vector.

Example trigger: `checksumTelemetryWindow(frame, 10, 100)` on a 50-byte frame will attempt to read bytes 10-109, going 40 bytes past the allocated memory.

## Fix

### File: TelemetryClaimedLengthRead.cpp

```cpp
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

std::uint32_t checksumTelemetryWindow(const std::vector<std::uint8_t>& frame, std::size_t offset, std::size_t length) {
    if (offset >= frame.size()) {
        return 0;
    }

    // Ensure we don't read past the end of the frame
    std::size_t safe_length = std::min(length, frame.size() - offset);

    std::uint32_t checksum = 0;
    for (std::size_t i = 0; i < safe_length; ++i) {
        checksum = (checksum << 5) ^ frame[offset + i];
    }

    return checksum;
}
```

## Explanation

The fix adds a bounds check by computing `safe_length` as the minimum of the requested `length` and the number of bytes actually available from `offset` to the end of the frame. This ensures the loop never attempts to read beyond `frame.size()`. The `#include <algorithm>` header is added to support `std::min()`.

The fix is safe because:
1. It preserves the initial check for `offset >= frame.size()` (returns 0 if offset is invalid)
2. It caps iteration to only valid indices: `[offset, offset + safe_length)`
3. It maintains the function's intended behavior for valid calls while preventing out-of-bounds access for oversized requests
