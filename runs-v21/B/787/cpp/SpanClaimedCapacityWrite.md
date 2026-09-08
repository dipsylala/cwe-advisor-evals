## Verdict

Exploitable. The function checks a user-supplied claimed capacity instead of the span's actual size, allowing writes beyond the buffer's real bounds.

## Source

`advertisedLength` parameter passed from `encodeTelemetry` to `writeSegmentByte` as `claimedCapacity`. This value originates from external input (network packet) and is not validated against the actual span capacity.

## Fix

### File: segment_writer.cpp

```cpp
#include <cstddef>
#include <cstdint>
#include <span>

void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t claimedCapacity, std::size_t index, std::uint8_t value) {
    if (index >= segment.size()) {
        return;
    }

    segment[index] = value;
}
```

## Explanation

The original code checked the index against `claimedCapacity`, a parameter derived from external input (the advertised packet length). An attacker can supply an advertised length larger than the actual buffer size, causing this check to pass while the subsequent write `segment[index] = value` accesses memory beyond the span's actual bounds. The fix replaces the check with a comparison against `segment.size()`, which reflects the true allocated capacity of the buffer. This ensures that every write is validated against the span's actual size, not a potentially inflated external claim. Per the C++ CWE-787 guidance: "take `std::span` and check the index against `buffer.size()` inside the function rather than trusting the caller's length."

## Behaviour changes

None. The function still returns early when the index is out of bounds. The only change is that the bounds check now uses the span's actual size instead of an external parameter, which correctly enforces the safety guarantee. The `claimedCapacity` parameter is no longer used but is preserved in the signature to maintain compatibility with existing callers (who may ignore it or deprecate it separately).
