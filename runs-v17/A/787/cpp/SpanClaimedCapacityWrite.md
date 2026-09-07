## Verdict

Out-of-bounds write confirmed. The bounds check at line 6 compares `index` against `claimedCapacity`, which is caller-provided and untrusted. If `claimedCapacity` exceeds the actual span size, the write at line 10 will exceed the span's bounds.

## Source

The vulnerability is in `segment_writer.cpp`, function `writeSegmentByte()`. The caller passes a `claimedCapacity` parameter that is trusted for bounds checking, but this parameter is not validated against the actual span size. The span's actual capacity (`segment.size()`) is never checked, creating a gap between the claimed and actual bounds.

The call chain originates in `telemetry_encoder.cpp`, where `encodeTelemetry()` receives an `advertisedLength` and forwards it as the `claimedCapacity`. An attacker or logic error providing an `advertisedLength` greater than the packet span's true size will cause `writeSegmentByte()` to write out-of-bounds.

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

The fix replaces the bounds check at line 6. Instead of validating `index` against the untrusted `claimedCapacity`, the check now uses `segment.size()`, the span's actual capacity. This ensures that any write stays within the span's true bounds regardless of what `claimedCapacity` value the caller provides.

The `claimedCapacity` parameter remains in the signature for API compatibility with the caller chain, but it is no longer used for bounds validation. The actual bounds check now relies on the span's inherent size, which is guaranteed by the type system.
