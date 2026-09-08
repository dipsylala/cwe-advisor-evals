## Verdict

Confirmed. `writeSegmentByte` bounds-checks `index` against `claimedCapacity`, a caller-supplied value that is never verified to match the actual size of the `segment` span. `encodeTelemetry` passes an `advertisedLength` straight through as `claimedCapacity`. If that advertised length is larger than the real extent of `packet`, the bounds check passes for indices that are still out of range for the underlying buffer, and `segment[index] = value` performs an out-of-bounds write. `std::span::operator[]` performs no bounds checking of its own (UB on an out-of-range index), so nothing downstream catches the mismatch.

## Source

`advertisedLength`, the `claimedCapacity` parameter of `writeSegmentByte` as forwarded by `encodeTelemetry`'s `advertisedLength` parameter - an externally supplied/advertised size that is not guaranteed to match the real size of the backing storage for `packet`/`segment`.

## Fix

### File: segment_writer.cpp

```cpp
#include <cstddef>
#include <cstdint>
#include <span>

void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t claimedCapacity, std::size_t index, std::uint8_t value) {
    if (index >= claimedCapacity || index >= segment.size()) {
        return;
    }

    segment[index] = value;
}
```

## Explanation

The original check `index >= claimedCapacity` only validates against a value the caller claims/advertises about the buffer, not against the buffer's actual size. `std::span` already carries its true extent via `segment.size()`, which reflects the real backing storage regardless of what a caller believes or advertises about it. Adding `|| index >= segment.size()` to the guard makes the write's bound the smaller of the two: the index must be within both the claimed capacity and the span's real extent. This closes the out-of-bounds write when `claimedCapacity` (i.e. `advertisedLength` from `encodeTelemetry`) overstates the real size of `packet`, while preserving the existing intent of also rejecting indices beyond the claimed capacity when that capacity is the tighter of the two bounds. The fix is local to the sink and needs no change to the call site: `segment.size()` is always available on the `std::span` parameter already being indexed.
