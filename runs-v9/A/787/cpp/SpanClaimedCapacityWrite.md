## Verdict

Confirmed. `writeSegmentByte` bounds-checks `index` against `claimedCapacity`, a caller-supplied value that is never verified to match the actual size of the `segment` span. When `claimedCapacity` (passed through as `advertisedLength` from `encodeTelemetry`) exceeds `segment.size()`, an `index` that passes the check can still be at or beyond the end of the real backing buffer, producing an out-of-bounds write at `segment[index] = value`.

## Source

`encodeTelemetry`'s `advertisedLength` parameter (telemetry_encoder.cpp, line 7) is the untrusted, caller-controlled capacity claim. It flows unchanged into `writeSegmentByte`'s `claimedCapacity` parameter (telemetry_encoder.cpp line 8 -> segment_writer.cpp line 5), which is then used as the sole bound for validating `index` against the `segment` span. There is no point in the call chain where `claimedCapacity`/`advertisedLength` is checked against `packet`/`segment`'s actual size (`segment.size()`).

## Fix

In `writeSegmentByte` (segment_writer.cpp), bound `index` against the span's real extent instead of (or in addition to) the claimed capacity:

```cpp
#include <cstddef>
#include <cstdint>
#include <span>

void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t claimedCapacity, std::size_t index, std::uint8_t value) {
    std::size_t effectiveCapacity = std::min(claimedCapacity, segment.size());

    if (index >= effectiveCapacity) {
        return;
    }

    segment[index] = value;
}
```

(`#include <algorithm>` for `std::min`.) This keeps the existing capacity semantics for legitimate callers while guaranteeing the write can never land outside `segment`'s real backing storage, regardless of what capacity value is claimed upstream.

## Explanation

`std::span<std::uint8_t>` does not own its storage and does not guarantee that `size()` matches any externally supplied "capacity" value — a span can be constructed over a buffer smaller than a length claimed elsewhere in the protocol/data structure being parsed. The original check `index >= claimedCapacity` validates `index` against a number that has no verified relationship to the actual memory `segment` refers to. An attacker or malformed input that inflates `advertisedLength` beyond the real packet buffer size can supply an `index` that is legal under the claimed capacity but out of bounds for the underlying storage, causing `segment[index] = value` to write past the end of the buffer — a classic CWE-787 out-of-bounds write. Clamping the effective bound to `std::min(claimedCapacity, segment.size())` ensures the check always reflects the true, physically backed extent of the buffer being written, closing the gap without requiring the caller (`encodeTelemetry`) to be trusted to pass a consistent capacity.
