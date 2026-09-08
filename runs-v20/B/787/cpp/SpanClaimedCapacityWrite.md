## Verdict

Confirmed. `writeSegmentByte` bounds-checks the write index against `claimedCapacity`, a caller-supplied length parameter, instead of against `segment.size()`, the actual extent of the `std::span` it writes into. When the claimed length exceeds the real span size, the index passes the check and `segment[index] = value` writes past the end of the backing buffer - CWE-787.

## Source

`encodeTelemetry` in `telemetry_encoder.cpp` receives `packet` (a `std::span<std::uint8_t>`) and `advertisedLength`, and forwards both unchanged to `writeSegmentByte`:

```
void encodeTelemetry(std::span<std::uint8_t> packet, std::size_t advertisedLength, std::size_t index, std::uint8_t value) {
    writeSegmentByte(packet, advertisedLength, index, value);
}
```

`advertisedLength` is a claim about the packet's declared/advertised size, not a measurement of the buffer actually backing `packet`. Nothing between the caller of `encodeTelemetry` and the write in `writeSegmentByte` reconciles the two. If a caller advertises a length larger than the span it actually hands over (e.g. a packet header claims more payload than was actually allocated or received), `advertisedLength` becomes `claimedCapacity` inside `writeSegmentByte`, and the bounds check at line 6 validates `index` against that inflated, untrustworthy value instead of the real buffer size.

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

The sink is `segment[index] = value`, a `std::span::operator[]` write, which performs no bounds checking of its own - the guarantee has to come from the check that precedes it. The original check (`index >= claimedCapacity`) validates the index against the sender's claimed length rather than the span's actual size, which is exactly the inversion CWE-787 guidance calls out: a length arriving from outside is a claim about how much data was sent, never a statement about how much room exists to write into. `std::span` already knows its own real extent via `.size()`, so the fix adds `index >= segment.size()` to the same guard, short-circuiting before the assignment whenever the index would fall outside the buffer that is actually backing the span - regardless of what `claimedCapacity` says. The original `claimedCapacity` check is left in place rather than replaced, since it may still encode a legitimate logical limit (e.g. the caller not wanting writes past the declared payload length even when the underlying buffer is larger); the new `segment.size()` check is a second, independent floor that the untrusted value can no longer bypass. The function's contract is otherwise unchanged: it still returns `void`, still silently declines the write and returns for any out-of-range index (including the newly-caught case), and takes no new parameters, so `encodeTelemetry` and any other caller need no changes.

`std::span::size()` is a standard-library member (C++20 `<span>`), already included via the existing `#include <span>`; no new header or dependency is introduced.

No C++ compiler was reachable in this environment to compile-check the fix; it was verified by hand instead: `segment` is a `std::span<std::uint8_t>`, `.size()` returns `std::span::size_type` (an unsigned integral type compatible with `std::size_t`), so `index >= segment.size()` is a valid, well-typed comparison consistent with the existing `index >= claimedCapacity` comparison beside it. No other symbol, argument, or return type in the file changed, and the one caller in the traced chain (`encodeTelemetry`) required no update since `writeSegmentByte`'s signature is unchanged.

## Behaviour changes

- A call whose `index` is within `claimedCapacity` but at or beyond the span's actual `.size()` now silently declines the write and returns, instead of writing out of bounds. This is the intended closure of the finding.
- No other input produces a different result: any index already rejected by the `claimedCapacity` check is still rejected, and any index within both bounds still writes exactly as before.
