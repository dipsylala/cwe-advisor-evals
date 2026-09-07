## Verdict

The vulnerability is confirmed. The code trusts an externally-supplied `claimedCapacity` parameter instead of validating the write index against the `std::span`'s actual size.

## Source

**File:** segment_writer.cpp  
**Lines:** 5-11

The vulnerable call site is in telemetry_encoder.cpp, line 8, which passes `advertisedLength` (untrusted packet header data) as `claimedCapacity`.

## Fix

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

**Key change (line 6):** Replace the check `if (index >= claimedCapacity)` with `if (index >= segment.size())`.

## Explanation

The vulnerability stems from trusting `claimedCapacity` — a value supplied by untrusted input (the packet header in the call chain) — instead of validating against the actual allocated size of the `std::span`.

**Why this is unsafe:**
- `claimedCapacity` may be larger than `segment.size()`
- The function's bounds check against `claimedCapacity` fails to prevent the out-of-bounds write on line 10
- Writing to `segment[index]` when `index >= segment.size()` is undefined behaviour in C++ and corrupts adjacent memory

**Why the fix works:**
- `segment.size()` is the true capacity of the span, not derived from untrusted input
- Checking `index >= segment.size()` ensures every write stays within the allocated buffer
- Per CWE-787 C++ guidance: "the length used for the check is always the length of the data actually pointed at" when using `std::span`
- The span itself is a trusted object received as a parameter; its size cannot be forged by the caller

**Secondary observation:** The `claimedCapacity` parameter is now unused and could be removed in a broader refactoring, but the minimal fix only changes the bounds check.

## Behaviour changes

- **Before:** A caller providing `advertisedLength > packet.size()` can write out of bounds to `packet`.
- **After:** Writes beyond `packet.size()` are silently rejected (early return), preventing memory corruption.
- **Expected test case:** `encodeTelemetry()` with `advertisedLength = 1000` and `packet.size() = 10` should not corrupt memory beyond the packet allocation. A write at index 9 is accepted; a write at index 10+ is rejected.
