## Verdict
exploitable

## Source
`telemetry_encoder.cpp:7` - the `advertisedLength` parameter originates from an external caller and is passed to `writeSegmentByte()` as the untrusted `claimedCapacity`.

## Fix

**Vulnerable code (segment_writer.cpp, lines 5-11):**
```cpp
void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t claimedCapacity, std::size_t index, std::uint8_t value) {
    if (index >= claimedCapacity) {
        return;
    }

    segment[index] = value;
}
```

**Fixed code (segment_writer.cpp):**
```cpp
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>

void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t index, std::uint8_t value) {
    if (index >= segment.size()) {
        throw std::out_of_range("Write index out of bounds");
    }

    segment[index] = value;
}
```

**Updated caller (telemetry_encoder.cpp):**
```cpp
#include <cstddef>
#include <cstdint>
#include <span>

void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t index, std::uint8_t value);

void encodeTelemetry(std::span<std::uint8_t> packet, std::size_t advertisedLength, std::size_t index, std::uint8_t value) {
    writeSegmentByte(packet, index, value);
}
```

## Explanation
The vulnerability stems from trusting an externally-supplied length claim (`claimedCapacity`/`advertisedLength`) rather than the actual span's capacity. An attacker can pass `advertisedLength > packet.size()` to bypass the bounds check at line 6 and write past the span's allocated region. The fix removes the untrusted parameter entirely and validates the index against `segment.size()` (the actual span capacity) instead. The check is now inside `writeSegmentByte()` where the real capacity is available, and an out-of-bounds write throws an exception rather than silently returning, so the caller knows the operation failed. This aligns with the C++ guidance principle: validate against the destination's actual capacity, never against an external claim.

## Behaviour changes
The function signature changes from `writeSegmentByte(span, claimedCapacity, index, value)` to `writeSegmentByte(span, index, value)`. The untrusted `claimedCapacity` parameter is removed, eliminating the source of the vulnerability. The error handling changes from silent return (which masks failure) to throwing `std::out_of_range`, making the error explicit to the caller. The caller must update its invocation to pass only `index` and `value`, and must handle or propagate the exception if out-of-bounds writes are possible.
