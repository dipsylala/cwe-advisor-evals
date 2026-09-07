## Verdict

Exploitable

## Source

Line 7 in `telemetry_encoder.cpp`: the `advertisedLength` parameter received from untrusted input represents a claim about how much data is present, not the actual capacity of the `packet` span being written to.

## Fix

### File: segment_writer.cpp

```cpp
#include <cstddef>
#include <cstdint>
#include <span>

void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t index, std::uint8_t value) {
    if (index >= segment.size()) {
        return;
    }

    segment[index] = value;
}
```

### File: telemetry_encoder.cpp

```cpp
#include <cstddef>
#include <cstdint>
#include <span>

void writeSegmentByte(std::span<std::uint8_t> segment, std::size_t index, std::uint8_t value);

void encodeTelemetry(std::span<std::uint8_t> packet, std::size_t index, std::uint8_t value) {
    writeSegmentByte(packet, index, value);
}
```

## Explanation

The vulnerability occurs because `writeSegmentByte()` checks whether `index >= claimedCapacity` to prevent out-of-bounds writes, but `claimedCapacity` is untrusted external input (the advertised length from the packet) rather than the actual size of the `segment` span. An attacker can supply an `advertisedLength` larger than the actual `packet` span, causing the bounds check to pass for indices that are actually out of bounds. When `operator[]` is then applied to the span at line 10 of the original code, it performs no bounds checking and writes past the allocated buffer, corrupting adjacent memory.

The fix removes the `claimedCapacity` parameter entirely and validates the index against the span's actual size using `segment.size()` instead. This ensures the bounds check cannot be bypassed by an attacker who controls the advertised length. The C++20 `std::span` automatically tracks its own capacity, making this check reliable and eliminating the vulnerability. Both files are updated to reflect the corrected function signature.

## Behaviour changes

**Removed parameter**: `claimedCapacity` parameter removed from `writeSegmentByte()` function signature in both files. This parameter is no longer necessary because the actual span size is used for validation. **Reason**: Removing the untrusted parameter eliminates the exploitation vector and aligns with CWE-787 guidance that states to "validate it against the actual destination capacity, not the sender's claim."

**Changed validation**: The bounds check now uses `segment.size()` instead of the caller-supplied `claimedCapacity`. **Reason**: This ensures validation against the actual allocated buffer, not an external claim.

No change to return value, error behavior, or the core write operation. The function still returns silently if the index is out of bounds, and still performs the write if it passes the check.

## Verification

Verification performed by code inspection for C++20 syntax compliance:
- `#include <span>` is valid C++20 header
- `std::span<std::uint8_t>` is valid C++20 template instantiation
- `segment.size()` is a valid method of `std::span` returning `std::size_t`
- Function signatures match between declaration and definition
- All parameters properly passed through the call chain
- No undefined symbols or missing dependencies

Syntax check: The fixed code uses only standard C++ library features (C++20) and contains no syntax errors. All identifiers are properly defined within standard library headers.

