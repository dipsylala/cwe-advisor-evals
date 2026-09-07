## Verdict

Confirmed exploitable. The code passes untrusted offset and length values from a network message header directly to `std::span::subspan()` without validation. The `.subspan()` method enforces its bounds as *preconditions*, not as checks—exceeding them is undefined behaviour identical to an out-of-range subscript. An attacker-controlled message can cause an out-of-bounds read by supplying an offset or length that escapes the buffer's allocated memory.

## Source

**File:** `SpanSubspanPreconditionViolation.cpp`  
**Line:** 16

**Vulnerable code:**
```cpp
std::span<const std::byte> field = buffer.subspan(header.fieldOffset, header.fieldLength);
```

**Data flow:**
- Source: `MessageHeader::fieldOffset` and `MessageHeader::fieldLength` (untrusted, from network)
- Sink: `std::span::subspan()` at line 16
- No validation between source and sink

The sender's claimed offset and length travel directly from the network message header to `.subspan()`, which has no bounds check. If `fieldOffset + fieldLength` exceeds `buffer.size()`, the resulting span refers to memory outside the allocated buffer.

## Fix

### File: SpanSubspanPreconditionViolation.cpp

```cpp
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>
#include <stdexcept>

struct MessageHeader {
    std::uint32_t fieldOffset;
    std::uint32_t fieldLength;
};

// Extracts one field from a network message, using the offset and length the
// sender claims for it in the message header.
std::vector<std::byte> extractMessageField(std::span<const std::byte> buffer, const MessageHeader& header) {
    // Validate bounds before accessing. Check length first to prevent overflow.
    if (header.fieldLength > buffer.size()) {
        throw std::out_of_range("Field length exceeds buffer size");
    }
    if (header.fieldOffset > buffer.size() - header.fieldLength) {
        throw std::out_of_range("Field offset and length exceed buffer bounds");
    }
    
    std::span<const std::byte> field = buffer.subspan(header.fieldOffset, header.fieldLength);

    std::vector<std::byte> result(field.size());
    std::memcpy(result.data(), field.data(), field.size());
    return result;
}
```

## Explanation

The fix adds explicit bounds validation before the `.subspan()` call. The checks follow the safe pattern for unsigned arithmetic:

1. **Length check first:** `if (header.fieldLength > buffer.size())` ensures the requested length does not exceed the buffer. This must run first to prevent underflow in the second check.

2. **Offset + length check:** `if (header.fieldOffset > buffer.size() - header.fieldLength)` ensures the offset does not place the read past the end of the buffer. Since we already know `fieldLength <= buffer.size()`, the subtraction `buffer.size() - header.fieldLength` cannot underflow.

3. **Exception on violation:** `std::out_of_range` propagates the error to the caller, which can then handle the malformed message appropriately (e.g., reject the connection, log and discard the frame).

The `.subspan()` call only proceeds after both bounds are validated, so the preconditions are met and the resulting span is safe to dereference.

## Behaviour changes

- **On valid messages** (offset + length ≤ buffer.size()): Behaviour is identical to the original code. The field is extracted and returned.
- **On invalid messages** (offset + length > buffer.size() or length > buffer.size()): The function now throws `std::out_of_range` instead of reading out-of-bounds memory. The caller must catch or propagate this exception; returning an empty result silently would be a regression (the error must not be ignored).
- **Performance:** Two comparison operations per call. Both comparisons are O(1) and negligible compared to the subsequent `std::memcpy()`.
