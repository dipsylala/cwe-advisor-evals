## Verdict
CONFIRMED: Out-of-bounds read via unchecked offset and length in `buffer.subspan()`.

## Source
Line 16 calls `buffer.subspan(header.fieldOffset, header.fieldLength)` without validating that the offset and length parameters stay within the buffer's bounds. A message header with `fieldOffset + fieldLength > buffer.size()` or `fieldOffset >= buffer.size()` creates a span that reads past valid memory.

## Fix

### File: SpanSubspanPreconditionViolation.cpp
```cpp
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

struct MessageHeader {
    std::uint32_t fieldOffset;
    std::uint32_t fieldLength;
};

// Extracts one field from a network message, using the offset and length the
// sender claims for it in the message header.
std::vector<std::byte> extractMessageField(std::span<const std::byte> buffer, const MessageHeader& header) {
    // Validate that the requested range is within the buffer bounds before creating the subspan.
    if (header.fieldOffset > buffer.size() || 
        header.fieldLength > buffer.size() - header.fieldOffset) {
        return std::vector<std::byte>();
    }
    
    std::span<const std::byte> field = buffer.subspan(header.fieldOffset, header.fieldLength);

    std::vector<std::byte> result(field.size());
    std::memcpy(result.data(), field.data(), field.size());
    return result;
}
```

## Explanation
The fix adds bounds checking before `subspan()` is called. The two conditions together ensure:

1. `header.fieldOffset > buffer.size()` — rejects offsets beyond the buffer end
2. `header.fieldLength > buffer.size() - header.fieldOffset` — rejects lengths that would extend past the buffer end (safe from underflow because the first check passed)

When the header claims an invalid range, the function returns an empty vector rather than creating a span that violates preconditions. This prevents the out-of-bounds memory read.
