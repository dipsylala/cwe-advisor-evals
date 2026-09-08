## Verdict

Exploitable. The code calls `std::span::subspan()` with user-supplied offset and length values from the `MessageHeader` struct without validation. The C++20 standard specifies that `subspan()` treats offset and count as preconditions, not checked parameters - exceeding them results in undefined behaviour (out-of-bounds read). This is an exploitable out-of-bounds read vulnerability.

## Source

The `header` parameter (specifically `header.fieldOffset` and `header.fieldLength`) contains untrusted values from a network message, passed through a `MessageHeader` struct to the `extractMessageField()` function.

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
    // Validate offset and length against buffer size before subspan.
    // Check length first (unsigned arithmetic): if length exceeds buffer.size(),
    // the subtraction in the second check would wrap. Then check that offset
    // plus length does not exceed buffer size.
    if (header.fieldLength > buffer.size() || 
        header.fieldOffset > buffer.size() - header.fieldLength) {
        return std::vector<std::byte>();
    }
    
    std::span<const std::byte> field = buffer.subspan(header.fieldOffset, header.fieldLength);

    std::vector<std::byte> result(field.size());
    std::memcpy(result.data(), field.data(), field.size());
    return result;
}
```

## Explanation

The fix adds an explicit bounds check immediately before the `.subspan()` call. The check validates that the requested field length does not exceed the buffer size, and that the field offset plus length does not overflow the buffer bounds. The check order matters: length is validated first to prevent unsigned integer underflow in the subtraction `buffer.size() - header.fieldLength`. If either condition is violated, the function returns an empty vector instead of proceeding with an out-of-bounds read. This eliminates the undefined behaviour while preserving the function's return type and contract.

## Behaviour changes

The function now returns an empty vector when the offset or length provided in the message header would read outside the buffer bounds, instead of proceeding with undefined behaviour. This is a necessary behaviour change to prevent memory corruption. Code that calls `extractMessageField()` should be prepared to handle empty results, which may indicate either a malformed message or insufficient buffer data.
