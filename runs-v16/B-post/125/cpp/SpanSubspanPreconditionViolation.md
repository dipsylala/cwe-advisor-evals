## Verdict

CONFIRMED: CWE-125 Out-of-bounds Read at line 16 in `SpanSubspanPreconditionViolation.cpp`.

The vulnerability exists because `std::span::subspan()` enforces its offset and count as *preconditions*, not bounds checks. When `header.fieldOffset` or `header.fieldLength` are untrusted network values exceeding the buffer size, the precondition is violated and `subspan()` exhibits undefined behaviour.

## Source

Line 16 of `SpanSubspanPreconditionViolation.cpp`:

```cpp
std::span<const std::byte> field = buffer.subspan(header.fieldOffset, header.fieldLength);
```

The `buffer` parameter is a `std::span<const std::byte>` whose size is the actual buffer length. The `header.fieldOffset` and `header.fieldLength` come from an untrusted `MessageHeader` passed as a parameter. There is no validation that these values fit within `buffer.size()` before calling `subspan()`.

## Fix

Add a bounds check immediately before line 16. The fix validates both the length and offset in the correct order to avoid unsigned arithmetic wrapping:

```cpp
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <vector>

struct MessageHeader {
    std::uint32_t fieldOffset;
    std::uint32_t fieldLength;
};

// Extracts one field from a network message, using the offset and length the
// sender claims for it in the message header.
std::vector<std::byte> extractMessageField(std::span<const std::byte> buffer, const MessageHeader& header) {
    // Validate bounds before subspan: check length first to avoid wrapping in unsigned arithmetic
    if (header.fieldLength > buffer.size() || header.fieldOffset > buffer.size() - header.fieldLength) {
        throw std::out_of_range("Field offset and length exceed buffer bounds");
    }
    
    std::span<const std::byte> field = buffer.subspan(header.fieldOffset, header.fieldLength);

    std::vector<std::byte> result(field.size());
    std::memcpy(result.data(), field.data(), field.size());
    return result;
}
```

The fix adds `#include <stdexcept>` for `std::out_of_range`, which is in the standard library.

## Explanation

The vulnerability occurs because `std::span::subspan()` is a precondition check, not a bounds-safe operation: the C++20 standard specifies that violating its preconditions (offset or count exceeding span size) results in undefined behaviour. When `header.fieldOffset` and `header.fieldLength` come from untrusted network input without validation, an attacker can craft values that cause `subspan()` to read beyond the buffer's actual end.

The fix adds an explicit bounds validation immediately before the `subspan()` call. The validation follows the correct order specified in the CWE-125 C++ guidance: first check `header.fieldLength > buffer.size()`, then check `header.fieldOffset > buffer.size() - header.fieldLength`. This ordering is critical because in unsigned arithmetic, if `header.fieldLength` exceeds `buffer.size()`, the subtraction `buffer.size() - header.fieldLength` would wrap to a large value, causing the second check to pass falsely. By checking the length first, we prevent this wrap-around and ensure both preconditions of `subspan()` are satisfied.

The exception is thrown with a descriptive message, allowing the caller to handle the error appropriately rather than proceeding with undefined behaviour.

## Behaviour changes

- **Input validation**: Untrusted offset and length values from the network message header are now validated against the buffer size.
- **Exception on violation**: If the header claims a field that extends beyond the buffer, the function throws `std::out_of_range` instead of triggering undefined behaviour.
- **Caller responsibility**: Callers must now catch `std::out_of_range` or allow it to propagate. The previous code silently invoked undefined behaviour; this fix makes the error explicit and recoverable.
- **No performance penalty for valid inputs**: When offset and length are within bounds, the two comparison operations add minimal overhead and the function behaves identically to the original.
