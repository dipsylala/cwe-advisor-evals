## Verdict

Real - CWE-125 out-of-bounds read in `buffer.subspan()` precondition validation.

## Source

Line 16: `std::span<const std::byte> field = buffer.subspan(header.fieldOffset, header.fieldLength);`

The `header.fieldOffset` and `header.fieldLength` originate from the `MessageHeader` parameter (untrusted network input) and are used as preconditions to `buffer.subspan()` without validation. The C++ standard defines `offset` and `count` in `subspan()` as preconditions, not runtime checks - exceeding them causes undefined behaviour, not an exception.

## Fix

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
    // Validate offset and length against buffer bounds before subspan
    if (header.fieldLength > buffer.size() || header.fieldOffset > buffer.size() - header.fieldLength) {
        return {};  // Return empty result on invalid header
    }
    
    std::span<const std::byte> field = buffer.subspan(header.fieldOffset, header.fieldLength);

    std::vector<std::byte> result(field.size());
    std::memcpy(result.data(), field.data(), field.size());
    return result;
}
```

## Explanation

The fix adds an explicit bounds check before calling `subspan()`. The check tests in the correct order: first verify that `fieldLength` does not exceed the buffer size (preventing wrap-around in unsigned arithmetic), then verify that the offset plus length stays within bounds. Only after both checks pass does the code call `subspan()`, which now operates on validated preconditions. On invalid input, the function returns an empty vector instead of triggering undefined behaviour. This satisfies the function's contract while eliminating the out-of-bounds read.

## Behaviour changes

- **Input rejection**: Oversized or misaligned field offsets/lengths that previously caused undefined behaviour now trigger early return with an empty result.
- **Return value**: On invalid header, the function now returns an empty `std::vector<std::byte>` instead of attempting a read. The caller must handle this case.
- **Exception safety**: No change - the function remains noexcept and does not throw.
