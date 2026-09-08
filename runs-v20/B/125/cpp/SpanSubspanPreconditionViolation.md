## Verdict

exploitable

## Source

`MessageHeader.fieldOffset` and `MessageHeader.fieldLength` (lines 8-9), the offset and length the remote sender claims for a field inside a network message. They flow directly, unvalidated, from the `header` parameter of `extractMessageField` into the `subspan` call on line 16 - there is no intervening check anywhere in the function.

## Fix

### File: SpanSubspanPreconditionViolation.cpp

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
    if (header.fieldLength > buffer.size() || header.fieldOffset > buffer.size() - header.fieldLength) {
        throw std::out_of_range("extractMessageField: header fieldOffset/fieldLength exceeds buffer size");
    }
    std::span<const std::byte> field = buffer.subspan(header.fieldOffset, header.fieldLength);

    std::vector<std::byte> result(field.size());
    std::memcpy(result.data(), field.data(), field.size());
    return result;
}
```

## Explanation

`std::span::subspan(offset, count)` documents its offset and count as preconditions, not as checked arguments: it has no throws clause, so calling it with `offset + count > size()` is undefined behaviour rather than a caught error, even though `offset` and `count` here come straight from an untrusted network header. The fix adds an explicit, overflow-safe bounds check immediately before the call, in the order the guidance requires: first reject `fieldLength > buffer.size()`, then - only once that has succeeded - check `fieldOffset > buffer.size() - fieldLength`. Because the first check guarantees `fieldLength <= buffer.size()`, the subtraction in the second check cannot wrap, unlike the more obvious `fieldOffset + fieldLength > buffer.size()`, which overflows for a large `fieldOffset` and would let exactly that oversized value bypass the guard. `buffer.size()` returns `size_t`, wider than the `uint32_t` header fields, so both comparisons promote safely with no separate overflow risk from the field types themselves. Once the check passes, `subspan` is called with values it is now guaranteed to accept, closing the out-of-bounds read at the sink named in the finding.

## Behaviour changes

- Malformed input (a header whose claimed field offset/length does not fit inside `buffer`) now throws `std::out_of_range` instead of invoking undefined behaviour. This is a new observable failure mode for the function: any caller of `extractMessageField` needs to either let the exception propagate or add a `try`/`catch`. No caller exists in the supplied file, so this could not be verified against real call sites; it is called out as the one behaviour change the fix introduces, per the guidance that a bounds-check failure should be surfaced to the caller rather than silently producing a placeholder result.
- No other change: the valid-input path (`fieldOffset`/`fieldLength` within `buffer`) is untouched - same `subspan`, same `memcpy` size, same return value.

Assumption: the file defines no existing error-handling convention (no status/error-code return, no logging), so `std::out_of_range` was chosen as the standard-library exception matching the `.at()`-style "throw on precondition violation" idiom the language guidance recommends. Confidence: medium on this specific choice; a codebase with an established error-return convention elsewhere should use that instead.

Verification: no C++ compiler (`g++`, `clang++`, MSVC `cl`) was reachable in this environment, so the fix was checked by hand rather than compiled. `<stdexcept>` is a standard-library header supplying `std::out_of_range`, whose single-`const char*`/`std::string` constructor is used here; `buffer.size()` and `.subspan()` are pre-existing `std::span` members already used in the original code; no other new name was introduced. The added `if` statement is syntactically complete (balanced braces, semicolon-terminated), uses only names already in scope (`header`, `buffer`) or newly included (`std::out_of_range`), and does not alter any subsequent line.
