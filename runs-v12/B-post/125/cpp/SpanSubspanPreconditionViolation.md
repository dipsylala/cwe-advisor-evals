## Verdict

Exploitable.

## Source

`header.fieldOffset` and `header.fieldLength` from the `MessageHeader` parameter, originating from untrusted network message data, flow directly to the `subspan()` call without validation.

## Sink

`buffer.subspan(header.fieldOffset, header.fieldLength)` at line 16.

## Fix

**Vulnerable code:**
```cpp
std::vector<std::byte> extractMessageField(std::span<const std::byte> buffer, const MessageHeader& header) {
    // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
    std::span<const std::byte> field = buffer.subspan(header.fieldOffset, header.fieldLength);

    std::vector<std::byte> result(field.size());
    std::memcpy(result.data(), field.data(), field.size());
    return result;
}
```

**Fixed code:**
```cpp
std::vector<std::byte> extractMessageField(std::span<const std::byte> buffer, const MessageHeader& header) {
    // Validate that the requested field is within the buffer bounds.
    // Check length first to avoid unsigned underflow in the offset check.
    if (header.fieldLength > buffer.size() || header.fieldOffset > buffer.size() - header.fieldLength) {
        return std::vector<std::byte>();
    }
    
    std::span<const std::byte> field = buffer.subspan(header.fieldOffset, header.fieldLength);

    std::vector<std::byte> result(field.size());
    std::memcpy(result.data(), field.data(), field.size());
    return result;
}
```

## Explanation

The vulnerability occurs because `std::span::subspan()` enforces its offset and count parameters as preconditions, not runtime checks. The C++ standard states these as undefined behaviour if violated, with no throw clause. When an untrusted `MessageHeader` struct provides offset and length values from network input, an attacker can craft values that cause the subspan call to read beyond the buffer bounds. The fix adds an explicit bounds check before calling `subspan()`, validating both that the requested length fits within the buffer and that the offset plus length does not exceed the buffer size. The check order matters: testing `fieldLength > buffer.size()` first prevents unsigned arithmetic underflow in the subsequent subtraction, which is critical in unsigned integer arithmetic.

## Behaviour changes

The fixed code returns an empty vector when the offset or length preconditions are violated. This is a behaviour change from the original, which would have undefined behaviour. The caller receives an empty result rather than undefined data, which is the correct safe-by-default response to invalid input. The function signature and return type remain unchanged, and valid inputs continue to produce the same result as before.
