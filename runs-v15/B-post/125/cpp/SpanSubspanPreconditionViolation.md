## Verdict

Exploitable.

## Source

`header.fieldOffset` and `header.fieldLength` from the untrusted `MessageHeader` struct, originating from a network message sender.

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
    // Validate length first to prevent unsigned integer wrap-around on subtraction
    if (header.fieldLength > buffer.size()) {
        throw std::out_of_range("Message field length exceeds buffer size");
    }
    // Then validate offset + length fits within buffer
    if (header.fieldOffset > buffer.size() - header.fieldLength) {
        throw std::out_of_range("Message field offset and length exceed buffer size");
    }
    
    std::span<const std::byte> field = buffer.subspan(header.fieldOffset, header.fieldLength);

    std::vector<std::byte> result(field.size());
    std::memcpy(result.data(), field.data(), field.size());
    return result;
}
```

## Explanation

The vulnerability occurs because `std::span::subspan()` treats its offset and count parameters as preconditions rather than enforced checks, meaning exceeding them results in undefined behavior. The code passes untrusted `fieldOffset` and `fieldLength` values directly from the network message header without validation. An attacker can craft a message where these values exceed the buffer's actual size, triggering an out-of-bounds read.

The fix adds explicit bounds validation before the `subspan()` call. The validation order is critical: checking `fieldLength > buffer.size()` first prevents unsigned integer wrap-around on the subtraction `buffer.size() - fieldLength`. If the length check were skipped and performed after the offset check, an oversized length would cause the subtraction to wrap to a large unsigned value, allowing the offset check to pass when it should fail. The second check ensures that `offset + length` does not exceed the buffer size. Only after both validations pass is the call to `subspan()` safe.

## Behaviour changes

The function now throws `std::out_of_range` when message field offsets or lengths exceed the buffer bounds. This changes the error-handling contract from undefined behavior to a defined exception that propagates to the caller. Callers must be prepared to handle this exception or let it unwind the stack. This is a safety improvement: the prior behavior risked silent memory corruption or information disclosure, while the new behavior makes the error explicit.
