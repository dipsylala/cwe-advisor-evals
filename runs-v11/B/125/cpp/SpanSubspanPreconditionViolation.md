## Verdict

Exploitable

## Source

`header.fieldOffset` and `header.fieldLength` originate from untrusted network message data (the `MessageHeader` struct parameter)

## Fix

**Vulnerable code (line 14-16):**
```cpp
std::vector<std::byte> extractMessageField(std::span<const std::byte> buffer, const MessageHeader& header) {
    // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
    std::span<const std::byte> field = buffer.subspan(header.fieldOffset, header.fieldLength);
```

**Fixed code:**
```cpp
std::vector<std::byte> extractMessageField(std::span<const std::byte> buffer, const MessageHeader& header) {
    // Validate offset and length against buffer bounds before calling subspan
    if (header.fieldOffset >= buffer.size()) {
        throw std::out_of_range("Field offset exceeds buffer size");
    }
    
    // Check that offset + length doesn't exceed buffer size (safe against overflow)
    if (header.fieldLength > buffer.size() - header.fieldOffset) {
        throw std::out_of_range("Field extends beyond buffer size");
    }
    
    std::span<const std::byte> field = buffer.subspan(header.fieldOffset, header.fieldLength);
```

## Explanation

The code trusts untrusted header field values (`fieldOffset` and `fieldLength`) without validation, passing them directly to `.subspan()`. According to C++20 semantics, `.subspan()` treats its offset and count as preconditions, not as checked parameters—it performs no bounds validation and has no throws clause. Exceeding these preconditions results in undefined behavior. An attacker can supply arbitrary offset and length values in the message header to create a span pointing to memory beyond the buffer's allocated bounds. The subsequent `memcpy()` at line 19 then reads from that out-of-bounds span.

The fix adds explicit bounds checking immediately before the `.subspan()` call. It verifies that the offset is within the buffer size and that adding the requested length to the offset does not exceed the buffer size. The overflow check is safe because if `header.fieldOffset >= buffer.size()`, the first check throws before we subtract. Only after both conditions are satisfied does the code call `.subspan()`, ensuring the subsequent span and memcpy operate on validated, in-bounds values.

## Behaviour changes

**Exception thrown on invalid input:** The function now throws `std::out_of_range` when the header specifies an offset or length that would read out of bounds. Previously, the code would create an out-of-bounds span silently, resulting in undefined behavior during the subsequent memcpy. This is a security improvement that makes the error explicit and actionable by the caller, rather than a logic change to the function's core operation.
