## Verdict
Exploitable

## Source
The `offset` and `length` parameters in the `write_payload()` function are passed from external input via `encode_frame()` without validation that their sum fits within the destination buffer.

## Fix

**Vulnerable code:**
```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (length > capacity) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

**Fixed code:**
```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (offset > capacity || length > capacity - offset) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

## Explanation
The original code checks only that `length` does not exceed `capacity`, but the actual write destination is `destination + offset`. This allows an attacker to write past the buffer end by providing values where `offset + length > capacity`. For example, with `capacity=256`, `offset=100`, and `length=200`, the original check passes because `200 ≤ 256`, but the write accesses bytes from position 100 to 299, exceeding the 256-byte buffer. The fix validates the offset first to ensure it is within bounds, then validates that the remaining capacity from the offset is sufficient for the length, preventing the sum from exceeding the buffer.

## Behaviour changes
None. The function performs the same write operation when the input is valid; it simply rejects invalid inputs more strictly by catching the case where `offset + length` exceeds the buffer capacity.
