## Verdict
exploitable

## Source
External parameters `offset` and `length` passed through `encode_frame()` into `write_payload()` without bounds validation relative to offset position.

## Fix

**Vulnerable Code:**
```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (length > capacity) {
        return;
    }

    memcpy(destination + offset, payload, length);  // Line 10: out-of-bounds write
}
```

**Fixed Code:**
```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (offset > capacity || length > capacity - offset) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

## Explanation
The original code validates that `length` does not exceed `capacity`, but fails to account for the offset when writing. An attacker can supply a large offset and small length that together exceed the buffer boundaries—for example, offset=200 and length=100 on a 256-byte buffer passes the original check (100 ≤ 256) but writes past the buffer end at position 299. The fix validates the offset first (`offset > capacity`) then checks that the remaining capacity accommodates the length (`length > capacity - offset`). This two-step validation is performed in the correct order so the subtraction cannot underflow. The function maintains its existing behavior of rejecting invalid writes silently via early return, preventing the out-of-bounds write at the memcpy call.

## Behaviour changes
The function now rejects writes where the offset exceeds capacity or where offset plus length exceeds capacity. This is a necessary behaviour change to close the vulnerability. The return path and silent-failure pattern remain unchanged from the original.
