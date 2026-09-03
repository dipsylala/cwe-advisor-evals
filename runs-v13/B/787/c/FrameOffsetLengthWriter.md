## Verdict

exploitable

## Source

The `offset` and `length` parameters are received from the caller, untrusted. The `capacity` parameter represents the destination buffer's size.

## Fix

**Vulnerable code:**
```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (length > capacity) {
        return;
    }

    memcpy(destination + offset, payload, length);  // Vulnerability: offset not validated
}
```

**Fixed code:**
```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    // Validate offset is within bounds
    if (offset > capacity) {
        return;
    }
    
    // Validate that offset + length doesn't exceed capacity (check in this order to prevent underflow)
    if (length > capacity - offset) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

## Explanation

The original code validates only that `length` does not exceed `capacity`, but does not account for the `offset`. An attacker who controls `offset` can cause the write to extend past the buffer's end: if `capacity=100`, `offset=50`, and `length=60`, the check passes but the write spans bytes 50–110, corrupting 10 bytes beyond the buffer. The fix adds two sequential checks: first, `offset <= capacity` to ensure the starting position is valid; second, `length <= capacity - offset` to ensure the write stays within bounds. The checks are performed in this order to prevent integer underflow in the subtraction. The bounds now guarantee that `offset + length <= capacity`, blocking all out-of-bounds writes.

## Behaviour changes

- Added early return if `offset > capacity` to validate the starting position within the buffer bounds
- Added early return if `length > capacity - offset` to ensure the total write span (offset + length) does not exceed capacity
- Both checks are rejections rather than truncations, so oversized or misaligned writes fail cleanly with no partial write
- The function's return type (void) and success indication remain unchanged; callers currently receive no feedback on whether a write was accepted or rejected—this is pre-existing and not addressed by the bounds-check fix
