## Verdict

The `write_payload` function at line 10 of buffer_writer.c contains an out-of-bounds write vulnerability. The bounds check validates only that the payload length does not exceed the total buffer capacity, but fails to account for the offset parameter when determining available space.

## Source

The vulnerability occurs in the `write_payload` function:

```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (length > capacity) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

The bounds check at line 6 tests whether `length > capacity`, but this does not account for the offset. When the offset is applied during the memcpy at line 10, the actual safe writable space is `capacity - offset`, not `capacity`. An attacker who controls the offset and length parameters can write past the buffer boundary.

## Fix

Add a check to ensure the offset and length do not exceed the buffer capacity:

```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (offset > capacity || length > capacity - offset) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

The corrected condition `length > capacity - offset` properly validates that the write operation fits within the remaining buffer space after applying the offset.

## Explanation

Out-of-bounds writes occur when a write operation references memory outside the intended buffer. In this case, the original code validates the payload length against the total buffer capacity but neglects to validate it against the available space *after* applying the offset.

The fix introduces two checks:
1. `offset > capacity` — ensures the offset itself does not exceed the buffer boundary.
2. `length > capacity - offset` — ensures the payload does not extend beyond the buffer when written at the given offset.

Together, these checks guarantee that `destination + offset + length` does not exceed the buffer end, preventing the memcpy from writing out-of-bounds.
