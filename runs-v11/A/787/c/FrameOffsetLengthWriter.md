## Verdict
Confirmed. The bounds check at line 6 validates only `length` against `capacity`, but fails to account for `offset`. When `offset + length > capacity`, the subsequent `memcpy` at line 10 writes beyond the allocated buffer.

## Source
```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (length > capacity) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

The vulnerability: the check `if (length > capacity)` permits writes where `offset + length` exceeds `capacity`.

## Fix
```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (offset + length > capacity) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

Replace the bounds check to validate the end position of the write: `offset + length > capacity` instead of `length > capacity`.

## Explanation
The original code checks whether the payload length alone exceeds capacity, but overlooks that the write begins at `offset` into the buffer. An attacker-controlled `offset` combined with a large `length` can bypass the check and write past the buffer boundary.

The fixed check verifies that the sum of offset and length does not exceed capacity, ensuring the write stays within bounds regardless of where it starts. This is the standard validation for any operation that writes at an offset: confirm both that the starting position and the ending position are within the valid range.
