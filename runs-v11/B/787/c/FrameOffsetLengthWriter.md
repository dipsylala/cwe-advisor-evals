## Verdict

Exploitable

## Source

The `offset` and `length` parameters passed to `write_payload()` from `encode_frame()` are externally controlled and not validated against the destination buffer's capacity before use.

## Fix

**Vulnerable code (line 5-11):**

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

The original bounds check validates only that `length` does not exceed `capacity`, but fails to account for the `offset` parameter. This allows a write to proceed past the end of the destination buffer. When `memcpy()` writes to `destination + offset`, the actual bytes written span from `offset` to `offset + length`. If `offset + length > capacity`, the write extends beyond the allocated buffer, corrupting adjacent memory.

The fix validates both `offset` and the combined size. It first checks that `offset` does not exceed the capacity, then checks that the remaining space (calculated as `capacity - offset`) is sufficient for `length` bytes. This order ensures the subtraction cannot underflow and closes the out-of-bounds write vulnerability.

## Behaviour changes

None. The function's contract and return value remain unchanged. The check now properly enforces that the entire write operation (from `offset` to `offset + length`) stays within the destination's allocated capacity.
