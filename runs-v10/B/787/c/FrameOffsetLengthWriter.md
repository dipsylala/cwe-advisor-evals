## Verdict

Exploitable. The `write_payload` function validates that the requested `length` does not exceed the destination `capacity`, but fails to validate that the combination of `offset` and `length` stays within bounds. An attacker providing a large `offset` value can cause `memcpy` to write past the end of the destination buffer.

## Source

Data flow originates in `encode_frame` (frame_encoder.c:11-12), which receives `offset` and `length` as parameters and passes them untrusted to `write_payload`. Both values arrive from the caller without bounds validation.

The sink is `memcpy` at buffer_writer.c:10, which writes `length` bytes to `destination + offset` without verifying that `offset + length` does not exceed the destination's `capacity`.

## Fix

**Vulnerable code** (buffer_writer.c:5-11):

```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (length > capacity) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

**Fixed code**:

```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (offset > capacity || length > capacity - offset) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

## Explanation

The original bounds check only validates `length` against `capacity`, ignoring the `offset`. The fix validates the offset first to ensure the subtraction is safe, then checks that the remaining capacity is sufficient for the `length`. This prevents both oversized length values and out-of-bounds offset values from causing a write past the destination buffer end. The check order—testing `offset > capacity` before subtracting from `capacity`—prevents integer underflow in the second comparison.

## Behaviour changes

None. The function signature, return type, and calling convention remain unchanged. The only change is the validation condition; on failure, the function still returns without writing. On success, the same `memcpy` call executes, and callers receive the same result.
