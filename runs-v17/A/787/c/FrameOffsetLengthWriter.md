## Verdict
CONFIRMED

## Source
The `write_payload` function in `buffer_writer.c` performs an out-of-bounds write by failing to account for the `offset` parameter when validating buffer capacity. The validation at line 6 checks only whether `length` exceeds `capacity`, but does not ensure that `offset + length` does not exceed the buffer bounds. This allows an attacker to trigger a write beyond the allocated buffer when `offset` is large relative to the remaining capacity.

## Fix

### File: buffer_writer.c
```c
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (offset > capacity || length > capacity - offset) {
        return;
    }

    memcpy(destination + offset, payload, length);
}
```

## Explanation
The fix adds two checks to prevent out-of-bounds writes:

1. `offset > capacity` — ensures the offset itself is within bounds
2. `length > capacity - offset` — ensures the write does not exceed the buffer by checking that the combined span (offset + length) does not overflow the capacity

This arithmetic check prevents integer underflow when `offset > capacity` (the subtraction `capacity - offset` would underflow for size_t), which is why the separate `offset > capacity` check must come first. Together, these conditions ensure that every byte written by `memcpy` falls within the allocated buffer range `[0, capacity)`.
