## Verdict

CONFIRMED. The `write_payload()` function at line 10 of buffer_writer.c performs an out-of-bounds write. The bounds check only validates `length > capacity` but fails to account for the `offset` parameter, allowing writes to proceed when `offset + length` exceeds the buffer capacity.

## Source

The vulnerability occurs in buffer_writer.c where `memcpy()` is called without proper bounds validation:

```c
void write_payload(uint8_t *destination, size_t capacity, size_t offset, const uint8_t *payload, size_t length) {
    if (length > capacity) {  // Incomplete check: ignores offset
        return;
    }
    
    memcpy(destination + offset, payload, length);  // Write at destination + offset
}
```

When called from frame_encoder.c with a Frame structure having capacity 256, an attacker can supply an offset and length such that `offset + length > 256`, resulting in a write past the buffer boundary.

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

The fix adds two complementary checks:

1. **`offset > capacity`**: Ensures the offset itself does not exceed the buffer capacity.
2. **`length > capacity - offset`**: Ensures that writing `length` bytes starting at `offset` does not exceed the buffer. This check is safe from integer underflow because the first condition already verified `offset <= capacity`.

Together, these ensure that `offset + length <= capacity`, preventing any out-of-bounds write. The function now correctly rejects requests where the combined offset and payload length would overflow the destination buffer.
