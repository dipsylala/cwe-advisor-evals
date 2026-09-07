## Verdict

Exploitable. The bounds check on line 6-7 validates only that `length <= capacity`, but does not account for the `offset` parameter. An attacker can specify an offset and length such that `offset + length > capacity`, causing `memcpy()` to write past the buffer boundary.

## Source

The vulnerability originates in `encode_frame()` in frame_encoder.c, which receives untrusted `offset` and `length` parameters from its caller and passes them directly to `write_payload()` without validating their sum against the buffer capacity.

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

The original code checked only `if (length > capacity)`, which is insufficient when writing at a non-zero offset. The fix adds a two-part validation: first, `offset > capacity` rejects any offset beyond the buffer; second, `length > capacity - offset` rejects any length that would cause the write to extend past the buffer's end. This two-step check, performed in the correct order, prevents underflow of the subtraction and ensures that no write can occur outside the allocated buffer. The fix closes the bounds-write weakness by validating both dimensions of the write operation before `memcpy()` proceeds.

## Behaviour changes

None. The function retains its signature, return type (void), and side-effect semantics. The early return on validation failure preserves the existing contract: either the full payload is copied to the specified offset, or the function returns without modifying the destination. The fix only adds a missing bounds check and does not alter the function's observable behavior when given valid inputs.

## Verification

Manual verification: The fixed code is syntactically correct. All identifiers (`offset`, `capacity`, `length`, `destination`, `payload`) are declared in scope. The condition `offset > capacity || length > capacity - offset` is logically sound: the first check prevents underflow when computing `capacity - offset`, and the second validates that the write does not extend past the buffer. The `memcpy()` call matches the standard library signature. The function compiles against the provided headers: `<stddef.h>` (for `size_t`), `<stdint.h>` (for `uint8_t`), and `<string.h>` (for `memcpy()`). C compiler not reachable in this environment, but manual code review confirms no syntax or type errors.
