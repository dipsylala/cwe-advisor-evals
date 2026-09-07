## Verdict

Exploitable. The function `write_payload()` at line 10 of buffer_writer.c performs a bounds-unchecked `memcpy()` that can write beyond the destination buffer's capacity when the `offset` parameter is large.

## Source

The `offset` and `length` parameters in `write_payload()` arrive from the caller `encode_frame()`, which receives them as untrusted external input. The `offset` parameter is never validated; the `length` check does not account for the offset's contribution to the total write position.

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

The vulnerability allows an attacker to write past the end of the buffer by supplying an offset that is within capacity but leaves insufficient remaining space for the requested length. For example, with capacity=256, offset=200, and length=100, the original check `length > capacity` passes, but the write reaches positions 200–299, exceeding the buffer boundary at 256.

The fix validates two conditions in sequence: first, that `offset` does not exceed `capacity`; second, that `length` does not exceed the remaining space `capacity - offset`. This order prevents underflow of the subtraction and closes the vulnerability per CWE-787 C guidance. The function silently rejects writes that would overflow, preserving its original error-handling contract.

## Behaviour changes

None. The function returns silently on invalid parameters, exactly as the original does when `length > capacity`. The fix simply extends the validation to include offset-aware bounds checking. The sink contract (memcpy's behavior on valid inputs) remains unchanged.

