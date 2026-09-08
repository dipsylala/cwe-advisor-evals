## Verdict

Out-of-bounds write via insufficient bounds checking. The function validates the length against capacity but fails to validate that offset + length does not exceed the capacity, allowing writes past the buffer boundary.

## Source

**Call chain:**  
`frame_encoder.c::encode_frame()` → `buffer_writer.c::write_payload()`

**Vulnerable sink:**  
`buffer_writer.c` line 10: `memcpy(destination + offset, payload, length);`

**Root cause:**  
The bounds check on line 6 (`if (length > capacity)`) only validates the payload length in isolation. It does not check whether the combination of offset and length exceeds the destination capacity. An attacker-controlled offset can cause the memcpy to write past the allocated buffer.

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

The fix replaces the single length check with two sequential bounds checks that validate the write will remain within the destination's allocated capacity. The first check `offset > capacity` prevents out-of-bounds offset values. The second check `length > capacity - offset` ensures the remaining capacity after the offset is sufficient for the payload. This ordering also prevents integer underflow in the subtraction: if the first condition is true, the second is never evaluated.

The memcpy write at line 10 now only executes when both offset and length are proven to stay within the destination's allocated size.

## Behaviour changes

**Input validation:** The function now rejects writes where `offset > capacity` or `offset + length > capacity`, returning early instead of writing out of bounds.

**No functional regression:** For valid offset and length combinations (those that fit within capacity), behavior is identical to before. The function still performs the memcpy with the same semantics; only invalid inputs are now blocked.
