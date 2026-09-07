## Verdict

Out-of-bounds write confirmed. The bounds check in `write_field()` validates against a hardcoded capacity constant (`MAX_PACKET_CAPACITY`) rather than the actual capacity of the allocated buffer. When the caller allocates a buffer smaller than this constant and passes it along with the constant as the capacity parameter, the check becomes incorrect and allows a write beyond the allocated memory.

## Source

**File:** field_writer.c, line 11  
**Sink:** `memcpy(dest + offset, value, valueLen)`

**Call chain:**
1. `encode_packet()` in packet_buffer.c (line 9) receives `requestedCapacity` from caller
2. Allocates buffer: `packet = malloc(requestedCapacity)` (line 10)
3. Calls `write_field(packet, MAX_PACKET_CAPACITY, offset, value, valueLen)` (line 15)
   - Passes actual buffer address but **incorrect** capacity constant
4. `write_field()` validates offset and length against `MAX_PACKET_CAPACITY` (line 6 in field_writer.c)
5. Performs `memcpy()` assuming bounds are correct (line 11 in field_writer.c)

**Vulnerability:** The bounds check in `write_field()` uses `destCapacity = MAX_PACKET_CAPACITY` (256), but the actual allocated buffer may be much smaller (e.g., if `requestedCapacity = 100`). This allows `offset + valueLen` to exceed the actual buffer size.

**Example:** If `requestedCapacity = 100`, `offset = 50`, `valueLen = 210`:
- Check: `210 > 256 - 50` → `210 > 206` → passes
- Reality: `210 > 100 - 50` → `210 > 50` → should fail
- Result: writes 210 bytes past the 50 available bytes in allocated buffer

## Fix

### File: packet_buffer.c

```c
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_PACKET_CAPACITY 256

void write_field(uint8_t *dest, size_t destCapacity, size_t offset, const uint8_t *value, size_t valueLen);

int encode_packet(size_t requestedCapacity, size_t offset, const uint8_t *value, size_t valueLen) {
    uint8_t *packet = malloc(requestedCapacity);
    if (packet == NULL) {
        return -1;
    }

    write_field(packet, requestedCapacity, offset, value, valueLen);
    free(packet);
    return 0;
}
```

**Change:** Line 15 - pass `requestedCapacity` instead of `MAX_PACKET_CAPACITY` to `write_field()`

## Explanation

The fix propagates the actual allocated capacity to the bounds-checking function. The bounds check in `write_field()` now validates `offset` and `valueLen` against the real buffer size, not a larger constant. This ensures that any write that would exceed the allocated memory is rejected before the `memcpy()` is performed.

The existing bounds check in `write_field()` is correct in structure—it checks `offset <= destCapacity` first, then `valueLen <= destCapacity - offset`—but was receiving the wrong capacity value. By passing `requestedCapacity` (the actual allocation size) instead of `MAX_PACKET_CAPACITY`, the check now enforces the correct invariant: no byte written will fall outside the allocated buffer.

## Behaviour changes

- **Before:** A caller allocating a buffer smaller than `MAX_PACKET_CAPACITY` could trigger an out-of-bounds write without triggering the bounds check.
- **After:** All writes are validated against the actual allocated buffer capacity. An attempt to write data that extends beyond the buffer is rejected and the function returns without writing.
- **No silent truncation:** Unlike functions like `strncpy`, this change rejects rather than truncates, so callers can detect when their write request could not be fully honored.
