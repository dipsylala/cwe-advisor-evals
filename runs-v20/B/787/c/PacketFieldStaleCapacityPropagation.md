## Verdict

exploitable, confidence: high

## Source

`encode_packet(size_t requestedCapacity, size_t offset, const uint8_t *value, size_t valueLen)` in `packet_buffer.c` - `requestedCapacity` (the true size of the buffer that gets allocated), `offset`, `value`, and `valueLen` are all external inputs to this function.

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

## Explanation

`encode_packet` allocates `packet` with exactly `requestedCapacity` bytes via `malloc`, but then calls `write_field` with the unrelated compile-time constant `MAX_PACKET_CAPACITY` (256) as the declared capacity instead of `requestedCapacity`, the value that actually describes how large the buffer is. `write_field`'s own bounds check (`offset > destCapacity || valueLen > destCapacity - offset`) is written correctly and enforces the ordering needed to avoid an underflow, but it can only be as accurate as the capacity it is handed. Whenever `requestedCapacity < MAX_PACKET_CAPACITY` (any allocation smaller than 256 bytes) and the caller-supplied `offset`/`valueLen` fit within 256 but exceed the real allocation, the check passes against the stale constant and `memcpy(dest + offset, value, valueLen)` writes past the end of the heap allocation - a classic heap out-of-bounds write. The fix removes the stale value at the source of the taint by passing the buffer's actual, just-computed size (`requestedCapacity`) into `write_field`, so the bounds check in `field_writer.c` is now validated against the real destination capacity instead of an unrelated constant. `field_writer.c` itself needs no change - its check and sink are already correct given an accurate capacity argument.

## Behaviour changes

- `write_field` is now called with a (generally smaller) `destCapacity` equal to the buffer's real size rather than the constant 256. This tightens the bounds check to match reality; any call that previously succeeded only because the stale, larger constant was used (writing beyond the true allocation) now correctly returns without writing. This is the intended effect of the fix, not a side effect: those cases were the vulnerability. No legitimate write - one where `offset + valueLen` actually fits in the allocated buffer - is affected.
- `MAX_PACKET_CAPACITY` becomes unused after this change; it is left in place since removing an unrelated, still-valid constant is out of scope for this fix and it is a `#define` (unused macros do not produce compiler diagnostics).
- No other arguments, return values, or control flow changed.
- Verification: no C compiler (`gcc`/`clang`/`cc`) was reachable in this environment, so the change was checked by hand. `requestedCapacity` is a pre-existing `size_t` parameter already in scope, matching the type and position of the `destCapacity` parameter it replaces in `write_field`'s prototype (argument 2 of 5). No new identifiers, includes, or calls were introduced, and no other call site or signature changed.
