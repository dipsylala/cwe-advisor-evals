## Verdict

Confirmed. `encode_packet` allocates `requestedCapacity` bytes with `malloc`, but calls `write_field` with the compile-time constant `MAX_PACKET_CAPACITY` (256) as the destination capacity instead of `requestedCapacity`. `write_field`'s own bounds check (`offset > destCapacity || valueLen > destCapacity - offset`) is correctly formed, but it validates against a capacity value that does not match the actual allocation. When `requestedCapacity < 256`, a write that satisfies the check against 256 can still write past the end of the real, smaller `packet` allocation, producing an out-of-bounds heap write in `memcpy` at `field_writer.c:11`.

## Source

`requestedCapacity`, `offset`, `value`, and `valueLen` are parameters to `encode_packet` in `packet_buffer.c`, i.e. attacker/caller-controlled inputs from outside this translation unit. `requestedCapacity` determines the true allocation size via `malloc(requestedCapacity)`. The taint flows from `requestedCapacity` (source, defines real buffer size) into the mismatched constant `MAX_PACKET_CAPACITY` used as `destCapacity` at the `write_field` call site, and separately `offset`/`value`/`valueLen` flow unchanged into `write_field`'s bounds check and the `memcpy` sink.

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

The vulnerability is not in `write_field`'s check formula: `offset > destCapacity || valueLen > destCapacity - offset` is the correct paired offset/length validation for whatever `destCapacity` it is told about, and it correctly rejects any write that would exceed that stated capacity. The defect is that `encode_packet` tells it the wrong capacity. `packet` is allocated with exactly `requestedCapacity` bytes via `malloc`, but the capacity value passed to `write_field` is the unrelated compile-time constant `MAX_PACKET_CAPACITY` (256). Whenever a caller passes `requestedCapacity < 256` (a perfectly valid, common case — e.g. a small packet), `write_field` validates `offset`/`valueLen` against a capacity larger than the buffer that actually exists, so a write that is invalid for the real allocation can still pass the check and `memcpy` writes past the end of the heap block.

The fix changes only the argument at the call site in `encode_packet`: pass `requestedCapacity` (the size actually given to `malloc`) instead of `MAX_PACKET_CAPACITY`. This does not touch `write_field.c` at all, because tightening or re-deriving the bounds check inside `write_field` cannot fix a caller passing the wrong capacity value in the first place — the check is only as sound as the capacity it is given. With the fix, `write_field` now validates `offset`/`valueLen` against the buffer's true size, so any write that fits inside the actual `requestedCapacity`-byte allocation still succeeds, and any write that would exceed it is still rejected by the existing check and the function returns without writing, exactly as before, but now correctly for every value of `requestedCapacity` rather than only for values equal to `MAX_PACKET_CAPACITY`.
