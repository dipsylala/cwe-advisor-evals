## Verdict

Confirmed exploitable out-of-bounds write. The vulnerability stem from two defects: (1) `encode_packet()` passes a hardcoded capacity constant (`MAX_PACKET_CAPACITY`) to `write_field()` instead of the actual allocated capacity, causing bounds checks to pass when they should fail; (2) `write_field()` has an off-by-one error in its boundary check (`offset > destCapacity` instead of `offset >= destCapacity`), allowing writes at the end of the buffer.

## Source

In `packet_buffer.c`, the `encode_packet()` function allocates a buffer with caller-controlled size (`requestedCapacity`) but unconditionally passes the hardcoded constant `MAX_PACKET_CAPACITY` (256) to `write_field()` as the capacity parameter. This stale capacity value causes the bounds check in `write_field()` to validate against an incorrect capacity.

If `requestedCapacity < MAX_PACKET_CAPACITY`, the attacker can craft an offset and valueLen that pass the incorrect check but write beyond the actual allocated buffer size.

In `field_writer.c`, the bounds check uses strict `>` comparison instead of `>=`, allowing offset to equal destCapacity (pointing one byte past the end of the buffer). When combined with the stale capacity issue, this enables out-of-bounds writes.

## Fix

### File: field_writer.c

```c
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void write_field(uint8_t *dest, size_t destCapacity, size_t offset, const uint8_t *value, size_t valueLen) {
    if (offset >= destCapacity || valueLen > destCapacity - offset) {
        return;
    }

    memcpy(dest + offset, value, valueLen);
}
```

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

The fix addresses the two-part vulnerability: 

1. **Stale Capacity Propagation** (packet_buffer.c): Changed the third argument to `write_field()` from `MAX_PACKET_CAPACITY` to `requestedCapacity`. This ensures the bounds check in `write_field()` validates against the actual allocated buffer size, not a hardcoded maximum. The capacity passed to `write_field()` must match the real allocated size or the check cannot be trusted.

2. **Boundary Check Off-by-One** (field_writer.c): Changed the condition from `offset > destCapacity` to `offset >= destCapacity`. For a buffer of size `destCapacity`, valid write offsets are 0 through `destCapacity - 1`. An offset equal to `destCapacity` points one byte past the end and must be rejected. The corrected check ensures no write can begin at or beyond the buffer's end boundary.

The second check (`valueLen > destCapacity - offset`) correctly validates that the write does not extend past the end, but it depends on the first check catching boundary offsets.

## Behaviour changes

- Calls to `write_field()` with `offset >= destCapacity` now correctly return without performing a write, even when `valueLen == 0` (previously allowed).
- The `encode_packet()` function now enforces the actual allocated size as the constraint, so requests with `offset + valueLen > requestedCapacity` are rejected instead of accepted.
- No change to successful write operations: writes with `offset < destCapacity` and `offset + valueLen <= destCapacity` continue to complete as before.
- Return value of `write_field()` is still `void` (no change).
- The `encode_packet()` function's return value is still 0 or -1 for allocation success/failure (no change).
