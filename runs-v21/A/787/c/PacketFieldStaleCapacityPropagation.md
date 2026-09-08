## Verdict

Out-of-bounds write is confirmed. The vulnerability stems from a stale capacity propagation in the call chain: `encode_packet` allocates a buffer with `requestedCapacity` bytes but passes `MAX_PACKET_CAPACITY` to `write_field`, causing the bounds validation to be ineffective when the actual allocation is smaller than the stated capacity.

## Source

**File: packet_buffer.c, line 15**

The `encode_packet` function allocates memory based on `requestedCapacity`:
```c
uint8_t *packet = malloc(requestedCapacity);
```

But then invokes `write_field` with the wrong capacity parameter:
```c
write_field(packet, MAX_PACKET_CAPACITY, offset, value, valueLen);
```

When `requestedCapacity < MAX_PACKET_CAPACITY`, the bounds check in `write_field` (which validates against `destCapacity = MAX_PACKET_CAPACITY`) will not detect writes that exceed the actual allocation.

**Data flow:** `requestedCapacity` → `malloc` → buffer allocation, but `MAX_PACKET_CAPACITY` → `write_field` validation mismatch.

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

The fix passes the actual allocated capacity (`requestedCapacity`) to `write_field` instead of `MAX_PACKET_CAPACITY`. This ensures the bounds validation in `write_field` operates on the correct capacity and will reject any write that exceeds the actual buffer size.

When line 6 of `field_writer.c` checks `offset > destCapacity || valueLen > destCapacity - offset`, it now compares against the real allocation size, not an overstated value. Attempts to write beyond the allocated buffer are correctly caught and rejected.
