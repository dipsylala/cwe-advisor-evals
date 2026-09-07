## Verdict

The CWE-787 finding is valid. The vulnerability occurs because `encode_packet` allocates a buffer with `requestedCapacity` bytes but passes an incorrect, larger capacity constant (`MAX_PACKET_CAPACITY`) to `write_field`. This causes the bounds check in `write_field` to validate against the wrong capacity, allowing writes beyond the actual allocated buffer.

## Source

The vulnerability stems from a mismatch between allocated and validated buffer capacity:

- **packet_buffer.c line 10**: Buffer allocated with `requestedCapacity` bytes
- **packet_buffer.c line 15**: Capacity parameter passed as `MAX_PACKET_CAPACITY` (256) instead of `requestedCapacity`
- **field_writer.c line 6**: Bounds validation uses the passed `destCapacity` parameter
- **field_writer.c line 11**: `memcpy` proceeds with validated-but-stale capacity, writing beyond the allocated buffer

The data flow: caller provides `requestedCapacity` → buffer allocated with that size → wrong capacity passed to `write_field` → validation succeeds falsely → memcpy writes out of bounds.

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

The fix corrects the capacity parameter passed to `write_field` from `MAX_PACKET_CAPACITY` to `requestedCapacity`. This ensures the bounds validation uses the actual allocated buffer capacity, not a stale constant. Now when `write_field` checks whether `offset > destCapacity || valueLen > destCapacity - offset`, it validates against the true buffer size, correctly rejecting writes that exceed the allocated memory.

