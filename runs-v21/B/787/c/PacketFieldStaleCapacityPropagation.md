## Verdict

Exploitable

## Source

The vulnerability originates in `encode_packet()` at `packet_buffer.c` line 15. The function allocates a buffer with `malloc(requestedCapacity)`, creating a buffer whose actual capacity is the value of the `requestedCapacity` parameter. However, when calling `write_field()`, the function passes a hard-coded constant `MAX_PACKET_CAPACITY` (256) as the `destCapacity` parameter instead of passing the actual allocated capacity.

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

The vulnerability is a stale capacity propagation defect. In the original code, `encode_packet()` allocates a buffer via `malloc(requestedCapacity)` but then passes `MAX_PACKET_CAPACITY` to `write_field()` as the destination's capacity. When `requestedCapacity` is smaller than `MAX_PACKET_CAPACITY` (e.g., 100 vs. 256), `write_field()` performs bounds checks against the claimed capacity of 256, not the actual allocated size of 100. An attacker can provide an offset and value length that pass this incorrect bounds check but exceed the real buffer, causing `memcpy()` to write past the allocation boundary.

The fix changes line 15 to pass `requestedCapacity` instead of the hard-coded `MAX_PACKET_CAPACITY`. This ensures that the bounds check inside `write_field()` operates against the true allocated size, preventing out-of-bounds writes when the requested capacity is smaller than the constant.

## Behaviour changes

None. The change passes the actual allocated buffer size instead of a hard-coded constant, which is the correct and intended behaviour. The `write_field()` function's contract is preserved: it receives the pointer and its real capacity, and uses them to perform a safe bounds check before copying. No other parameters, return values, or side effects change.

