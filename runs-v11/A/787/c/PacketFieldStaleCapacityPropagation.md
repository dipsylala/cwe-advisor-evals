## Verdict

CWE-787 confirmed. A mismatch between allocated buffer size and the capacity argument passed to the bounds-checking function allows out-of-bounds writes.

## Source

In `packet_buffer.c`, the function `encode_packet()` allocates a buffer with size `requestedCapacity` but then calls `write_field()` with `MAX_PACKET_CAPACITY` as the capacity argument. The `write_field()` function in `field_writer.c` performs bounds validation against the passed capacity, not the actual allocation. If `requestedCapacity < MAX_PACKET_CAPACITY`, the validation passes but the subsequent `memcpy` at line 11 writes beyond the allocated buffer.

## Fix

In `packet_buffer.c`, line 15, change the call to `write_field()` from:

```
write_field(packet, MAX_PACKET_CAPACITY, offset, value, valueLen);
```

to:

```
write_field(packet, requestedCapacity, offset, value, valueLen);
```

This ensures the capacity argument passed to `write_field()` matches the actual allocated buffer size, so the bounds check correctly validates against the true allocation limit.

## Explanation

The vulnerability is a stale capacity propagation: the `encode_packet()` function allocates memory based on `requestedCapacity` but then lies to `write_field()` about the actual capacity, claiming it is `MAX_PACKET_CAPACITY` instead. The bounds check in `write_field()` is logically sound, but operates against incorrect input. By passing the true allocated size, the validation becomes accurate and prevents writes beyond the allocated memory region.
