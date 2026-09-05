## Verdict

Exploitable

## Source

The `requestedCapacity` parameter passed to `encode_packet()` (packet_buffer.c, line 9) is not validated and controls the heap allocation size at line 10. The caller allocates a buffer of exactly `requestedCapacity` bytes via `malloc()`.

## Fix

**Vulnerable code** (packet_buffer.c, line 15):
```c
write_field(packet, MAX_PACKET_CAPACITY, offset, value, valueLen);
```

**Fixed code** (packet_buffer.c, line 15):
```c
write_field(packet, requestedCapacity, offset, value, valueLen);
```

## Explanation

The vulnerability stems from a stale capacity parameter. The `encode_packet()` function allocates a buffer of exactly `requestedCapacity` bytes (line 10), but then calls `write_field()` with `MAX_PACKET_CAPACITY` (a constant 256) as the destination capacity argument. This mismatch causes the bounds check in `write_field()` (lines 6–7 of field_writer.c) to validate the write against 256 bytes even when the actual buffer might be smaller. If `requestedCapacity < MAX_PACKET_CAPACITY`, an attacker can supply values for `offset` and `valueLen` that pass the stale validation but write beyond the allocated buffer.

The fix passes the actual allocated capacity `requestedCapacity` to `write_field()`, ensuring the bounds check is performed against the real buffer size. This closes the out-of-bounds write path.

## Behaviour changes

None. The function's signature, return value, and calling contract remain unchanged. Only the second argument to `write_field()` is corrected to reflect the actual buffer capacity, which the bounds-checking logic in `write_field()` requires in order to function safely.
