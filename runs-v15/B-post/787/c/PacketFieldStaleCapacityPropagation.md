## Verdict

Real - Out-of-bounds write via stale capacity validation.

## Source

**File:** `packet_buffer.c`, line 15  
**Call chain:** `encode_packet()` → `write_field()` → `memcpy()` at field_writer.c:11

The `encode_packet` function allocates a buffer with `requestedCapacity` bytes but passes `MAX_PACKET_CAPACITY` (a compile-time constant of 256) to `write_field` as the capacity parameter. If `requestedCapacity < MAX_PACKET_CAPACITY`, the validation check in `write_field` will pass when it should fail, allowing the `memcpy` to write past the end of the actual allocated buffer.

## Fix

**In packet_buffer.c (line 15):**

Replace:
```c
write_field(packet, MAX_PACKET_CAPACITY, offset, value, valueLen);
```

With:
```c
write_field(packet, requestedCapacity, offset, value, valueLen);
```

## Explanation

The vulnerability occurs because the capacity parameter passed to `write_field` does not reflect the actual size of the allocated buffer. The `write_field` function's bounds check compares the offset and value length against the provided capacity; if that capacity is larger than the actual allocation, the check passes and permits writes that exceed the buffer's bounds.

The fix ensures that `write_field` receives the true allocated capacity (`requestedCapacity`), allowing its validation at line 6 to correctly reject writes that would overflow. The condition `offset > destCapacity || valueLen > destCapacity - offset` will now properly enforce that the write stays within the actual buffer's bounds.

## Behaviour changes

- `write_field` now receives the accurate allocated buffer size instead of a fixed maximum size.
- Writes that exceed the actual buffer capacity will now be rejected (the function returns early) rather than proceeding to an out-of-bounds `memcpy`.
- Applications that were relying on allocating small buffers while using `MAX_PACKET_CAPACITY` for validation will now see their writes rejected if they attempt to write more data than their buffer can hold.
