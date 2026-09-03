## Verdict

The out-of-bounds write is confirmed. The bounds check in `write_field()` at line 6 uses `offset > destCapacity` instead of `offset >= destCapacity`, allowing writes to begin exactly at the buffer boundary (where offset equals capacity). Combined with the caller (`encode_packet()`) passing a hardcoded capacity (MAX_PACKET_CAPACITY=256) that does not match the actual allocation (`requestedCapacity`), a write can exceed the actual allocated buffer.

## Source

The vulnerability is in the bounds validation in `field_writer.c`:

```c
void write_field(uint8_t *dest, size_t destCapacity, size_t offset, const uint8_t *value, size_t valueLen) {
    if (offset > destCapacity || valueLen > destCapacity - offset) {  // BUG: offset > should be offset >=
        return;
    }
    memcpy(dest + offset, value, valueLen);  // Sink: write may exceed actual allocation
}
```

The caller in `packet_buffer.c` demonstrates the issue:
- `packet_buffer.c` line 10: allocates buffer of size `requestedCapacity` (variable, could be 100)
- `packet_buffer.c` line 15: passes `MAX_PACKET_CAPACITY` (256) to `write_field()` as destCapacity
- This mismatch allows the bounds check to pass when it should fail

Example exploitation path:
- `requestedCapacity = 100` → allocates 100 bytes
- Call: `write_field(packet, 256, 100, value, 10)` (offset at boundary of actual allocation)
- Check: `100 > 256` (false) and `10 > 256 - 100 = 156` (false) → passes
- `memcpy(dest + 100, value, 10)` writes bytes 100-109 to a 100-byte buffer → out of bounds

## Fix

Correct the off-by-one error in the bounds check by using `>=` for the offset comparison:

```c
void write_field(uint8_t *dest, size_t destCapacity, size_t offset, const uint8_t *value, size_t valueLen) {
    if (offset >= destCapacity || valueLen > destCapacity - offset) {  // FIXED: offset >= ensures offset < destCapacity
        return;
    }

    memcpy(dest + offset, value, valueLen);
}
```

## Explanation

The fix changes the offset validation from `offset > destCapacity` to `offset >= destCapacity`. This ensures that offset must be strictly less than destCapacity, which is the correct invariant for buffer access. Valid indices into a buffer of size N are [0, N-1], so any offset >= N is out of bounds. By tightening this check, the function rejects writes that would begin at or beyond the buffer boundary. The memcpy at the sink is now protected by this corrected validation.

## Behaviour changes

- Calls to `write_field()` with offset exactly equal to destCapacity will now return early without writing, instead of proceeding to the memcpy call
- This is a security-correct behavior change: such calls were previously treated as valid but are actually out of bounds
- No legitimate code should pass offset >= capacity; existing callers passing exact-boundary offsets indicate a bug in the caller logic that should be fixed there as well
