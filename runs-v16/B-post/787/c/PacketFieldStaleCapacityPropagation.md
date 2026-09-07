## Verdict

**EXPLOITABLE** — Out-of-bounds write confirmed.

## Source

**File:** `evals/cases/787/c/PacketFieldStaleCapacityPropagation/packet_buffer.c`, line 15  
**Vulnerable call chain:** `encode_packet()` → `write_field()` → `memcpy()`

Data flow: `requestedCapacity` (caller-supplied) → `malloc(requestedCapacity)` → buffer passed to `write_field()` with mismatched capacity claim → bounds check bypassed → out-of-bounds `memcpy()` at line 11 of `field_writer.c`.

## Fix

**File:** `evals/cases/787/c/PacketFieldStaleCapacityPropagation/packet_buffer.c`

**Vulnerable code (line 15):**
```c
write_field(packet, MAX_PACKET_CAPACITY, offset, value, valueLen);
```

**Fixed code:**
```c
write_field(packet, requestedCapacity, offset, value, valueLen);
```

## Explanation

The vulnerability arises from a stale-capacity propagation defect: `encode_packet()` allocates a buffer using `malloc(requestedCapacity)`, but then passes a misleading capacity hint to `write_field()`. It tells `write_field()` that the destination buffer is `MAX_PACKET_CAPACITY` (256 bytes) when the actual allocation may be much smaller (any size up to and including 256, supplied by the caller as `requestedCapacity`).

The bounds check in `write_field()` validates against the claimed capacity (256), not the actual allocation. If `requestedCapacity < MAX_PACKET_CAPACITY` — for example, if a caller allocates only 100 bytes but the check permits a write of the full 256 — the `memcpy()` at line 11 of `field_writer.c` writes past the end of the allocated buffer, corrupting adjacent memory.

The fix passes the actual allocated capacity (`requestedCapacity`) to `write_field()` instead of the constant. This ensures the bounds check in `write_field()` is performed against the real buffer size. When `write_field()` rejects the operation because `offset + valueLen > requestedCapacity`, the write is prevented before it reaches the sink.

## Behaviour changes

- **Before:** Bounds check in `write_field()` allows writes up to 256 bytes; if the actual buffer is smaller, `memcpy()` overwrites adjacent memory.
- **After:** Bounds check in `write_field()` allows writes only up to the actual allocated size; oversized writes are rejected before `memcpy()` is called.
- **Side effects:** None. The function's contract remains unchanged: it still validates offset and length before writing. The only difference is that validation is now performed against the correct capacity.
