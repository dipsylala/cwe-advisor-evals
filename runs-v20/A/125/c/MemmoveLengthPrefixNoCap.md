## Verdict

Confirmed. The length prefix read from `conn->sourceBuffer` is validated only against the caller-supplied `destinationCapacity`, never against how many bytes were actually placed in `conn->sourceBuffer` (`conn->receivedByteCount`) or against the fixed size of that array (`MAX_PAYLOAD_SIZE`). If a caller passes a `destinationCapacity` larger than `MAX_PAYLOAD_SIZE`, or if fewer bytes were actually received than the header claims, `memmove` reads past the end of `sourceBuffer` (and potentially past the end of the `connection_t` struct), producing an out-of-bounds read (CWE-125).

## Source

- Tainted value: `length`, derived from the two-byte big-endian header at `conn->sourceBuffer[0..1]`. This buffer is attacker-controlled network input already landed by the caller before `extract_payload` runs.
- Sink: `memmove(destination, conn->sourceBuffer + 2, length)` at line 33, which reads `length` bytes starting at `conn->sourceBuffer + 2`.
- Missing check: `length` is bounds-checked only against `destinationCapacity` (the write side). It is never checked against `conn->receivedByteCount` (how many bytes of `sourceBuffer` are actually valid/populated) or against the physical size of `sourceBuffer` (`MAX_PAYLOAD_SIZE`). A caller with a large `destinationCapacity`, or a `receivedByteCount` smaller than `2 + length`, lets the read run past the valid (or physical) extent of `sourceBuffer`.

## Fix

### File: MemmoveLengthPrefixNoCap.c

```c
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define MAX_PAYLOAD_SIZE 4096

typedef struct {
    unsigned char sourceBuffer[MAX_PAYLOAD_SIZE];
    size_t receivedByteCount; /* how many bytes actually arrived in sourceBuffer */
} connection_t;

/*
 * Extracts the payload from a length-prefixed message that has already
 * landed in conn->sourceBuffer. The wire format is a 2-byte big-endian
 * length header followed immediately by that many bytes of payload.
 */
int extract_payload(connection_t *conn, unsigned char *destination, size_t destinationCapacity) {
    if (conn == NULL || destination == NULL) {
        return -1;
    }

    if (conn->receivedByteCount < 2) {
        return -1;
    }

    uint16_t length = (uint16_t)((conn->sourceBuffer[0] << 8) | conn->sourceBuffer[1]);

    /* The payload must fit both in the caller's destination buffer and
     * within the bytes actually received into sourceBuffer. Checking only
     * destinationCapacity allows length to exceed the data that is really
     * present (or even the physical size of sourceBuffer), causing
     * memmove to read out of bounds. */
    size_t availablePayload = conn->receivedByteCount - 2;

    if (length > destinationCapacity || (size_t)length > availablePayload) {
        return -1;
    }

    memmove(destination, conn->sourceBuffer + 2, length);

    return (int)length;
}
```

## Explanation

The original code bounded `length` only by `destinationCapacity`, which constrains the write side of the copy but says nothing about the read side. `conn->sourceBuffer` is a fixed 4096-byte array, and only `conn->receivedByteCount` bytes of it hold data that actually arrived on the wire; anything beyond that is either uninitialized or, if `2 + length` exceeds `MAX_PAYLOAD_SIZE`, entirely outside the array. Since `destinationCapacity` is caller-supplied and can legitimately be larger than `MAX_PAYLOAD_SIZE`, an attacker who controls the two-byte length header can set `length` up to `destinationCapacity - 1` (or up to 65535), causing `memmove` to read from `conn->sourceBuffer + 2` for more bytes than were ever written into that buffer - an out-of-bounds read that can disclose adjacent memory (e.g., the `receivedByteCount` field or data past the struct) into `destination`.

The fix adds a second bound: `length` must also not exceed `conn->receivedByteCount - 2`, the number of payload bytes actually present after the header. This subtraction is safe because the preceding `conn->receivedByteCount < 2` check guarantees `receivedByteCount >= 2`. With both checks in place, `memmove` can never read past the region of `sourceBuffer` that was genuinely populated, and by construction that region never exceeds `MAX_PAYLOAD_SIZE`, so both the logical (uninitialized-read) and physical (array-bounds) failure modes are closed without changing the function's signature or its success-path behavior for legitimate, fully-received messages.
