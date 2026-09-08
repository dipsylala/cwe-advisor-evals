## Verdict

Exploitable. Confidence: high.

## Source

`conn->sourceBuffer[0]` / `conn->sourceBuffer[1]` - the 2-byte big-endian length prefix taken from network-supplied data already landed in `conn->sourceBuffer` (`extract_payload`, line 26). This value is fully attacker-controlled (`uint16_t`, range 0-65535).

Sink: `memmove(destination, conn->sourceBuffer + 2, length)` (line 33), which reads `length` bytes starting at `conn->sourceBuffer + 2`.

Data flow: the length prefix is validated only against `destinationCapacity` (line 28) before reaching the sink. It is never validated against how many bytes were actually placed in `conn->sourceBuffer` (`conn->receivedByteCount`), nor against the buffer's fixed allocation (`MAX_PAYLOAD_SIZE` = 4096). If a caller supplies a `destinationCapacity` of 65535 or more (or any value larger than `conn->receivedByteCount - 2`), a wire message that claims a large `length` but delivered fewer bytes drives `memmove()` to read past the valid data in `sourceBuffer` - and, once `length` exceeds `MAX_PAYLOAD_SIZE - 2` (4094), past the end of the `sourceBuffer` array itself, into adjacent struct memory and beyond.

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

    if (length > destinationCapacity) {
        return -1;
    }

    /* Cap the wire-supplied length against the payload bytes actually
     * received into sourceBuffer, not just against the destination's
     * capacity. Without this, a length header claiming more bytes than
     * were received (up to 65535) drives memmove() past the end of the
     * valid data - and, once length exceeds MAX_PAYLOAD_SIZE - 2, past
     * the end of the sourceBuffer array itself. */
    size_t availablePayloadBytes = conn->receivedByteCount - 2;
    if (length > availablePayloadBytes) {
        return -1;
    }

    memmove(destination, conn->sourceBuffer + 2, length);

    return (int)length;
}
```

## Explanation

The original code clamped `length` only against `destinationCapacity`, bounding the write side of the `memmove()` but leaving the read side unbounded against the actual source data: `conn->receivedByteCount` records how many bytes really arrived in `sourceBuffer`, and nothing compared `length` to it. The fix adds a second clamp, `length > conn->receivedByteCount - 2`, computed after the existing `receivedByteCount < 2` check so the subtraction cannot underflow. This enforces the guidance's "clamp the length to the smaller of the source's available bytes and the destination's capacity" rule on both ends of the copy: `length` can no longer exceed either the caller's buffer or the bytes actually present in `sourceBuffer`, which also keeps it within the fixed `MAX_PAYLOAD_SIZE` allocation, closing the out-of-bounds read.

## Behaviour changes

- Added rejection case: `extract_payload` now returns `-1` when `length > conn->receivedByteCount - 2`, i.e. when the length prefix claims more payload than was actually received. Previously such a call would proceed to `memmove()` and read out-of-bounds/stale memory instead of failing. This is the intended effect of the fix, not incidental - a truncated or malformed message is now rejected rather than read past its real extent.
- No other arguments, return values, or control flow were altered. The success path (`length` bytes copied, `(int)length` returned) is unchanged for any message where the claimed length is actually backed by received data and fits the destination.

Verification: no C compiler (`gcc`, `cl`) was reachable in the environment, so the fix was checked by manual read against the sink contract - `conn`, `destination`, `length`, `availablePayloadBytes`, and `memmove`/`size_t` are all pre-existing symbols or C standard library (`<string.h>`, `<stddef.h>`) already used or included in the original file; no new symbol requires further verification. The added subtraction and comparison follow the same underflow-safe ordering (bound the count that was already checked non-negative, subtract, then compare) used elsewhere in this function.
