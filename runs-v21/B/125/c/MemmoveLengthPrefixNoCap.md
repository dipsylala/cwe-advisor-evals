## Verdict

Out-of-bounds read confirmed. The code validates the destination buffer's capacity but fails to validate that the source buffer contains enough bytes to satisfy the untrusted length field decoded from the wire format. An attacker can craft a message with a length prefix claiming more bytes than were actually received, causing memmove to read past the end of sourceBuffer.

## Source

Line 33 in MemmoveLengthPrefixNoCap.c: `memmove(destination, conn->sourceBuffer + 2, length);`

The vulnerability is in the data flow:
1. Line 26: `uint16_t length = (uint16_t)((conn->sourceBuffer[0] << 8) | conn->sourceBuffer[1]);` — untrusted length decoded from wire format
2. Line 28: `if (length > destinationCapacity) return -1;` — validates destination capacity only
3. **Missing**: No validation that `length <= (conn->receivedByteCount - 2)` — the actual available bytes in the source buffer
4. Line 33: `memmove(destination, conn->sourceBuffer + 2, length);` — reads `length` bytes from source without bounds check

The check at line 22 (`if (conn->receivedByteCount < 2) return -1;`) only ensures the header exists, not that the payload follows.

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

    if (length > (conn->receivedByteCount - 2)) {
        return -1;
    }

    memmove(destination, conn->sourceBuffer + 2, length);

    return (int)length;
}
```

## Explanation

The fix adds a bounds check at line 31-33 (immediately before the memmove at line 35) to validate that the untrusted length field does not claim more bytes than are actually available in sourceBuffer after the 2-byte header.

The check `if (length > (conn->receivedByteCount - 2))` ensures that:
- The subtraction `(conn->receivedByteCount - 2)` is safe because we already validated `conn->receivedByteCount >= 2` at line 22
- The length is clamped to the source buffer's actual available bytes
- The memmove will never read past the end of sourceBuffer

This follows the C-specific CWE-125 guidance: validate offset and length against the buffer's actual size before every read, and check bounds immediately before the sink in the same function.

## Behaviour changes

**Input handling**: The function now correctly rejects messages where the length prefix claims more bytes than the message actually contains. Previously, these would pass the destination-capacity check and proceed to an out-of-bounds read.

**Return value**: On success, still returns the payload length. On error (including the new bounds violation), still returns -1, matching the existing error contract.

**Memory safety**: Eliminates the out-of-bounds read condition. The memmove call now has a guaranteed-safe bound on its length operand.

**No semantic change to valid inputs**: Correctly-formed messages (where the declared length matches the actual received bytes) behave identically before and after the fix.
