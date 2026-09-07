## Verdict
The out-of-bounds read is confirmed. The function extracts a length value from the source buffer and then attempts to read that many bytes without verifying the source buffer contains enough bytes to satisfy the read.

## Source
Line 33 performs `memmove(destination, conn->sourceBuffer + 2, length)` where `length` is extracted from the first two bytes of the source buffer. The check at lines 22-24 only confirms that at least 2 bytes have been received (to read the length header), but the check at lines 28-30 only validates that the destination buffer is large enough—it does not validate that the source buffer has received enough bytes to provide `length` bytes starting at offset 2.

An attacker who sends a length-prefixed message with a length value larger than the data actually transmitted causes `memmove` to read beyond the populated region of `conn->sourceBuffer`, resulting in an out-of-bounds read.

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

    /* Verify the source buffer has received the complete message: 2-byte header plus payload */
    if (conn->receivedByteCount < 2 + length) {
        return -1;
    }

    memmove(destination, conn->sourceBuffer + 2, length);

    return (int)length;
}
```

## Explanation
The fix adds a bounds check at lines 33-35 to verify that `conn->receivedByteCount` includes both the 2-byte length header and the full payload. The expression `2 + length` calculates the minimum number of bytes that must have been received.

Without this check, the `memmove` at line 36 could read beyond the initialized region of `sourceBuffer` if the wire protocol sends a length value larger than the actual payload transmitted. By validating that enough bytes have been received before reading, the function prevents the out-of-bounds read and safely returns an error code if the message is incomplete.
