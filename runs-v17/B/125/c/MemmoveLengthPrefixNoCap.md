## Verdict

The CWE-125 finding is correct. The code validates the destination buffer's capacity but fails to validate that the source buffer contains sufficient data before reading from it.

## Source

The vulnerability is in the `extract_payload()` function at line 33. While the code ensures `length` does not exceed `destinationCapacity`, it does not verify that `conn->receivedByteCount` actually contains a full 2-byte header plus `length` bytes of payload.

An attacker controlling the wire protocol can send a 2-byte length prefix (e.g., 5000) followed by fewer than 5000 actual bytes. The code checks only that the destination can hold 5000 bytes, then attempts to read 5000 bytes from a buffer that may contain only 100 bytes, causing an out-of-bounds read from the source buffer.

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

    /* Validate that source buffer has enough bytes: 2-byte header + payload */
    if (conn->receivedByteCount < 2 + length) {
        return -1;
    }

    memmove(destination, conn->sourceBuffer + 2, length);

    return (int)length;
}
```

## Explanation

The fix adds an explicit bounds check immediately before the `memmove()` to ensure the source buffer contains at least 2 bytes (for the header) plus the full payload length. This check validates that `conn->receivedByteCount >= 2 + length` before attempting to read from `conn->sourceBuffer + 2`.

Per CWE-125 C guidance: "Never pass an attacker-supplied or miscalculated size directly to `memcpy()` or `memmove()`; clamp it against both the source's actual available bytes and the destination's capacity first." The original code validated the destination capacity but not the source availability. The fix adds the source-side validation.

## Behaviour changes

- **Before:** A message with a length prefix exceeding the actual received byte count would cause an out-of-bounds read from the source buffer.
- **After:** Such messages are rejected with a return value of -1, preventing the out-of-bounds read.

For valid messages where `receivedByteCount >= 2 + length`, the function behaves identically to the original.
