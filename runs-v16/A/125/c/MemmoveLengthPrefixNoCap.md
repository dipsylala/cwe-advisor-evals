## Verdict
Confirmed: Out-of-bounds read in memmove on line 33.

## Source
```c
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

    // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
    memmove(destination, conn->sourceBuffer + 2, length);

    return (int)length;
}
```

## Fix
Add a bounds check for the source buffer before the memmove call:

```c
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

    /* Validate source buffer has enough bytes: 2-byte header + payload */
    if (2 + length > conn->receivedByteCount) {
        return -1;
    }

    memmove(destination, conn->sourceBuffer + 2, length);

    return (int)length;
}
```

## Explanation
The vulnerability exists because the code validates that the destination buffer can hold the claimed payload length, but fails to validate that the source buffer actually contains that many bytes.

The wire format specifies:
- Bytes 0-1: 2-byte big-endian length header
- Bytes 2 onwards: payload data (length bytes)

The original code checks:
- `conn->receivedByteCount >= 2` (header exists)
- `length <= destinationCapacity` (destination is large enough)

But does not check:
- `conn->receivedByteCount >= 2 + length` (source contains full payload)

If an attacker sends a message with a length field larger than the actual received data, memmove reads beyond the allocated sourceBuffer, causing an out-of-bounds read.

The fix adds an explicit bounds check: `if (2 + length > conn->receivedByteCount)` before calling memmove. This ensures the source buffer contains both the 2-byte header and the full payload before attempting to copy it, closing the vulnerability.
