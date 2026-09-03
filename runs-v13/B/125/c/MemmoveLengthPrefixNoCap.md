## Verdict

Real vulnerability. Out-of-bounds read confirmed at line 33.

## Source

The vulnerability is in the data flow from `conn->receivedByteCount` and the length-prefixed message format:

1. Line 26: A 2-byte big-endian length field is extracted from `conn->sourceBuffer[0..1]`
2. Line 28: The extracted length is validated against `destinationCapacity`
3. Line 33 (sink): `memmove()` reads `length` bytes from `conn->sourceBuffer + 2`

**Missing validation**: The code never checks that `conn->receivedByteCount >= 2 + length`. An attacker can send a message where the length field exceeds the actual bytes received, causing `memmove()` to read past the end of the allocated `sourceBuffer` (line 8).

Example: if `receivedByteCount = 5` but the length field is `0x0010` (16 bytes), memmove will attempt to read 16 bytes starting at offset 2, reading 13 bytes beyond what was actually received.

## Fix

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

    if (2 + length > conn->receivedByteCount) {
        return -1;
    }

    memmove(destination, conn->sourceBuffer + 2, length);

    return (int)length;
}
```

## Explanation

The fix adds an explicit bounds check on line 16-18 (new) that validates the source buffer has at least `2 + length` bytes before the `memmove()` call. This check is performed after the length header is extracted and validated against the destination capacity but immediately before the read operation. The check validates `offset (2) + length` against the actual received byte count, following the CWE-125 C guidance for safe pattern: validate `offset <= buffer_size` first (implicitly true here since offset is constant 2), then `length <= buffer_size - offset`. The order matters: subtraction `conn->receivedByteCount - 2` could underflow if `receivedByteCount < 2`, but we already rejected that case on line 9-10, so the new check is safe against underflow.

## Behaviour changes

- Input: A message where the length prefix exceeds the actual bytes received
- Before fix: Reads past the end of `sourceBuffer` into adjacent memory (CWE-125)
- After fix: Detects the undersized source buffer and returns -1 (same error path as insufficient destination capacity)
- Valid inputs: No change. Messages where length ≤ received bytes are unaffected
- Return values: Returns -1 on source buffer undersize (new error condition). All other returns unchanged
