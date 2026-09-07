## Verdict

Confirmed exploitable out-of-bounds read. The function validates that the payload length fits in the destination buffer (line 28) but fails to validate that the complete payload has actually been received in the source buffer. If the wire format claims N bytes of payload but the connection has received fewer than N bytes, `memmove()` at line 33 reads past the end of `sourceBuffer`.

## Source

- **Location**: `evals/cases/125/c/MemmoveLengthPrefixNoCap/MemmoveLengthPrefixNoCap.c`, line 26–33
- **Source of untrusted data**: `conn->sourceBuffer[0]` and `conn->sourceBuffer[1]` (wire-provided 2-byte big-endian length)
- **Buffer being read**: `conn->sourceBuffer` at offset 2 (the payload region)
- **Data flow**: The function parses the length header and derives the payload size from untrusted wire data. The length is checked against `destinationCapacity` but not against the actual number of bytes received in `sourceBuffer`. The `memmove()` uses this unchecked length to read from `sourceBuffer + 2`, which may extend past the received data.

## Fix

Add an explicit bounds check to ensure the complete payload (header plus declared length) is present before reading:

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

    // Bounds check: ensure the complete payload has been received.
    // Header is 2 bytes, so payload starts at offset 2.
    // Validate that offset 2 + length does not exceed receivedByteCount.
    if (length > conn->receivedByteCount - 2) {
        return -1;
    }

    memmove(destination, conn->sourceBuffer + 2, length);

    return (int)length;
}
```

**Check:** The added validation enforces the C language guidance principle: "Validate `offset <= buffer_size` first, then `length <= buffer_size - offset`". Here, `offset = 2`, `length` comes from untrusted input, and `buffer_size = conn->receivedByteCount`. The new check `length <= conn->receivedByteCount - 2` ensures the payload region does not extend beyond the allocated/received buffer, preventing the out-of-bounds read. This check is performed immediately before the `memmove()` call that performs the read, in the same function, as required.

## Explanation

The original code validates the payload length against the destination buffer capacity but omits a critical check: whether the source data actually contains all the bytes it claims to. In a length-prefixed protocol, a malformed or incomplete message could declare a payload length larger than the number of bytes actually present in the source buffer. When `memmove()` is called with that oversized length, it reads past the end of `sourceBuffer`, disclosing uninitialized or adjacent memory.

The fix adds an underflow-safe bounds check before the `memmove()`. The check verifies that `length <= conn->receivedByteCount - 2`, ensuring that starting at offset 2 and reading `length` bytes does not exceed the received buffer's actual size. The subtraction `conn->receivedByteCount - 2` is safe here because the earlier check at line 22 guarantees that `conn->receivedByteCount >= 2`.

This follows the C language guidance: never pass an attacker-supplied or miscalculated size directly to `memcpy()` or `memmove()` without first clamping it against the source's actual available bytes. The validation is placed immediately before the sink, in the same function that performs the read.

## Behaviour changes

- **New control flow**: If the wire-provided payload length exceeds the number of bytes actually received, the function now returns -1 (error) instead of reading out-of-bounds. This is semantically correct: a complete message has not arrived, so the extraction fails.
- **Return value**: No change to the return contract; -1 already means extraction failed. A successful extraction still returns the payload length as before.
- **Buffer invariant**: The `memmove()` now respects the guarantee that the source and destination buffers are not overread/overwritten beyond their respective capacities. The function upholds the invariant that `length <= conn->receivedByteCount - 2` and `length <= destinationCapacity` before performing the copy.
- **Performance**: Negligible; one additional subtraction and comparison before a memory operation.
- **Error handling for callers**: Callers already handle the -1 return code (e.g., line 19 and 23 return -1 on validation failure), so no change required to calling code.
