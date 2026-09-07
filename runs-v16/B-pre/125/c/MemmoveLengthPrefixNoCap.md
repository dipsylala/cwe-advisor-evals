## Verdict
exploitable

## Source
Wire format: a 2-byte big-endian length header at `conn->sourceBuffer[0:2]` followed by `length` bytes of payload. The `length` value is parsed directly from untrusted network input without full bounds validation on the source buffer.

## Fix

**Vulnerable code (line 33):**
```c
    // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
    memmove(destination, conn->sourceBuffer + 2, length);
```

**Fixed code (insert after line 30, before line 33):**
```c
    // Validate that the source buffer contains at least 2 + length bytes
    if (conn->receivedByteCount < 2 + length) {
        return -1;
    }

    memmove(destination, conn->sourceBuffer + 2, length);
```

## Explanation

The code validates that the destination has sufficient capacity (`length <= destinationCapacity`) and that at least 2 bytes were received for the header, but omits a critical check: whether the source buffer actually contains the declared payload. An attacker can craft a message claiming a large payload when fewer bytes were received (e.g., wire says 1000 bytes, but only 50 bytes arrived), causing `memmove()` to read past the end of the received data in `conn->sourceBuffer`. The fix adds an explicit bounds check immediately before the sink to ensure `conn->receivedByteCount >= 2 + length`, preventing the read from exceeding what was actually received.

## Behaviour changes

none
