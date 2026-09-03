## Verdict

exploitable

## Source

Line 26: `uint16_t length = (uint16_t)((conn->sourceBuffer[0] << 8) | conn->sourceBuffer[1]);` — the message length field extracted from untrusted network input. `conn->sourceBuffer` and `conn->receivedByteCount` are provided by the caller and represent data that has arrived from the network.

## Fix

**Vulnerable code (line 28-33):**
```c
if (length > destinationCapacity) {
    return -1;
}

// SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
memmove(destination, conn->sourceBuffer + 2, length);
```

**Fixed code:**
```c
if (length > destinationCapacity) {
    return -1;
}

if (2 + length > conn->receivedByteCount) {
    return -1;
}

memmove(destination, conn->sourceBuffer + 2, length);
```

## Explanation

The vulnerability is a missing bounds check on the source buffer. The code validates that the declared message length fits into the destination buffer, but does not validate that the source buffer (`conn->sourceBuffer`) actually contains that many bytes. An attacker who controls the wire format can send a length field claiming 1000 bytes while the actual payload contains only 5 bytes; when `memmove()` is called, it reads 1000 bytes starting from `sourceBuffer + 2`, exceeding the actual received data and reading into adjacent memory. The fix adds an explicit check that the sourceBuffer contains at least `2 + length` bytes (the 2-byte header plus the declared payload) before attempting the copy. This prevents the out-of-bounds read by rejecting oversized length claims.

## Behaviour changes

None. The memmove call's contract is preserved: destination capacity is still validated, the same payload is copied when both bounds checks pass, and the function returns -1 on error exactly as before.
