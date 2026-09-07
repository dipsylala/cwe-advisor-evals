## Verdict
exploitable

## Source
The `length` parameter passed by the caller to `send_response_slice()`, combined with the unchecked `offset` parameter.

## Fix

**Vulnerable code:**
```c
ssize_t send_response_slice(const unsigned char *buffer, size_t buffer_len, size_t offset, size_t length)
{
    if (offset > buffer_len) {
        return -1;
    }

    // CWE-125: No check that offset + length does not exceed buffer_len
    return socket_send(buffer + offset, length);
}
```

**Fixed code:**
```c
ssize_t send_response_slice(const unsigned char *buffer, size_t buffer_len, size_t offset, size_t length)
{
    if (offset > buffer_len) {
        return -1;
    }

    // CWE-125: Verify that offset + length does not exceed buffer_len
    if (length > buffer_len - offset) {
        return -1;
    }

    return socket_send(buffer + offset, length);
}
```

## Explanation
The original code checks whether the offset is within bounds but fails to verify that the requested `length` bytes from that offset do not read past the end of the buffer. An attacker who controls the `length` parameter can craft a value that, when added to a valid `offset`, exceeds `buffer_len`, causing `socket_send()` to read beyond the allocated buffer. The fix adds a second bounds check: `length > buffer_len - offset`, evaluated after confirming `offset <= buffer_len` to prevent underflow in the subtraction. This ensures that the sum `offset + length` never exceeds the buffer's actual size.

## Behaviour changes
The function now returns `-1` when the requested `length` exceeds the readable range from `offset` onward, rather than proceeding to `socket_send()` with an oversized read. This prevents the out-of-bounds read but changes the return value for this error case from whatever `socket_send()` would return to `-1`. No other changes to the sink contract or caller expectations.
