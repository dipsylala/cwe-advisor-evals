## Verdict

**Confirmed.** Out-of-bounds write via unbounded string concatenation into a stack buffer.

## Source

**Taint source:** `filename` parameter from multipart upload header, untrusted and unvalidated.

**Data flow:**
- `filename` (untrusted, no length bound) → `strcat(path, filename)` (unbounded concatenation)
- `path` is a 128-byte stack buffer initialized with `BASE_DIR "/"` (24 bytes)
- `strcat` appends `filename` with no size parameter, overflowing if filename exceeds ~103 bytes
- The length check on line 22 occurs *after* the overflow has already occurred
- Line 24 compounds the issue by using `strcpy(out, path)` without bounds checking

## Fix

Replace line 20's unbounded `strcat()` with `strlcat()` and check the result for truncation. Replace line 24's unbounded `strcpy()` with `strlcpy()` and check that as well.

**Original vulnerable code:**
```c
strcat(path, filename);

if (strlen(path) >= out_size) {
    return -1;
}

strcpy(out, path);
```

**Fixed code:**
```c
if (strlcat(path, filename, sizeof(path)) >= sizeof(path)) {
    return -1;
}

if (strlcpy(out, path, out_size) >= out_size) {
    return -1;
}
```

## Explanation

`strcat()` has no way to know the destination buffer's size and concatenates blindly. The fix replaces it with `strlcat(dest, src, size)`, which:
- Takes an explicit capacity parameter `size` (pass `sizeof(path)`)
- Returns the total length the concatenated string would occupy
- If the return value is >= `size`, truncation occurred and the operation failed—return -1 to signal this to the caller

Similarly, `strcpy()` is replaced with `strlcpy()` to safely copy the result into the output buffer with the same validation pattern.

By checking the return value and rejecting the operation when truncation would occur, the code avoids silently overflowing the buffer. `strlcat()` and `strlcpy()` are available in glibc 2.38+, BSD, and macOS; on older systems, the portable fallback is `strncpy(dest, src, sizeof(dest) - 1)` followed by `dest[sizeof(dest) - 1] = '\0'`, though this cannot report truncation.

## Behaviour changes

**Input that is safe:** A short filename (under ~103 bytes) continues to work as before—the file path is built and returned successfully.

**Input that was previously dangerous:** A long filename (over ~103 bytes) now causes the function to reject the operation and return -1 instead of overflowing the stack buffer. The caller is signaled that the display path could not be built safely. This is the intended hardening: long or malicious filenames are now safely rejected rather than corrupting the stack.

**Trade-off:** The function now communicates failure by returning -1 when truncation would occur. Callers must check this return value; previously, the overflow occurred silently. This is the correct trade-off: detecting and rejecting an unsafe condition beats silently corrupting memory.
