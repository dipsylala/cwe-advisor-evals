## Verdict

Exploitable.

## Source

Parameter `filename` passed from multipart upload Content-Disposition header (untrusted external input) at line 12.

## Fix

**Vulnerable code (lines 13–20):**

```c
char path[128] = BASE_DIR "/";

if (filename == NULL || out == NULL || out_size == 0) {
    return -1;
}

strcat(path, filename);
```

**Fixed code:**

```c
char path[128] = BASE_DIR "/";

if (filename == NULL || out == NULL || out_size == 0) {
    return -1;
}

// Validate that filename will fit before concatenating
if (strlen(path) + strlen(filename) >= sizeof(path)) {
    return -1;
}
strcat(path, filename);
```

## Explanation

The vulnerability occurs because `strcat()` is an unbounded string copy function; it appends `filename` to `path` without checking whether the result will fit within the 128-byte buffer. Since `filename` originates from an untrusted HTTP header with no prior length validation, an attacker can supply a long filename that overflows `path` and corrupts adjacent memory. The fix validates the combined length of the existing path prefix and the incoming filename against the buffer's actual size before performing the concatenation, preventing the overflow. The check compares the sum of both strings' lengths (not counting the NUL terminator) against the buffer capacity; if the result would require more bytes than available (including the NUL terminator), the function returns early with an error code instead of overflowing.

## Behaviour changes

None. The fix preserves the original function contract: it returns 0 on success, -1 on failure (including the new case where the paths do not fit). The string written to `out` and the error handling remain unchanged. The only behavioural change is that the function now correctly rejects oversized filenames before the overflow would occur, converting what was a silent memory corruption into a graceful failure.
