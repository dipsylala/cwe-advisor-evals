## Verdict

exploitable

## Source

`filename` parameter from multipart upload Content-Disposition header, passed to the function as untrusted input with no length validation.

## Fix

**Vulnerable code (line 20):**
```c
strcat(path, filename);
```

**Fixed code:**
```c
size_t result = strlcat(path, filename, sizeof(path));

if (result >= sizeof(path) || result >= out_size) {
    return -1;
}
```

The complete corrected function:

```c
int build_upload_display_path(const char *filename, char *out, size_t out_size) {
    char path[128] = BASE_DIR "/";

    if (filename == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    // Safely concatenate with bounds checking
    size_t result = strlcat(path, filename, sizeof(path));
    
    // Reject if filename would overflow path buffer or output buffer
    if (result >= sizeof(path) || result >= out_size) {
        return -1;
    }

    strcpy(out, path);
    return 0;
}
```

## Explanation

The original code uses `strcat(path, filename)` to concatenate an untrusted filename into a fixed 128-byte stack buffer without checking whether the filename fits first. Since `path` starts with `"/srv/uploads/incoming/"` (22 bytes), any filename longer than approximately 106 bytes will overflow the buffer and corrupt adjacent stack memory. The length check that follows (`if (strlen(path) >= out_size)`) comes too late—the overflow has already occurred—and checks against the wrong limit (the output buffer size rather than the path buffer's actual capacity).

The fix replaces `strcat` with `strlcat`, which takes an explicit destination size parameter and returns the total length the string would have needed if it had not been truncated. The code then checks this return value against `sizeof(path)` to detect truncation; if the result is greater than or equal to the buffer size, it means the filename was too long and the concatenation was truncated by `strlcat`. The check is also evaluated against `out_size` to preserve the original function's contract of rejecting paths that don't fit in the output buffer. Both conditions must pass to proceed safely.

## Behaviour changes

**Before truncation detection:** The original code performed an unbounded write and only checked the length afterward, which is ineffective against stack overflow.

**After fix:** The code uses `strlcat` which performs bounded concatenation and reports truncation via its return value. Both the path buffer boundary (128 bytes) and the output buffer size are validated before the copy to `out` proceeds, preventing both the stack overflow and accidental silent truncation of the filename.

The `strcpy` call at line 26 remains as-is because `strlcat` guarantees that `path` will not overflow, and the preceding size checks ensure the result fits within `out_size`, making the strcpy safe.
