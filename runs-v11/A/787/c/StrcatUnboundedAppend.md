## Verdict

The vulnerability is **confirmed**. Line 20 uses `strcat(path, filename)` to append untrusted, length-unchecked user input to a fixed-size buffer. The bounds check on line 22 happens after the write, leaving a window where stack-allocated `path` (128 bytes) can be overflowed if `filename` exceeds approximately 107 bytes (accounting for `BASE_DIR "/" ` prefix). Additionally, line 26 copies the potentially overflowed `path` to the output buffer.

## Source

The vulnerability originates in the `filename` parameter, which the function comment explicitly states comes from an HTTP multipart upload header without length validation. An attacker can supply a Content-Disposition header with an arbitrarily long filename to trigger the overflow.

The sink is line 20: `strcat(path, filename)`, where user-controlled data is written to a fixed-size stack buffer without bounds checking.

A secondary sink is line 26: `strcpy(out, path)`, which copies potentially corrupted data further.

## Fix

Replace the unsafe string concatenation and copying operations with bounds-safe alternatives. The most direct fix:

```c
int build_upload_display_path(const char *filename, char *out, size_t out_size) {
    char path[128] = BASE_DIR "/";

    if (filename == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    // Calculate remaining space in path buffer after BASE_DIR "/"
    size_t path_len = strlen(path);  // strlen("BASE_DIR /") = 19
    size_t remaining = sizeof(path) - path_len - 1;  // -1 for null terminator

    // Use strncat with calculated size limit
    if (strlen(filename) > remaining) {
        return -1;
    }
    strncat(path, filename, remaining);

    // Validate path fits in output buffer
    if (strlen(path) >= out_size) {
        return -1;
    }

    // Use strncpy to safely copy to output
    strncpy(out, path, out_size - 1);
    out[out_size - 1] = '\0';
    return 0;
}
```

Alternatively, use `snprintf` for the initial concatenation, which is more concise:

```c
int build_upload_display_path(const char *filename, char *out, size_t out_size) {
    char path[128];

    if (filename == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    // snprintf safely constructs the path with bounds checking
    int ret = snprintf(path, sizeof(path), "%s/%s", BASE_DIR, filename);
    if (ret < 0 || (size_t)ret >= sizeof(path)) {
        return -1;  // Path too long for internal buffer
    }

    if (strlen(path) >= out_size) {
        return -1;  // Path too long for output buffer
    }

    strncpy(out, path, out_size - 1);
    out[out_size - 1] = '\0';
    return 0;
}
```

## Explanation

The original code violates the principle of checking bounds *before* writing to a buffer. The `strcat` call on line 20 blindly appends `filename` to `path` with no size limit, and only afterward checks whether the result fits (line 22). By that point, the overflow has already occurred.

The fix calculates the available space in `path` before concatenation and either rejects oversized filenames or uses `snprintf` (which includes built-in bounds checking). The secondary sink at line 26 is also hardened by using `strncpy` and explicit null termination instead of `strcpy`.

Both approaches ensure:
1. The input size is validated or limited before any buffer write
2. Null termination is guaranteed
3. Output buffer underflow is prevented

The `snprintf` approach is preferred in modern C code for its clarity and reduced mental math, but the `strncat` version more directly mirrors the original intent.
