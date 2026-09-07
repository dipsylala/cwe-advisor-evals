## Verdict

Out-of-bounds write confirmed. The `strcat()` at line 20 appends an untrusted, unbounded `filename` to a 128-byte stack buffer without checking available space before the operation. The validation at line 22 occurs too late — the overflow has already occurred.

## Source

```c
char path[128] = BASE_DIR "/";  // Line 13: 128-byte stack buffer
// ...
strcat(path, filename);          // Line 20: VULNERABLE — no length check before append
```

The `filename` parameter originates from an HTTP multipart upload header (`Content-Disposition`) and carries no validation. The code initializes `path` with `"/srv/uploads/incoming/"` (21 bytes), leaving only ~107 bytes. If `filename` exceeds that space, `strcat()` writes past the buffer boundary.

## Fix

Replace `strcat()` with `strncat()` and move the length validation before the concatenation:

```c
int build_upload_display_path(const char *filename, char *out, size_t out_size) {
    char path[128] = BASE_DIR "/";

    if (filename == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    // Validate combined length before appending
    if (strlen(path) + strlen(filename) >= sizeof(path)) {
        return -1;
    }

    strncat(path, filename, sizeof(path) - strlen(path) - 1);

    if (strlen(path) >= out_size) {
        return -1;
    }

    strcpy(out, path);
    return 0;
}
```

Alternatively, use `snprintf()` for the entire path construction, which is safer and more readable:

```c
int build_upload_display_path(const char *filename, char *out, size_t out_size) {
    char path[128];

    if (filename == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    if (snprintf(path, sizeof(path), "%s%s", BASE_DIR "/", filename) >= (int)sizeof(path)) {
        return -1;
    }

    if (strlen(path) >= out_size) {
        return -1;
    }

    strcpy(out, path);
    return 0;
}
```

## Explanation

The root cause is that `strcat()` does not accept a size limit — it writes until it encounters the null terminator of the source string, regardless of the destination buffer's capacity. This is a classic unsafe function for untrusted input.

The original code attempted to defend against this by checking the final path length at line 22, but this check occurs *after* the overflow at line 20. By that point, the stack buffer has been corrupted and the return value cannot undo the damage.

The fix enforces two principles:

1. **Pre-validate before the sink**: Check that `strlen(path) + strlen(filename)` fits in 128 bytes *before* calling `strncat()`. This stops the operation before overflow can occur.

2. **Use length-bounded API**: Replace `strcat()` with `strncat()`, which accepts a maximum byte count and will not write past that boundary. When calculating the limit, subtract 1 from available space to reserve room for the null terminator.

The `snprintf()` alternative is even more robust because it handles the bounds check internally and returns the length that *would have been* written, making it clear whether truncation occurred.
