## Verdict
CONFIRMED. The vulnerability is a classical out-of-bounds write via unbounded string concatenation. The `strcat()` call on line 20 writes beyond the 128-byte `path` buffer when `filename` exceeds the remaining capacity, because bounds checking occurs after the write has already happened.

## Source
```c
char path[128] = BASE_DIR "/";  // BASE_DIR "/" occupies ~20 bytes
// ... validation skipped ...
strcat(path, filename);  // No size limit; filename can exceed remaining ~108 bytes
if (strlen(path) >= out_size) {  // Check happens AFTER the write
    return -1;
}
```

The root cause: user-controlled `filename` from the multipart header is concatenated without prior length validation into a fixed 128-byte buffer.

## Fix
### File: StrcatUnboundedAppend.c
```c
#include <stdio.h>
#include <string.h>

#define BASE_DIR "/srv/uploads/incoming"

/*
 * Builds a display path for a file that was just uploaded, so the caller
 * can log or show the user where the file landed. filename comes straight
 * from the multipart upload's Content-Disposition header and is not
 * validated for length before it reaches this function.
 */
int build_upload_display_path(const char *filename, char *out, size_t out_size) {
    char path[128] = BASE_DIR "/";

    if (filename == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    // Calculate available space in path buffer for the filename.
    size_t path_len = strlen(path);
    size_t available = sizeof(path) - path_len - 1; // -1 for null terminator

    // Reject filenames that will not fit in the path buffer.
    if (strlen(filename) > available) {
        return -1;
    }

    // Safely append filename with a size limit.
    strncat(path, filename, available);

    if (strlen(path) >= out_size) {
        return -1;
    }

    strcpy(out, path);
    return 0;
}

int main(void) {
    char display[256];
    const char *uploaded_name =
        "quarterly-report-final-v2-reviewed-by-legal-and-finance-and-ops-and-compliance-and-everyone-else-who-had-an-opinion-about-the-filename-length-limit-apparently-nobody.pdf";

    if (build_upload_display_path(uploaded_name, display, sizeof(display)) == 0) {
        printf("Uploaded file available at: %s\n", display);
    } else {
        printf("Failed to build display path\n");
    }

    return 0;
}
```

## Explanation
The fix prevents out-of-bounds write by validating the filename length before any write operation:

1. **Calculate available space**: Before concatenation, compute how many bytes remain in the `path` buffer: `sizeof(path) - path_len - 1` (the `-1` reserves space for the null terminator).

2. **Validate before write**: Check if `filename` length exceeds available space and reject it early, before any strcat call occurs.

3. **Use bounded concatenation**: Replace `strcat()` with `strncat(path, filename, available)`, which respects the size limit even if the pre-check is somehow bypassed.

The order matters: validation must occur before the write, not after. With this fix, an oversized filename is rejected gracefully, and even if the check were removed, `strncat()` ensures no write past the buffer boundary.
