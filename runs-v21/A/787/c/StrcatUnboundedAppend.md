## Verdict

Confirmed out-of-bounds write vulnerability. The `strcat()` call on line 20 concatenates untrusted filename data into a fixed 128-byte buffer without verifying that the concatenated string will fit. When filename exceeds the remaining buffer capacity (~107 bytes after the BASE_DIR prefix), `strcat()` writes past the buffer boundary into adjacent memory.

## Source

**File:** StrcatUnboundedAppend.c  
**Line:** 20  
**Root cause:** Use of unsafe string concatenation function `strcat()` on untrusted input without prior bounds validation.

The `path` buffer is 128 bytes. After initialization with `BASE_DIR "/"` (21 bytes), only 107 bytes remain. The filename parameter arrives from an untrusted multipart upload header and is not length-validated before being passed to `strcat()`. The bounds check on line 22 occurs after the unsafe write, making it ineffective.

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

    // Use strncat with computed remaining space to prevent buffer overflow
    size_t path_len = strlen(path);
    size_t remaining = sizeof(path) - path_len;
    
    // strncat appends up to remaining-1 bytes (leaving room for null terminator)
    strncat(path, filename, remaining - 1);

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

Replace `strcat()` with `strncat()` to enforce bounds on the concatenation. Before calling `strncat()`:
1. Calculate the current string length of `path` using `strlen()`.
2. Compute the remaining capacity as `sizeof(path) - path_len`.
3. Pass `remaining - 1` as the count to `strncat()` to reserve one byte for the null terminator, ensuring the concatenated string cannot overflow the 128-byte buffer.

`strncat(path, filename, remaining - 1)` will truncate the filename if necessary, preventing any write beyond the buffer boundary. The existing validation logic then correctly rejects the result if the truncated path exceeds `out_size`.
