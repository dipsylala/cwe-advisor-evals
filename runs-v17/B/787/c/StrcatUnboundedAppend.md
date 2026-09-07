## Verdict
Exploitable

## Source
Untrusted user-controlled filename string from multipart upload Content-Disposition header passed as the `filename` parameter to `build_upload_display_path()`.

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

    // Use strlcat with explicit destination capacity and check for truncation
    if (strlcat(path, filename, sizeof(path)) >= sizeof(path)) {
        return -1;
    }

    if (strlen(path) >= out_size) {
        return -1;
    }

    // Use strlcpy with explicit destination capacity
    strlcpy(out, path, out_size);
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

The original code used two unbounded string copy functions: `strcat()` on line 20 and `strcpy()` on line 26. The `strcat()` call appended untrusted `filename` data into a fixed 128-byte stack buffer with no prior bounds check, causing an out-of-bounds write when the combined path exceeded the buffer capacity. The validation check on line 22 came too late, after the overflow had already occurred.

The fix replaces both `strcat()` and `strcpy()` with size-aware alternatives: `strlcat()` and `strlcpy()`. Each takes an explicit destination capacity parameter and detects truncation by comparing the return value to the buffer size. The critical change is moving the bounds check to occur before any data is written into the path buffer, by testing `strlcat()`'s return value immediately after the call. If the concatenation would overflow (return value >= sizeof(path)), the function returns an error without writing. The subsequent check ensures the final path also fits within the output buffer before copying.

## Behaviour changes

- `strlcat()` replaces `strcat()` with an explicit size parameter (sizeof(path)). `strlcat()` returns the total length of the concatenated result (including NUL terminator in the count), or the length it would have been if truncated. Testing if this return value is >= the size parameter detects truncation and prevents overflow.
- `strlcpy()` replaces `strcpy()` with an explicit size parameter (out_size). `strlcpy()` always NUL-terminates the destination, even when truncation occurs. The return value is the length of the source string, which can be compared to out_size to detect truncation if needed (though the check before this line already validates the path length).
- The validation of the concatenation result is now performed immediately after `strlcat()`, before the code proceeds. This prevents any code execution after a buffer overflow.
- Both functions guarantee NUL-termination, preserving the original behavior of producing a valid C string in all cases.
