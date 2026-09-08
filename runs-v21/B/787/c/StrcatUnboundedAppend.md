## Verdict

Exploitable. The `filename` parameter from an untrusted source (multipart upload header) is concatenated into a fixed 128-byte buffer without validating its length beforehand. The bounds check on line 22 occurs after the write has already completed, allowing unbounded input to overflow the stack buffer.

## Source

Line 9-10: `filename` is stated to come from an untrusted multipart upload Content-Disposition header with no prior validation.

## Fix

Add a size check before line 20 to validate that the filename fits in the remaining space of the `path` buffer. Calculate space remaining, compare against the untrusted input length, and reject if it does not fit:

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

    /* Validate filename fits in remaining space before concatenating */
    size_t space_left = sizeof(path) - strlen(path) - 1;
    if (strlen(filename) > space_left) {
        return -1;
    }

    strcat(path, filename);

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

The vulnerable code concatenated untrusted input directly into a fixed-size buffer without first verifying it would fit. The fix adds a bounds check before the write: it calculates the space remaining in the `path` buffer (sizeof minus the bytes already used minus one for the NUL terminator) and compares against the length of the untrusted `filename`. If the filename is longer than the available space, the function rejects it and returns an error code. Only after validation passes does the code proceed to the `strcat()` call, ensuring no overflow occurs. This matches the CWE-787/c guidance to validate the write size against the destination's real capacity before the write, using the destination's known capacity (the array's fixed size) rather than any size field from the input.

## Behaviour changes

The function now rejects filenames longer than approximately 106 bytes (the 128-byte path buffer minus the 21-byte base directory path minus one for the NUL terminator). Previously, such filenames would silently overflow the buffer; now they trigger the error path (`return -1`), which the caller already handles by printing "Failed to build display path". No change in the success path contract: on valid input, the function still computes and copies the path exactly as before.
