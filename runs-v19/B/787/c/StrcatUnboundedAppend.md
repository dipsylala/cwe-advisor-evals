## Verdict

Confirmed CWE-787 vulnerability. The out-of-bounds write occurs at line 20 where `strcat(path, filename)` writes untrusted user input to a fixed-size stack buffer without bounds validation. The subsequent check at line 22 cannot prevent the overflow as it occurs after the dangerous write.

## Source

**File:** StrcatUnboundedAppend.c  
**Vulnerable Line:** 20  
**Sink:** `strcat(path, filename)`

**Root Cause:** The `filename` parameter is untrusted external input from a multipart upload header (documented at lines 9-10) with no length constraints. The `path` buffer is declared with fixed capacity of 128 bytes (line 13), initialized with "/srv/uploads/incoming/" (23 bytes), leaving only ~104 bytes for the filename. The unbounded `strcat()` function provides no capacity checking, allowing any filename longer than 104 bytes to overflow the buffer.

**Why the Existing Check Fails:** The validation at line 22 (`if (strlen(path) >= out_size)`) occurs after the buffer overflow has already happened on line 20. A bounds check must occur before the write, not after.

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
    char path[128];

    if (filename == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    // Use snprintf to safely construct the path with automatic bounds checking.
    // snprintf returns the number of bytes that would have been written (excluding NUL).
    // If the return value is >= sizeof(path), the string was truncated.
    int written = snprintf(path, sizeof(path), "%s/%s", BASE_DIR, filename);
    if (written < 0 || written >= (int)sizeof(path)) {
        // Encoding error or path would be truncated; reject the request
        return -1;
    }

    if (strlen(path) >= out_size) {
        return -1;
    }

    // Use snprintf for output copy to enforce bounds
    written = snprintf(out, out_size, "%s", path);
    if (written < 0 || written >= (int)out_size) {
        return -1;
    }
    
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

The fix replaces two vulnerable operations with bounded alternatives:

**Primary Fix (Line 20 vulnerability):**
- **Before:** `char path[128] = BASE_DIR "/"; strcat(path, filename);` 
- **After:** `snprintf(path, sizeof(path), "%s/%s", BASE_DIR, filename);`

The vulnerable `strcat()` performs an unbounded write that does not validate the destination's capacity. The replacement uses `snprintf()`, which:
1. Accepts an explicit size parameter (`sizeof(path)`) 
2. Performs the bounds check before writing
3. Returns the length that would have been written, allowing detection of truncation
4. Handles encoding errors by returning a negative value

The check `if (written < 0 || written >= (int)sizeof(path))` ensures the function rejects any attempt to write beyond the buffer's 128-byte capacity. This converts a silent buffer overflow into a detectable, recoverable error condition.

**Secondary Fix (Line 26 vulnerability):**
- **Before:** `strcpy(out, path);`
- **After:** `snprintf(out, out_size, "%s", path);` with validation

While line 22's check technically prevents this second overflow, it is safer to use a bounds-checked function rather than relying on a preceding validation. The `snprintf()` approach enforces the constraint at the point of the write.

**Sink Contract Preservation:**
The fix preserves the function's original contract: it still returns 0 on success and -1 on failure. The path building logic and output copying semantics remain unchanged. The only behavioral change is that oversized filenames are now properly rejected before buffer overflow occurs, rather than allowing memory corruption.

## Behaviour changes

**Functional Changes:**
- The function now returns -1 when `filename` is long enough to cause truncation in the 128-byte `path` buffer (previously: buffer overflow occurred silently)
- The function now returns -1 when formatting errors occur (previously: behavior undefined)
- Oversized paths are rejected with a clear error return code, allowing the caller to handle the condition gracefully (e.g., log the rejection, return an HTTP 400 error)

**Test Case Behavior:**
The test case's 164-character filename now results in the function returning -1 (failure) and printing "Failed to build display path" instead of silently corrupting the stack and potentially crashing or executing attacker-supplied code.

**No Regression:**
- For valid filenames that fit within the buffer, the function succeeds exactly as before
- The return value semantics (0 = success, -1 = error) are unchanged
- The output buffer format and content are identical for successful cases
