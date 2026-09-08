## Verdict

- CWE-787 (Out-of-bounds Write), C
- Location: `StrcatUnboundedAppend.c`, `build_upload_display_path()`, line 20 (`strcat(path, filename)`)
- Verdict: **exploitable**
- Confidence: high

## Source

- Source: `filename` parameter of `build_upload_display_path()`. Per the function's own doc comment, this value comes directly from the multipart upload's `Content-Disposition` header and is not validated for length before it reaches this function - it is attacker-controlled and unbounded.
- Intermediate: `path` is a fixed 128-byte stack buffer (`char path[128]`), pre-loaded with the 22-byte string `"/srv/uploads/incoming/"`, leaving 105 usable bytes.
- Sink: `strcat(path, filename)` at line 20 appends `filename` onto `path` with no destination-capacity check. Any `filename` longer than 105 bytes overflows `path` on the stack, corrupting adjacent stack memory (potentially the saved frame pointer/return address - this is the CWE-121 stack-buffer-overflow shape of CWE-787).
- The only length check in the function (`strlen(path) >= out_size` at line 22) runs *after* the `strcat` has already executed, so it cannot prevent the overflow - it only gates the later `strcpy(out, path)`. `main()`'s sample filename is 173 characters, which already exceeds the 105 remaining bytes in `path`, confirming the path is reachable and not merely theoretical.
- Sink contract: `strcat` returns `path` (the return value is discarded, as in the original - unchanged); it takes no destination-capacity argument, so nothing bounds the write; on overflow it has no defined failure behavior (undefined behavior / memory corruption rather than a reportable error).

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
    int written;

    if (filename == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    written = snprintf(path, sizeof(path), "%s/%s", BASE_DIR, filename);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        return -1;
    }

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

The unbounded `strcat(path, filename)` is replaced with `snprintf(path, sizeof(path), "%s/%s", BASE_DIR, filename)`, which builds the same `BASE_DIR + "/" + filename` string but is told the destination's real 128-byte capacity and will never write past it. `snprintf` returns the number of bytes it *would* have written had the buffer been big enough, so `written < 0 || (size_t)written >= sizeof(path)` (cast to `size_t` first, per the C guidance, so a negative encoding-error result doesn't slip past the comparison as a huge unsigned value) detects both an encoding failure and truncation and rejects the input instead of silently continuing with a corrupted or truncated path. This closes the out-of-bounds write at its source - the fixed-size stack buffer can no longer be overrun by an oversized `filename` - while leaving the existing `strlen(path) >= out_size` / `strcpy(out, path)` logic that copies into the caller's buffer untouched, since that check already validates against `out_size` before the copy and was not the reported sink.

## Behaviour changes

- Oversized `filename`: previously caused undefined behavior (stack buffer overflow) with no defined return; now the function returns `-1` (the same failure code already used for the other invalid-input cases in this function) instead of writing out of bounds. This is the intended effect of the fix, not incidental.
- All other inputs (any `filename` where `BASE_DIR "/" filename` fits in 128 bytes, which includes every input that did not already crash or corrupt memory): identical observable behavior - same resulting `path` string, same `out`/`out_size` handling, same return values.
- No arguments, return type, or call sites changed. `strcat`'s discarded return value is replicated by `snprintf`'s discarded (checked, not passed on) return value - no new output is surfaced and none is newly discarded.
- New symbol introduced: `snprintf` - C standard library, declared in `<stdio.h>`, already included in this file; no new import needed.
- Verification: no C compiler (`gcc`/`clang`/`cl`) was reachable in this environment to compile the fix. Performed a manual by-hand check instead: `snprintf`'s signature (`int snprintf(char *restrict str, size_t size, const char *restrict format, ...)`) matches the call's argument count and types; `sizeof(path)` is correct here because `path` is still an in-scope local array (not a decayed pointer parameter); every brace and statement in the modified function balances against the original; the only other caller in the file, `main()`, calls `build_upload_display_path()` with the same signature and is unchanged.
- Assumption: none needed - the finding's CWE ID, file, and line were unambiguous and matched a single sink.
