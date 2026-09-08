## Verdict

Confirmed. `build_upload_display_path()` copies attacker-controlled `filename` into the fixed-size stack buffer `path[128]` with `strcat`, which has no bound on how much it writes. `BASE_DIR "/"` occupies 23 bytes, leaving 104 usable bytes in `path`, but `filename` comes straight from the multipart upload's `Content-Disposition` header with no length check before this call. Any filename longer than that overflows `path` and corrupts adjacent stack memory before the existing `strlen(path) >= out_size` check ever runs - that check only bounds the later copy into `out`, not the write into `path` that already happened.

## Source

`filename`, passed into `build_upload_display_path()` from the multipart upload's `Content-Disposition` header (per the function's own comment: "not validated for length before it reaches this function").

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

    int written = snprintf(path, sizeof(path), "%s/%s", BASE_DIR, filename);
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

The unbounded `strcat(path, filename)` is replaced with `snprintf(path, sizeof(path), "%s/%s", BASE_DIR, filename)`, which never writes past `path`'s 128-byte bound regardless of `filename`'s length. `snprintf` returns the number of characters that *would* have been written (excluding the terminator); checking that return value against `sizeof(path)` detects truncation and rejects the input by returning `-1` instead of silently producing a shortened, misleading path. This replaces the concatenation itself rather than adding a length check beforehand, since `strlen(filename)` would need to duplicate the same arithmetic `snprintf` already does safely.

The existing `strlen(path) >= out_size` check is preserved unchanged - it still guards the separate concern of whether the now-safely-built `path` fits into the caller-supplied `out` buffer before the final `strcpy(out, path)`, which remains safe because that check runs first every time `path` was successfully constructed.

With the sample's 171-character `uploaded_name`, `snprintf` now safely truncates into the 128-byte `path` buffer, the truncation check catches it, and `build_upload_display_path()` returns `-1` instead of corrupting stack memory - visible as "Failed to build display path" instead of a crash or undefined behavior.
