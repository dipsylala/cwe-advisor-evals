## Verdict

Exploitable. CWE-787 (Out-of-bounds Write), confirmed at `SprintfFixedBufferOverflow.c:16`.

Confidence: medium - the trace and fix are direct, but no C compiler (`gcc`, `clang`, `cl`) was reachable in this environment to verify by building, so verification below is by manual review only.

## Source

`log_user_action`'s `username` and `message` parameters. The function's own doc comment states they "come from the authenticated request handler and are attacker-controlled in length"; `main`'s comment confirms "In the real service these come from request fields with no length cap." `timestamp` is locally generated (`strftime` into a 32-byte buffer) and bounded, so it does not by itself drive the overflow, but it still consumes space in the destination.

## Sink

`sprintf(line, "[%s] %s: %s", timestamp, username, message);` at line 16, writing into `char line[64]`. `sprintf` performs no bounds checking against the destination's capacity, so any `timestamp` + `username` + `message` combination whose formatted length reaches or exceeds 64 bytes writes past the end of `line`, which is a stack buffer - corrupting adjacent stack memory (locals, saved registers, up to the return address depending on layout).

Sink contract: `sprintf` returns the number of characters written (excluding the terminator), which the original code discards entirely; it takes no destination-capacity argument; it has no defined failure mode for "wrote too much" - it simply overflows. The line is passed to `fputs`/`fputc` and appended to `audit.log`; per the knowledge base's audit-log guidance, discarding the whole entry when the input is long loses the event, so the fix truncates-with-marker and reports truncation through the return value rather than rejecting the write outright.

## Fix

### File: SprintfFixedBufferOverflow.c

```c
#include <stdio.h>
#include <string.h>
#include <time.h>

/*
 * Appends one formatted audit-log entry to the shared log file.
 * username and message come from the authenticated request handler
 * and are attacker-controlled in length (a display name and a free-text
 * status message respectively); timestamp is generated locally.
 */
int log_user_action(const char *timestamp, const char *username, const char *message)
{
    char line[64];

    int written = snprintf(line, sizeof(line), "[%s] %s: %s", timestamp, username, message);
    if (written < 0) {
        return -2;
    }
    int truncated = ((size_t)written >= sizeof(line));

    FILE *fp = fopen("audit.log", "a");
    if (fp == NULL) {
        return -1;
    }

    fputs(line, fp);
    if (truncated) {
        fputs(" [TRUNCATED]", fp);
    }
    fputc('\n', fp);
    fclose(fp);
    return truncated ? 1 : 0;
}

int main(void)
{
    time_t now = time(NULL);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", localtime(&now));

    /* In the real service these come from request fields with no length cap. */
    const char *username = "alice";
    const char *message = "logged in successfully";

    return log_user_action(timestamp, username, message);
}
```

## Explanation

The unbounded `sprintf` is replaced with `snprintf(line, sizeof(line), ...)`, which stops writing at the destination's real 64-byte capacity and always NUL-terminates, eliminating the out-of-bounds write regardless of how long `username` or `message` are. `sizeof(line)` is safe to use here because `line` is a local array in the same scope as the call, not a pointer parameter. Because this destination is an audit-log entry rather than, say, a security decision value, the knowledge base's audit-log guidance applies: instead of silently truncating (which loses evidence of the truncation) or rejecting the entry outright (which loses the event), the fix checks `snprintf`'s return value - the number of characters the full, untruncated output would have needed - against `sizeof(line)`. When the formatted output did not fit, the truncated line is still written but with a `" [TRUNCATED]"` marker appended, and the function returns `1` instead of `0` so a caller can detect and act on the truncation (e.g. alert, or log the full un-truncated fields elsewhere). A negative return from `snprintf` (an encoding error) is treated as a distinct failure (`-2`) rather than proceeding to write a buffer whose contents are unspecified in that case.

## Behaviour changes

- `log_user_action` now returns `1` (instead of `0`) when the formatted entry did not fit in the 64-byte buffer and was truncated. Reason: the audit-log exception in the knowledge base requires the caller be able to tell truncation happened; `sprintf`'s discarded return value gave no way to do this, and `snprintf`'s return value is what makes it possible without changing the log-instead-of-reject strategy.
- `log_user_action` now returns `-2` if `snprintf` reports an encoding error, a case the original `sprintf` had no defined way to signal either. This preserves the existing convention of using negative returns for failure (alongside the pre-existing `-1` for `fopen` failure) rather than proceeding to log indeterminate buffer contents.
- A truncated audit-log entry now has the literal marker `" [TRUNCATED]"` appended before the newline. Reason: per the same audit-log exception, the entry must still be written (not discarded) but the record needs to visibly flag that it was cut short, rather than silently reading as a complete, accurate entry.
- `main`'s exit code is a straight pass-through of `log_user_action`'s return value in both the original and fixed code, so it now can additionally be `1` or `-2`; no change was made in `main` itself since it was already just forwarding the return value.
- No other differences: the format string, argument order, `fopen` mode, file name, and overall control flow are unchanged.

Verification: no C compiler (`gcc`, `clang`, `cl`) was reachable in this sandbox, so the fix was checked by manual review rather than compilation. Confirmed `snprintf`, `fputs`, `fputc`, `fopen`, `fclose`, and `size_t` are all standard symbols already reachable through the existing `<stdio.h>` include (no new `#include` needed). Confirmed the call `snprintf(line, sizeof(line), "[%s] %s: %s", timestamp, username, message)` matches the standard prototype `int snprintf(char *restrict s, size_t n, const char *restrict format, ...)` in argument count, order, and type. Confirmed `line` is a same-scope local array, so `sizeof(line)` yields its true 64-byte capacity rather than falling into the pointer-decay `sizeof` pitfall. Confirmed the sole caller, `main`, requires no change since it already returns `log_user_action`'s value verbatim and imposes no constraint on its range.

Assumptions:
- Language inferred as C (not C++) from the `.c` extension and pure-C syntax (no classes, no `extern "C"`, C-style casts only) - unambiguous, not flagged for confirmation.
- Treated this as the knowledge base's audit-log exception case (truncate-with-marker rather than reject-oversized-input) because the destination is explicitly an audit log file (`audit.log`) and the function's own comment frames it as "one formatted audit-log entry." This is the reasoned choice, not the only one the guidance allows, so confidence above is medium rather than high.
