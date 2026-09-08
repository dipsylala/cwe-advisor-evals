## Verdict

- **CWE**: CWE-121 (Stack-based Buffer Overflow)
- **Location**: `StackAuditMessageOverflow.c`, `build_audit_message()`, line 14 (sink), preceded by the unbounded write at line 11
- **Verdict**: exploitable
- **Confidence**: high

## Source

- **Source**: the `username` and `action` parameters of `build_audit_message()`. Neither is length-checked, bounded, or otherwise constrained before use; the single file in this call chain shows no validation performed by this function or before it, so both are treated as untrusted/attacker-influenced data (e.g. an audit-logged username or action string originating outside this function).
- **Sink**: `char message[64]` on the stack, written via `strcpy(message, username)` (line 11) and `strcat(message, ":")` / `strcat(message, action)` (lines 12, 14). None of these calls are bounded by `sizeof(message)`. Any combination of `username` + `":"` + `action` (+ NUL) longer than 64 bytes overflows `message` and corrupts adjacent stack memory. The finding's marked line (14) is the point at which the already-overflowable buffer receives the final, attacker-controlled write.
- The subsequent `snprintf(out, out_capacity, "AUDIT %s", message)` (line 16) is already bounded and is not itself the weakness, but it reads from `message` only after the corruption has already occurred.

## Fix

### File: StackAuditMessageOverflow.c
```c
#include <stdio.h>

int build_audit_message(const char *username,
                        const char *action,
                        char *out,
                        size_t out_capacity)
{
    char message[64];

    int msg_written = snprintf(message, sizeof message, "%s:%s", username, action);
    if (msg_written < 0 || (size_t)msg_written >= sizeof message) {
        return -1;
    }

    int written = snprintf(out, out_capacity, "AUDIT %s", message);
    if (written < 0 || (size_t)written >= out_capacity) {
        return -1;
    }
    return 0;
}
```

## Explanation

The unbounded `strcpy`/`strcat` pair is replaced with a single bounded `snprintf(message, sizeof message, "%s:%s", username, action)`, per the C-specific guidance's preference for one bounded format call over `strcpy` followed by `strcat`. `snprintf` never writes past `sizeof message` and returns the length it would have needed had truncation not occurred, so the length can be checked *after* the call: `msg_written < 0 || (size_t)msg_written >= sizeof message`. Per the guidance's instruction to reject oversized input rather than silently truncate it, that condition returns `-1` immediately, exactly as the function already does for the second `snprintf` into `out` - so an oversized `username`/`action` combination is rejected rather than producing a truncated audit message that the caller would treat as complete and correct. This closes the stack overflow at its root (the write into `message` can no longer exceed 64 bytes under any input) rather than only hardening the copy. The now-unused `#include <string.h>` was removed since no `string.h` function remains in the file.

## Behaviour changes

- **Rejection of oversized input**: previously, `username`+`":"`+`action` longer than 63 bytes caused undefined behavior (stack corruption) rather than any defined return value. The fixed code returns `-1` for that case, matching the existing convention already used by this function for an oversized `out` buffer. This is the intended effect of the fix, not incidental.
- **Return value / discards**: unchanged for the success path - the function still returns `0` and writes `"AUDIT username:action"` into `out` for any input that fits, identical to the original's intended (non-overflowing) behavior. `strcpy`/`strcat`'s discarded pointer return values are replaced by `snprintf`'s length return value, but that return value is only used internally for the new bounds check and does not change what the caller observes on success.
- **Arguments/defaults**: no parameter was added, dropped, or given a different default; `out` and `out_capacity` are used exactly as before.
- **Dependency removed**: `#include <string.h>` dropped as dead after removing `strcpy`/`strcat`; no functional effect.
- **Verification**: no C compiler (`gcc`, `clang`, `cl`) was reachable in this environment, so the fix was checked by hand rather than compiled: `snprintf` is declared in `<stdio.h>` (already included) and was already used identically in this file's untouched second call; `size_t` was already relied upon in the original signature and is guaranteed by `<stdio.h>` alone, so removing `<string.h>` introduces no missing declaration; the two `if` conditions mirror the existing, untouched pattern at line 17 exactly, only re-targeted at `message`/`sizeof message`; no other caller or symbol in the (single-file) call chain references `message`, `strcpy`, or `strcat`, so no other site needed updating.
- **Assumptions**: `username` and `action` are treated as untrusted because no validation is visible anywhere in the provided call chain; if a caller elsewhere in the real codebase already bounds these values, the fix is still safe (the check simply never triggers) but may be redundant defense-in-depth rather than the primary control.
