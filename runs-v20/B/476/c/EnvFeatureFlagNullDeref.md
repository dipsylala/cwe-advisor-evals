## Verdict

exploitable

- cwe_id: CWE-476
- location: EnvFeatureFlagNullDeref.c, line 6 (`strcmp(mode, "strict")`)
- confidence: high

## Source

`getenv("FEATURE_MODE")` at line 5. `getenv` returns `NULL` when the named environment variable is not set in the process environment - this is the routine, expected outcome, not an exceptional one, since the caller of `feature_flag_enabled()` has no way to guarantee `FEATURE_MODE` is set. The result is assigned to `mode` with no intervening check before it is used.

## Fix

### File: EnvFeatureFlagNullDeref.c

```c
#include <string.h>
#include <stdlib.h>

int feature_flag_enabled(void) {
    const char *mode = getenv("FEATURE_MODE");
    if (mode == NULL) {
        return 0;
    }

    if (strcmp(mode, "strict") == 0) {
        return 1;
    }

    return 0;
}
```

## Explanation

`getenv` returns `NULL` whenever `FEATURE_MODE` is unset, which is the normal case for any environment that hasn't explicitly opted into the feature flag; the original code passed that potentially-null pointer straight into `strcmp` as its first argument, which is undefined behaviour in C regardless of the second argument's length. The fix adds a null check immediately after the `getenv` call and before the first (and only) use of `mode`, returning `0` - "feature not enabled" - when the variable is absent. This preserves the function's existing contract (an `int` flag, no error path, no exceptions) and treats "unset" as the same disabled state a caller would reasonably expect, rather than substituting a default value that masks the missing configuration or continuing to a crash.

## Behaviour changes

- Previously: an unset `FEATURE_MODE` environment variable caused undefined behaviour (typically a crash) inside `strcmp`. Now: an unset `FEATURE_MODE` makes `feature_flag_enabled()` return `0`, the same value already returned for any set-but-non-"strict" value (e.g. `FEATURE_MODE=off`). This is the intended fix, not an incidental change - it makes "flag absent" and "flag not set to strict" collapse to the same, already-existing disabled outcome, so no caller of `feature_flag_enabled()` needs to change.
- No arguments, return type, includes, or other call sites were altered. `strcmp`'s call and both its arguments are unchanged from the original once `mode` is known non-null.
- assumptions: no compiler was reachable in this environment to run a syntax check (no `gcc`/`cc`/`clang`/`cl` on PATH); verified by manual read instead - `NULL` comes from `stdlib.h`, already included; `strcmp`'s signature and both call sites are unchanged from the original; the added branch's `return 0;` uses the function's existing return type and matches the existing "not strict" return path.

## Verification

No C compiler (`gcc`, `cc`, `clang`, `cl`) was available in this environment, so no `-c`/syntax-check compile was run. Verified by manual read instead: `NULL` is provided by `stdlib.h`, already included at the top of the file; the new `if (mode == NULL) { return 0; }` block is syntactically well-formed and placed before the only dereference of `mode`; `strcmp`'s two arguments and the surrounding `if` are byte-for-byte unchanged from the original; the function's signature, includes, and other return paths are unmodified.
