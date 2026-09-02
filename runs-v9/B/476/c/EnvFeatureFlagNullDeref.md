## Verdict

Exploitable. CWE-476 (NULL Pointer Dereference), confidence: high.

Location: `EnvFeatureFlagNullDeref.c`, line 6, inside `feature_flag_enabled()`.

## Source

`getenv("FEATURE_MODE")` at line 5. `getenv` returns `NULL` whenever the named environment
variable is not set in the process environment - this is the routine, expected outcome, not an
edge case, since callers/deployments frequently run without every optional flag defined.

The returned pointer is assigned to `mode` and used immediately, with no intervening validation,
so the trace from source to sink is direct and unconditional.

## Fix

Vulnerable code:

```c
#include <string.h>
#include <stdlib.h>

int feature_flag_enabled(void) {
    const char *mode = getenv("FEATURE_MODE");
    if (strcmp(mode, "strict") == 0) {  // mode may be NULL here
        return 1;
    }

    return 0;
}
```

Fixed code:

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

`strcmp`'s first argument is dereferenced unconditionally; passing it a `NULL` `mode` is undefined
behavior in C, not a guaranteed, catchable crash. The fix adds the null check immediately after
the `getenv` call and before the first (and only) dereference of `mode`, so the guard cannot be
optimized away as dead code the way a check placed after a dereference could be. Absence is
handled explicitly by returning `0`, the same value the function already returns for any
non-`"strict"` string, rather than substituting a default and continuing into further pointer use.

## Behaviour changes

- When `FEATURE_MODE` is unset, the function now returns `0` (feature disabled) instead of
  invoking undefined behavior via `strcmp(NULL, "strict")`. This is the change that closes the
  weakness, not incidental scope creep: it reuses the function's existing "not strict" return
  value (`0`), so the disabled-by-default outcome is consistent with how the function already
  treats any other non-matching string - no new default value or error path was introduced.
- No other arguments, return values, or code paths were altered. The `"strict"`-set and
  set-to-other-string behaviors are unchanged.
- Assumption: treating an absent `FEATURE_MODE` as "flag disabled" (return `0`) is the correct
  contract, since it matches the function's own fallback for every other unmatched value and no
  caller-side error-signaling mechanism exists in this single-function file to report absence
  differently. If the intended contract is that an unset variable should be distinguishable from
  an explicitly-disabled one, the return type would need to change (e.g. a tri-state or an out
  parameter) - that is a larger contract change than this finding calls for.
