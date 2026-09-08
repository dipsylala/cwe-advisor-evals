## Verdict

TRUE POSITIVE: CWE-476 (NULL Pointer Dereference) confirmed at line 6.

## Source

`getenv("FEATURE_MODE")` at line 5 returns a pointer to the environment variable value, or NULL if the variable is not set. The function does not validate this return value before using it.

## Fix

### File: EnvFeatureFlagNullDeref.c

```c
#include <string.h>
#include <stdlib.h>

int feature_flag_enabled(void) {
    const char *mode = getenv("FEATURE_MODE");
    if (mode != NULL && strcmp(mode, "strict") == 0) {
        return 1;
    }

    return 0;
}
```

## Explanation

The vulnerability occurs because `strcmp()` expects non-NULL pointers. When `getenv()` fails to find the environment variable, it returns NULL. Passing NULL to `strcmp()` causes undefined behavior and a NULL pointer dereference.

The fix adds a NULL check using short-circuit evaluation: `mode != NULL &&` ensures that `strcmp()` is only called when `mode` is a valid pointer. If the environment variable is not set, the condition fails and the function returns 0 (feature flag disabled), which is safe and semantically appropriate for a missing configuration.
