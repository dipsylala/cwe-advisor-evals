## Verdict

CWE-476 (NULL Pointer Dereference) confirmed. `getenv()` returns NULL when the environment variable is not set, and `strcmp()` does not accept NULL pointers.

## Source

Line 6 calls `strcmp(mode, "strict")` where `mode` is the return value of `getenv("FEATURE_MODE")` (line 5). The `getenv()` function returns NULL if the environment variable does not exist, and passing NULL to `strcmp()` triggers undefined behavior.

## Fix

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

Add a NULL check before calling `strcmp()`. The condition `mode != NULL && strcmp(mode, "strict") == 0` ensures the pointer is valid before dereferencing it in the comparison.

## Explanation

`getenv()` returns a pointer to the value of an environment variable, or NULL if the variable is not set. The original code unconditionally calls `strcmp()` with the return value, which violates the documented precondition that both arguments must be valid pointers to null-terminated strings. The fix guards the string comparison with an explicit NULL check using short-circuit evaluation, so `strcmp()` is only called when `mode` is guaranteed to be non-NULL. This is the standard defensive approach for C library functions that can return NULL.
