## Verdict
exploitable

## Source
`getenv("FEATURE_MODE")` on line 5 returns a null pointer when the environment variable is not set. This is the normal case, not an exceptional one.

## Fix
**Vulnerable code (line 5-6):**
```c
int feature_flag_enabled(void) {
    const char *mode = getenv("FEATURE_MODE");
    if (strcmp(mode, "strict") == 0) {  // NULL dereference: mode is unchecked
        return 1;
    }
    return 0;
}
```

**Fixed code:**
```c
int feature_flag_enabled(void) {
    const char *mode = getenv("FEATURE_MODE");
    if (mode == NULL) {
        return 0;  // Treat missing env var as feature not enabled
    }
    if (strcmp(mode, "strict") == 0) {
        return 1;
    }
    return 0;
}
```

## Explanation
The fix adds a null check immediately after the `getenv()` call, before any attempt to dereference `mode`. When the FEATURE_MODE environment variable is not set, `getenv()` returns NULL. Without the check, `strcmp(mode, "strict")` attempts to dereference a null pointer, causing undefined behavior. The check is positioned before the first use of `mode`, consistent with C's undefined-behavior semantics where a compiler can assume a dereferenced pointer was non-null and optimize away any check placed after the dereference. By returning 0 (feature not enabled) when the variable is absent, the function handles this common case explicitly rather than crashing.

## Behaviour changes
The return value interpretation changes when FEATURE_MODE is not set: the original code crashes with undefined behavior, while the fixed code returns 0 (feature not enabled). This is a sensible semantic for a feature flag - an unset variable means the feature is off by default. Callers relying on this function do not need to change their code; the function continues to return 0 or 1 in all cases.
