## Verdict
exploitable

## Source
`getenv("FEATURE_MODE")` on line 5 — returns NULL when the environment variable is not set.

## Fix

**Vulnerable code:**
```c
int feature_flag_enabled(void) {
    const char *mode = getenv("FEATURE_MODE");
    if (strcmp(mode, "strict") == 0) {  // NULL pointer dereference
        return 1;
    }
    return 0;
}
```

**Fixed code:**
```c
int feature_flag_enabled(void) {
    const char *mode = getenv("FEATURE_MODE");
    
    // Check for NULL before dereferencing the pointer
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
The vulnerability occurs because `getenv()` returns NULL when the requested environment variable is not set, and this is the routine case per the C standard. The original code passes this potentially-NULL pointer directly to `strcmp()`, which dereferences it without validation, causing undefined behavior. The fix adds an explicit NULL check before the first use of the pointer, handling the absent case by returning 0 (feature disabled). This follows the C guidance on ordering: the check must precede the first dereference, and `getenv` is explicitly listed as a lookup that can return NULL.

## Behaviour changes
The fixed code introduces one new execution path not present in the original: when `getenv()` returns NULL, the function returns 0 immediately instead of attempting to call `strcmp()`. This is a necessary change because the original code had undefined behavior in that case. The return value (0) represents a documented default state — the feature flag is disabled when the environment variable is not set. This is reasonable for a feature-flag checker and does not introduce silent wrong behavior; it is an explicit, controlled handling of the absent case.
