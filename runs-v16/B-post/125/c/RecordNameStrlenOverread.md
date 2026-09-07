## Verdict
Exploitable

## Source
The `record->name` field (a fixed-size 16-byte array) is the data source. It is obtained from the `Record` struct parameter and passed directly to `strlen()` without bounds validation.

## Fix

**Vulnerable code:**
```c
size_t record_name_length(const struct Record *record) {
    return strlen((const char *)record->name);  // OOB read if no NUL terminator in 16-byte buffer
}
```

**Fixed code:**
```c
size_t record_name_length(const struct Record *record) {
    return strnlen((const char *)record->name, sizeof(record->name));
}
```

## Explanation
The vulnerability occurs because `strlen()` reads past the end of the buffer if no NUL terminator exists within the allocated 16 bytes. The fix replaces `strlen()` with `strnlen()`, which accepts a maximum length parameter (`sizeof(record->name)` = 16) and returns immediately upon finding a NUL terminator or reaching the capacity limit. This prevents the out-of-bounds read even when the buffer is not NUL-terminated within its allocation.

## Behaviour changes
The function's return value is now capped at 16 (the buffer size) instead of potentially reading arbitrarily far into memory. If the buffer contains no NUL terminator within its 16-byte allocation, `strnlen()` returns 16 rather than continuing the search. This is the desired behavior: the caller receives the actual usable length of the buffer within its bounds, and the weakness is closed. The return type remains `size_t` and the function signature is unchanged from the caller's perspective.
