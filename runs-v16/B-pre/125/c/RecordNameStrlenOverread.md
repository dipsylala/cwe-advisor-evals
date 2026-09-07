## Verdict
exploitable

## Source
The `record->name` field: a 16-byte fixed array in the `Record` struct that is not guaranteed to contain a null terminator.

## Fix

**Vulnerable code:**
```c
size_t record_name_length(const struct Record *record) {
    return strlen((const char *)record->name);  // OOB read if name is not null-terminated
}
```

**Fixed code:**
```c
size_t record_name_length(const struct Record *record) {
    return strnlen((const char *)record->name, sizeof(record->name));
}
```

## Explanation
The original code calls `strlen()` on a 16-byte fixed array without ensuring it contains a null terminator. If the buffer is filled from untrusted input or is not properly null-terminated, `strlen()` will read past the 16-byte allocation searching for a null byte. The fix replaces `strlen()` with `strnlen()`, which accepts a maximum length parameter and stops reading at either the first null byte or after checking `sizeof(record->name)` bytes, whichever comes first. This eliminates the out-of-bounds read while preserving the return value semantics: `strnlen()` returns the string length (up to the null terminator) or the maximum length if no terminator is found.

## Behaviour changes
none
