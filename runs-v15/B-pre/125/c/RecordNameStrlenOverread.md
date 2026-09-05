## Verdict

Exploitable. The `strlen()` call on line 11 reads the 16-byte `name` buffer without validating a null terminator exists within the buffer's bounds, creating an out-of-bounds read if the buffer is completely filled without a null terminator.

## Source

The `record->name` field is a fixed 16-byte array with no guarantee of NUL termination. The function receives a pointer to a `struct Record` from an untrusted caller and immediately passes the `name` field to `strlen()`.

## Fix

```c
// Vulnerable code:
size_t record_name_length(const struct Record *record) {
    return strlen((const char *)record->name);
}

// Fixed code:
size_t record_name_length(const struct Record *record) {
    return strnlen((const char *)record->name, sizeof(record->name));
}
```

## Explanation

Replace `strlen()` with `strnlen()` and supply the buffer's actual size (`sizeof(record->name)`) as the capacity limit. The `strnlen()` function reads at most `sizeof(record->name)` bytes, preventing a read past the 16-byte boundary even if no null terminator is present. If `strnlen()` returns 16, the caller knows the null terminator was not found within the buffer and can handle that condition appropriately (e.g., reject the buffer or treat it as unterminated).

## Behaviour changes

The function's return value now differs when the buffer contains no null terminator within its 16 bytes. Previously, `strlen()` would read past the buffer and potentially trigger undefined behavior or segmentation fault. Now, `strnlen()` returns 16 (the buffer size) if no null terminator is found, allowing the caller to detect and handle this safely. This is the correct behavior for a length query on a fixed-size, potentially non-terminated buffer.
