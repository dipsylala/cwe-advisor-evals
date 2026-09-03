## Verdict

**Out-of-Bounds Read confirmed.** The `strlen()` function at line 11 reads beyond the 16-byte `name` buffer when the array lacks a null terminator within its bounds.

## Source

The vulnerability is in the `record_name_length()` function:

```c
size_t record_name_length(const struct Record *record) {
    return strlen((const char *)record->name);  // Line 11
}
```

The `name` field is a fixed-size array of 16 bytes (`uint8_t name[16]`). The `strlen()` function scans memory until it encounters a null terminator, with no awareness of the buffer's 16-byte limit. If the array does not contain a null terminator within its bounds, `strlen()` continues reading past the end of the buffer, triggering an out-of-bounds read.

## Fix

Replace `strlen()` with `strnlen()`, which accepts a maximum length parameter:

```c
size_t record_name_length(const struct Record *record) {
    return strnlen((const char *)record->name, sizeof(record->name));
}
```

This ensures the scan stops at 16 bytes, preventing an out-of-bounds read even if no null terminator is present.

## Explanation

`strlen()` is designed for null-terminated strings with unbounded memory access; it is unsafe when applied to fixed-size buffers that may not be null-terminated. `strnlen()` (available in C99 and later, via `<string.h>`) performs the same length calculation but stops at the specified maximum length, making it safe for fixed-size arrays. The `sizeof(record->name)` idiom ensures the limit stays synchronized with the array declaration, preventing length creep during refactoring.
