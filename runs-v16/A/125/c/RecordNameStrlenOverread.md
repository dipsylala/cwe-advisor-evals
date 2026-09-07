## Verdict
Confirmed out-of-bounds read.

## Source
```c
size_t record_name_length(const struct Record *record) {
    return strlen((const char *)record->name);
}
```

The `record->name` field is a fixed 16-byte array with no guaranteed null terminator. If the array is fully populated without a null byte, `strlen()` reads past the buffer boundary to locate the terminator.

## Fix
```c
size_t record_name_length(const struct Record *record) {
    return strnlen((const char *)record->name, sizeof(record->name));
}
```

Replace `strlen()` with `strnlen()`, passing the buffer size as the maximum length to search. `strnlen()` scans for a null terminator but stops at the buffer boundary, preventing the out-of-bounds read.

## Explanation
`strlen()` assumes the input is null-terminated and unbounded—it reads until it encounters a null byte. When the fixed-size array `name[16]` contains no null terminator (a valid state for packed binary data or incompletely initialized buffers), `strlen()` reads into adjacent memory.

`strnlen()` is designed for this scenario: it searches for a null terminator within a specified length limit, returning the lesser of the string length or the limit. Passing `sizeof(record->name)` ensures we never read beyond the 16-byte field regardless of its contents.
