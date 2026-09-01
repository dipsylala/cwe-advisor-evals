## Verdict

The finding is confirmed. The use of `strlen()` on a fixed-size buffer without a guaranteed null terminator causes an out-of-bounds read.

## Source

Line 11 calls `strlen((const char *)record->name)` where `name` is a 16-byte fixed-size buffer. The `strlen()` function searches for a null terminator and will read past the buffer boundary if one is not present within the 16 bytes, potentially reading into the adjacent `flags` field and beyond.

## Fix

Replace `strlen()` with `strnlen()` to enforce a maximum length limit:

```c
size_t record_name_length(const struct Record *record) {
    return strnlen((const char *)record->name, sizeof(record->name));
}
```

Alternatively, if the size is hardcoded:

```c
size_t record_name_length(const struct Record *record) {
    return strnlen((const char *)record->name, 16);
}
```

## Explanation

`strnlen()` takes a maximum length parameter and stops reading when either a null terminator is found or the maximum length is reached. This prevents reading past the buffer boundary. Using `sizeof(record->name)` is preferred over the hardcoded `16` because it automatically adapts if the buffer size changes, reducing maintenance risk.

