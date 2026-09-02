## Verdict

The vulnerability is confirmed: `strlen()` on a fixed 16-byte buffer without a null-terminator guarantee reads beyond the array bounds.

## Source

Line 11 calls `strlen()` on `record->name`, a `uint8_t[16]` array with no null-termination guarantee. The `strlen()` function will scan past the 16-byte boundary if no `\0` byte is found within that range.

## Fix

Replace `strlen()` with `strnlen()`, which accepts a maximum byte count:

```c
size_t record_name_length(const struct Record *record) {
    return strnlen((const char *)record->name, sizeof(record->name));
}
```

`strnlen()` is part of POSIX.1-2008 and is widely available on modern systems (glibc, musl, Windows via BSD compatibility, etc.). It returns the length of the string up to a maximum of `sizeof(record->name)` bytes, preventing reads past the buffer end.

## Explanation

`strlen()` relies on finding a null terminator and has no built-in bounds check. A 16-byte array may never be null-terminated, or the null byte may be beyond the 16-byte boundary if the record structure is not properly initialized or if the caller writes untrusted data into the `name` field.

`strnlen(ptr, limit)` scans up to `limit` bytes and returns the length without requiring a null terminator within that span, making it safe for fixed-size buffers. Here, `limit` is the exact size of the array, ensuring no read occurs outside it.
