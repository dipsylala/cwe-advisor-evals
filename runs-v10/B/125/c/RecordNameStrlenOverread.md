## Verdict

Exploitable. The `strlen()` call on line 11 reads past the 16-byte buffer boundary when the buffer does not contain a NUL terminator within its allocated size.

## Source

The `name` field is a `uint8_t[16]` array in `struct Record`. There is no guarantee that this buffer contains a NUL terminator within its 16-byte allocation.

## Fix

Replace `strlen()` with `strnlen()` to enforce a maximum search length equal to the buffer's actual size:

**Vulnerable code:**
```c
size_t record_name_length(const struct Record *record) {
    return strlen((const char *)record->name);
}
```

**Fixed code:**
```c
size_t record_name_length(const struct Record *record) {
    return strnlen((const char *)record->name, sizeof(record->name));
}
```

## Explanation

`strlen()` scans memory until it finds a NUL terminator, with no bounds check. If the buffer does not contain a NUL terminator within its 16-byte allocation, `strlen()` continues reading past the buffer boundary, triggering an out-of-bounds read. `strnlen()` limits the search to the specified maximum length (16 bytes), returning either the position of the NUL terminator if found, or the maximum length itself if no terminator is found. This prevents the out-of-bounds read and allows the caller to detect whether the buffer was actually NUL-terminated.

## Behaviour changes

The function now returns 16 if no NUL terminator is found within the buffer, whereas the original `strlen()` would have read past the buffer boundary. Callers must handle the case where the returned length equals `sizeof(record->name)`, which indicates the buffer is not NUL-terminated. This behavior change is necessary to eliminate the vulnerability; the safer contract requires explicit handling of unterminated buffers rather than reading out-of-bounds.
