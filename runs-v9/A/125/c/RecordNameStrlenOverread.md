## Verdict

Confirmed. `record_name_length` calls `strlen` on `record->name`, a fixed-size 16-byte array, with no guarantee that the buffer contains a NUL terminator within its bounds. If `name` is fully populated with 16 non-NUL bytes (e.g. a name exactly 16 characters long, or a record read from disk/network without a trailing terminator), `strlen` walks past the end of `record->name`, over the adjacent `flags` field, and potentially beyond the end of the `struct Record` allocation, reading out-of-bounds memory until it happens to find a zero byte.

## Source

`record->name`, a `uint8_t[16]` field of `struct Record`, treated as a NUL-terminated C string. The caller-supplied `record` pointer is the entry point; nothing in this function (or visible in this file) guarantees `name` is NUL-terminated before `record_name_length` is called.

## Fix

```c
#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct Record {
    uint8_t name[16];
    uint32_t flags;
};

size_t record_name_length(const struct Record *record) {
    return strnlen((const char *)record->name, sizeof(record->name));
}
```

## Explanation

`strnlen` bounds the scan to `sizeof(record->name)` (16) bytes, so it can never read past the end of the `name` array regardless of whether the buffer is NUL-terminated. If no NUL byte is found within the first 16 bytes, `strnlen` simply returns 16 (the full array length) instead of continuing to scan adjacent memory the way `strlen` does. This preserves the function's behavior for the common case (a properly terminated, shorter name) while eliminating the out-of-bounds read for the untrusted or unterminated case, at the cost of a single extra bound argument — no change to the function's signature or callers is required.

If callers need to distinguish "name uses the full 16 bytes with no terminator" from "name is exactly 16 characters plus terminator elsewhere," that distinction should be handled by whoever populates `struct Record` (e.g. by explicitly ensuring termination or by tracking name length separately), not by this length-reading function.
