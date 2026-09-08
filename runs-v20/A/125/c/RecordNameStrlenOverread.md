## Verdict
Confirmed: `strlen()` on `record->name` reads past the 16-byte fixed-size array if the buffer is not null-terminated (e.g., a caller fills all 16 bytes with a non-terminated name), scanning into adjacent struct memory (`flags`) and beyond until a zero byte happens to be found.

## Source
`record->name` is a fixed-size `uint8_t[16]` array with no guarantee of null-termination from the struct definition alone; `record_name_length()` treats it as a bounded-length C string via `strlen()`.

## Fix

### File: RecordNameStrlenOverread.c
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
`strlen()` has no concept of the underlying buffer's size and will keep scanning past the end of `record->name` into `flags` and beyond if no null byte occurs within the first 16 bytes, causing an out-of-bounds read. Replacing it with `strnlen(record->name, sizeof(record->name))` bounds the scan to the array's actual size: it returns the same length as `strlen()` when the name is properly terminated within the buffer, and safely returns `sizeof(record->name)` (16) instead of reading further when it is not. This is the minimal, non-breaking change — callers that already rely on a null-terminated name see identical behavior, and callers with a full 16-byte non-terminated name no longer trigger undefined behavior.
