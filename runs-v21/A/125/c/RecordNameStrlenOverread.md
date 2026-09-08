## Verdict
CONFIRMED. The call to `strlen()` on a fixed-size array without null-termination guarantee performs an out-of-bounds read.

## Source
`strlen()` scans the buffer for a null terminator without respecting array bounds. The `name` field is a 16-byte `uint8_t` array; if all 16 bytes are occupied with data (no null terminator), `strlen()` reads past the buffer boundary.

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
Replace `strlen()` with `strnlen()`, passing `sizeof(record->name)` as the maximum length. `strnlen()` scans for a null terminator but stops at the buffer boundary, preventing reads beyond the 16-byte allocation. This bounds the search to the actual data size and eliminates the out-of-bounds read vulnerability.
