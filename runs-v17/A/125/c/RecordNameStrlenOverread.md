## Verdict

CONFIRMED: Out-of-bounds read via unbounded `strlen()` on fixed-size buffer.

## Source

The vulnerable code calls `strlen()` on a 16-byte fixed-size array without ensuring it contains a null terminator:

```c
struct Record {
    uint8_t name[16];
    uint32_t flags;
};

size_t record_name_length(const struct Record *record) {
    return strlen((const char *)record->name);  // Line 11: OOB read
}
```

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

The vulnerability occurs because `strlen()` scans memory byte-by-byte until finding a null terminator (`\0`). If the 16-byte `name` array is not null-terminated within its bounds, `strlen()` reads beyond the struct, causing an out-of-bounds read.

The fix uses `strnlen()`, which accepts a maximum length parameter. By passing `sizeof(record->name)` (16 bytes), the function is bounded to read at most 16 bytes from the `name` field, preventing reads beyond the struct. If no null terminator exists within the 16 bytes, `strnlen()` safely returns 16 without overreading.

E:/Github/cwe-advisor/evals/runs-v17/A/125/c/RecordNameStrlenOverread.md