## Verdict

Out-of-bounds read vulnerability confirmed. `strlen()` reads indefinitely past the buffer boundary if the 16-byte `name` field lacks a NUL terminator.

## Source

Line 11 in `RecordNameStrlenOverread.c` calls `strlen()` on `record->name`, a fixed-size `uint8_t[16]` buffer with no guaranteed NUL termination. If the buffer does not contain a NUL terminator within its allocated 16 bytes, `strlen()` continues reading into adjacent memory, causing an out-of-bounds read.

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
    size_t len = strnlen((const char *)record->name, sizeof(record->name));
    if (len == sizeof(record->name)) {
        // Name is not NUL-terminated within allocated space
        return 0;
    }
    return len;
}
```

## Explanation

The fix replaces `strlen()` with `strnlen()`, which accepts a maximum length parameter to prevent reading past the buffer. `strnlen(buf, cap)` searches for a NUL terminator but stops after reading `cap` bytes, returning either the string length (if a terminator is found within `cap` bytes) or `cap` itself (if no terminator is found).

The fix adds an explicit check: if `strnlen()` returns the full buffer size (16), it means no NUL terminator was found within the buffer, indicating corrupted or improperly initialized data. Returning 0 in this case signals that no valid null-terminated string exists, preventing the caller from treating unterminated buffers as valid strings while also preventing further out-of-bounds reads.

## Behaviour changes

- **Original**: Reads past the buffer boundary if no NUL terminator exists, causing undefined behavior.
- **Fixed**: Limits the read to exactly 16 bytes, and explicitly detects non-terminated buffers by checking if `strnlen()` returns the full capacity. Returns 0 for any buffer lacking a NUL terminator within its allocated space, signaling corrupted data rather than attempting to read further.
- **Impact**: Callers receive 0 for malformed records, where the original would have read garbage data. This is the correct behavior when the record's name field is not a proper C string.
