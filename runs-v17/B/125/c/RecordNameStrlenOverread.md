## Verdict

**Out-of-bounds read confirmed.** The call to `strlen()` on line 11 reads a buffer of fixed size 16 bytes without guaranteeing a NUL terminator exists within that allocation. If the buffer is not NUL-terminated, `strlen()` will read past the 16-byte boundary searching for the terminator, causing an out-of-bounds read.

## Source

**File:** `RecordNameStrlenOverread.c`  
**Line:** 11  
**Sink:** `strlen((const char *)record->name)`

The vulnerability occurs because:
- `record->name` is a fixed-size buffer of 16 bytes (`uint8_t name[16]`)
- `strlen()` reads until finding a NUL terminator (`\0`)
- No check ensures a NUL terminator exists within the 16-byte allocation
- If the buffer is filled with 16 non-NUL bytes, `strlen()` will read past the buffer boundary

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

The fix replaces `strlen()` with `strnlen()`, a bounds-safe variant that takes a maximum read size as its second parameter. The call `strnlen((const char *)record->name, sizeof(record->name))` safely computes the string length up to a maximum of 16 bytes, ensuring the function never reads past the buffer boundary. If the buffer contains no NUL terminator within its 16-byte allocation, `strnlen()` returns 16 (the buffer size) rather than reading out-of-bounds. This aligns with the C language guidance in CWE-125, which explicitly prescribes `strnlen()` over `strlen()` for buffers that may lack a NUL terminator within their allocated size.

## Behaviour changes

- **Before:** If `record->name` lacks a NUL terminator, the function reads undefined memory past the 16-byte buffer.
- **After:** The function safely returns the actual string length (if NUL-terminated before byte 16) or 16 (if no terminator found within the buffer).
- **Caller impact:** Code using this function's return value continues to work unchanged. If the caller needs to know whether the buffer lacked a NUL terminator, it can check whether the return value equals `sizeof(record->name)` (16).
