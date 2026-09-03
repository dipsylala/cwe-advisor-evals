## Verdict

Exploitable. The call to `strlen()` on line 11 reads the fixed-size `record->name` buffer without bounds checking. If the buffer does not contain a NUL terminator within its 16-byte allocation, `strlen()` will read past the buffer end, causing an out-of-bounds read.

## Source

The `name` field is defined as `uint8_t name[16]` in the struct Record (line 6). This fixed-size buffer is passed to `strlen()` without validation that a NUL terminator exists within its bounds.

## Fix

**Vulnerable code (line 11):**
```c
return strlen((const char *)record->name);
```

**Fixed code:**
```c
return strnlen((const char *)record->name, sizeof(record->name));
```

## Explanation

The fix replaces `strlen()` with `strnlen()`, which bounds the search for a NUL terminator to the buffer's actual allocated size (16 bytes). This prevents `strlen()` from reading past the buffer end. If no NUL terminator is found within the 16-byte allocation, `strnlen()` returns 16, signaling to the caller that the buffer is not properly NUL-terminated. The caller can then handle this condition (e.g., reject malformed input or copy only the available bytes), rather than silently reading into memory it does not own.

## Behaviour changes

The function's return type and interface remain identical. The only change is that `strnlen()` bounds the search operation, preventing out-of-bounds reads. If the original buffer always contained a NUL terminator within 16 bytes, the return value is unchanged. If the buffer lacked a terminator (the vulnerability scenario), `strnlen()` now safely returns 16 instead of continuing to read past the allocation.
