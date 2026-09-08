## Verdict

Exploitable. CWE-125 (Out-of-bounds Read), high confidence.

## Source

`struct Record.name`, a fixed 16-byte `uint8_t` array (`RecordNameStrlenOverread.c:6`) that is not guaranteed to contain a NUL terminator within its 16 bytes - the struct's own layout gives no such guarantee, and no code in this file establishes one before the field is read as a string. Any `Record` populated from outside this function (parsed from a file, network buffer, or other external data) can carry a `name` field with no NUL byte in any of its 16 bytes.

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

`record_name_length()` called `strlen()` on `record->name`, which scans forward from the array's start until it finds a byte equal to `0`. Because `name` is a fixed 16-byte array with no guarantee of an embedded NUL, `strlen()` can walk past the end of the array - into the padding, into `flags`, and past the end of the struct's allocation entirely - reading memory that does not belong to `name`, which is the out-of-bounds read the finding identifies. The fix replaces `strlen()` with `strnlen((const char *)record->name, sizeof(record->name))`, which caps the scan at the array's own 16-byte capacity: `strnlen` returns the offset of the first NUL if one is found within those 16 bytes, and returns exactly 16 - never more - if none is found, so the read can never leave the array regardless of the field's content. `sizeof(record->name)` is used rather than a literal `16` so the bound stays correct if the field's declared size ever changes. `string.h`, already included, declares `strnlen` as well as `strlen`, so no new include is needed.

## Behaviour changes

- Return value when `name` has no NUL within its 16 bytes: previously undefined (the out-of-bounds read could return any value depending on adjacent memory, or crash); now deterministically returns `16`, meaning "the name occupies the full field width with no terminator." This is the direct consequence of closing the weakness, not an independent behaviour change - `16` is the correct length for a full, unterminated fixed-width name field, and no caller-visible contract is available in this file to check the new value against, since the file exposes only this one function with no visible callers.
- Return value when `name` does contain a NUL within its 16 bytes: unchanged - `strnlen` and `strlen` agree exactly in this case.
- No arguments, includes, or the function's signature/return type were altered.

## Verification

No C compiler (`gcc`, `clang`, `cc`, MSVC `cl`) was reachable in this environment, so the fix was checked by hand instead: `strnlen` is declared in `<string.h>` (already included) with signature `size_t strnlen(const char *s, size_t maxlen)`, matching the call `strnlen((const char *)record->name, sizeof(record->name))` - the cast matches the one already used for `strlen`, and `sizeof(record->name)` is a `size_t` matching `strnlen`'s second parameter. The function's return type (`size_t`) and signature are unchanged from the original, and the file has no other callers or references to update.
