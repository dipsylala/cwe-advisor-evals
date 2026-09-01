## Verdict

Out-of-bounds read confirmed. The call to `strlen()` on a fixed-size buffer without guaranteed NUL termination will read past the 16-byte boundary of `record->name` if no NUL terminator exists within the allocation.

## Source

`record->name` is a 16-byte buffer embedded in the `Record` struct. The caller has full control over its contents via the function parameter `const struct Record *record`. No constraint guarantees a NUL terminator within the buffer's allocation.

## Fix

Line 11, replace:
```c
return strlen((const char *)record->name);
```

With:
```c
return strnlen((const char *)record->name, sizeof(record->name));
```

## Explanation

`strlen()` scans memory until it finds a NUL terminator, with no bounds check. If all 16 bytes are filled with non-NUL data, the function will read past the buffer into adjacent memory. `strnlen()` takes a maximum length parameter and stops scanning at that limit or upon finding a terminator, whichever comes first. Using `sizeof(record->name)` as the limit ensures the read stays within the 16-byte allocation. The function still correctly returns the length of the string up to 16 characters, or 16 if no terminator is found within the buffer.

## Behaviour changes

- If `record->name` contains a NUL terminator before byte 16, `strnlen()` returns the same result as `strlen()` would have.
- If all 16 bytes are filled with non-NUL data, `strlen()` causes an out-of-bounds read; `strnlen()` returns 16 without reading past the buffer.
- Return type remains `size_t`; no change to the function signature or caller expectations.
