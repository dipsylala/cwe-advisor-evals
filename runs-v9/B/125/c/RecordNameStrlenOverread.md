## Verdict

exploitable (confidence: high)

- cwe_id: CWE-125 (Out-of-bounds Read)
- location: `RecordNameStrlenOverread.c`, line 11, function `record_name_length`

## Source

`record->name`, an 8-bit fixed-size array field (`uint8_t name[16]`) inside `struct Record`. The struct is populated from data outside this file's visible scope (typical for a fixed-width on-the-wire or on-disk record layout); nothing in `record_name_length` or the struct definition guarantees a `NUL` byte appears within the 16 bytes. If the name occupies the full 16-byte field with no terminator - a routine case for fixed-width record formats - the array is not a valid C string.

Assumption: no caller is present in the case file, so the fill origin of `record->name` cannot be traced further; it is treated as untrusted/unterminated data because the field's own type gives no termination guarantee. This lowers confidence slightly but does not change the fix, since the sink is unsafe for any non-terminated input regardless of where it originates.

## Fix

Vulnerable code:

```c
size_t record_name_length(const struct Record *record) {
    return strlen((const char *)record->name);  // reads past name[16] if no NUL is present
}
```

Fixed code:

```c
size_t record_name_length(const struct Record *record) {
    return strnlen((const char *)record->name, sizeof(record->name));
}
```

## Explanation

`strlen()` scans forward from the pointer until it finds a `NUL` byte, with no awareness of the array's actual 16-byte capacity; if `name` is filled to all 16 bytes with no terminator, the scan reads `flags` and then whatever memory follows the struct, which is an out-of-bounds read (CWE-125) with undefined behaviour. Replacing it with `strnlen((const char *)record->name, sizeof(record->name))` bounds the scan to the field's real allocated size, per the CWE-125 C guidance's `strnlen` taint-sink replacement pattern: the function still returns the length up to the first `NUL`, but can never read past the 16 bytes that belong to `name`, and caps the returned length at 16 when no terminator is present instead of continuing to read adjacent memory.

## Behaviour changes

- Return value when `name` has no `NUL` within its 16 bytes: previously undefined (whatever byte sequence follows in memory happened to contain a zero, or a crash) - now deterministically `16` (`sizeof(record->name)`), meaning "no terminator found within capacity." This is the intended safe substitution named in the CWE-125 C guidance, not an unrelated behaviour change: the function's contract - "length of the name" - is preserved for every terminated input, and is now well-defined instead of undefined for unterminated input.
- All other behaviour is unchanged: same signature, same return type, same result for any `name` that does contain a `NUL` within the first 16 bytes.
