## Verdict
Exploitable

## Source
The `line` parameter—a 64-byte buffer filled from a raw socket read with no guarantee of a NUL terminator inside its allocation.

## Fix

**Vulnerable code (line 32):**
```c
int fields = sscanf(line, "%7s %s %63s %d", tag, out->nameBuf, out->state, &out->uptimeSeconds);
```

**Fixed code:**
```c
char lineBuf[LINE_CAPACITY + 1];  // +1 for NUL terminator

// Create a NUL-terminated copy of the line to ensure sscanf doesn't
// read past the buffer boundary looking for a string terminator
memcpy(lineBuf, line, LINE_CAPACITY);
lineBuf[LINE_CAPACITY] = '\0';

// Use field widths for all string conversions to prevent buffer overflow
// tag is char[8] -> %7s (7 chars + NUL)
// nameBuf is char[256] -> %255s (255 chars + NUL)  
// state is char[64] -> %63s (63 chars + NUL)
int fields = sscanf(lineBuf, "%7s %255s %63s %d", tag, out->nameBuf, out->state, &out->uptimeSeconds);
```

## Explanation
The vulnerability arises because `sscanf()` with an unwidthed `%s` field scans until it encounters whitespace or a NUL terminator. Since `line` is a 64-byte buffer from a raw socket read that is NOT guaranteed to be NUL-terminated, if the input contains 64 bytes of non-whitespace data, `sscanf()` will read past the buffer's end into adjacent memory. The fix addresses this by: (1) creating a NUL-terminated copy of the input in a temporary buffer that is one byte larger, ensuring `sscanf()` finds a definite terminator at position 64; and (2) adding a field width (`%255s`) to the previously unwidthed `%s` conversion for `out->nameBuf` to enforce a strict upper bound matching the destination buffer size. Both changes together prevent scanning past allocated memory.

## Behaviour changes
- Added a temporary 65-byte stack buffer (`lineBuf`) to hold a NUL-terminated copy of the input. This trades a small amount of stack memory for guaranteed termination semantics.
- Added field width `255` to the second `%s` format specifier. This changes how much data can be scanned into `nameBuf` (maximum 255 characters before) but that constraint was already implicit in CWE-125 remediation guidance—the field width prevents `sscanf()` from reading into adjacent memory when no whitespace is present in the source.
- The sink contract (what `sscanf()` writes into the output fields) is preserved: all three output buffers now receive properly bounded data, and the returned field count is identical.

