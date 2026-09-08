## Verdict

exploitable

- cwe_id: CWE-125 (Out-of-bounds Read)
- location: `SscanfMissingFieldWidth.c`, line 32, function `parsePeerStatusLine`
- confidence: high

## Source

`line`, the `const char line[LINE_CAPACITY]` parameter of `parsePeerStatusLine`. Per the function's own doc comment, `line` is filled by a raw socket read that copies in exactly the number of bytes received and never appends a NUL terminator. A peer that sends `LINE_CAPACITY` (64) bytes containing no whitespace and no `\0` produces a buffer that is completely full of scannable, non-terminating data before `line` ever reaches this function - the source is attacker-controlled network input with no length or content guarantee beyond "at most 64 bytes were copied in."

## Fix

### File: SscanfMissingFieldWidth.c

```c
#include <stdio.h>
#include <string.h>

#define LINE_CAPACITY 64

/*
 * Parses a fixed-format peer status line of the form:
 *   "STATUS <peerName> <state> <uptimeSeconds>"
 * The line buffer is filled by a raw socket read that copies in exactly
 * the number of bytes actually received and does not append a NUL
 * terminator, so a peer that sends LINE_CAPACITY bytes with no whitespace
 * or NUL anywhere in them leaves the buffer completely full of scannable
 * data with nothing inside its allocation to stop sscanf's %s conversion.
 * The destination fields are deliberately larger than any legitimate
 * value, so the write side is not the limiting factor here - the bug is
 * that the unwidthed %s has to keep reading line looking for a delimiter,
 * and can run past line's own LINE_CAPACITY-byte allocation to find one.
 */
typedef struct {
    char nameBuf[256];
    char state[64];
    int uptimeSeconds;
} PeerStatus;

int parsePeerStatusLine(const char line[LINE_CAPACITY], PeerStatus *out)
{
    char tag[8];

    memset(out, 0, sizeof(*out));

    /* line comes from a raw socket read that does not guarantee a NUL
     * terminator inside its LINE_CAPACITY-byte allocation. sscanf has no
     * way to know where that allocation ends, so confirm a terminator is
     * present within it before scanning; otherwise every %s conversion
     * below is free to run past the buffer looking for a stopping point. */
    if (strnlen(line, LINE_CAPACITY) == LINE_CAPACITY) {
        return -1;
    }

    int fields = sscanf(line, "%7s %255s %63s %d", tag, out->nameBuf, out->state, &out->uptimeSeconds);

    if (fields != 4 || strcmp(tag, "STATUS") != 0) {
        return -1;
    }

    return 0;
}
```

## Explanation

Two changes close the weakness, matching the C-specific guidance for `sscanf()`: a literal field width one smaller than the destination array, and confirmation that the source is NUL-terminated inside its own allocation before scanning. First, the previously unwidthed `%s` targeting `out->nameBuf` (a `char[256]`) is given a literal width of `%255s`; C has no dynamic/run-time field width (`%*s` means suppress assignment, not "take the width from an argument"), so the width has to be a compile-time literal matching the destination's real capacity, consistent with the `%7s`/`%63s` widths already used for `tag` and `out->state`. Second, and this is what actually stops the out-of-bounds read, the code now calls `strnlen(line, LINE_CAPACITY)` before any scanning and rejects the line if it returns `LINE_CAPACITY` - that return value means no NUL byte exists anywhere in `line`'s 64-byte allocation, which is exactly the condition under which `sscanf`'s `%s` conversions (bounded or not) would otherwise keep consuming memory past the end of `line` looking for whitespace or a terminator. Confirming the terminator is present first means every `%s` conversion is guaranteed to encounter either whitespace or the confirmed NUL no later than byte 63, so none of them can read past `line`'s real allocation. The field-width change alone would not have been sufficient: it only bounds how much could be written into `out->nameBuf`, not how far `sscanf` reads from an unterminated `line` before hitting that bound.

## Behaviour changes

- A `line` value that fills all 64 bytes with non-whitespace, non-NUL data now causes `parsePeerStatusLine` to return `-1` immediately, before any scanning is attempted. Previously this input triggered undefined behaviour (an out-of-bounds read of unspecified extent). The new return value reuses the function's existing "malformed input" contract - it already returns `-1` for a short field count or a mismatched tag - so callers do not need a new failure branch; this is not a new failure mode, only a new path into the failure mode that already exists.
- The second `%s` conversion (into `out->nameBuf`) is now capped at 255 characters instead of being unbounded. Per the function's own doc comment, `out->nameBuf`'s 256-byte capacity is "deliberately larger than any legitimate value," so this cap does not affect any well-formed input; it only bounds what an oversized, non-whitespace-delimited value can write, as defense-in-depth alongside the `strnlen` check, matching the pattern already used for `tag` (`%7s`) and `out->state` (`%63s`).
- No other argument, return value, or control-flow path in the function changed. `fields != 4` and `strcmp(tag, "STATUS") != 0` checks are untouched, and `memset` still zero-initializes `*out` on every call.

## Verification

No C compiler (`gcc`, `cc`, `clang`) was reachable in this environment, so the fix was checked by manual read rather than by compiling it, per the skill's fallback path. Confirmed by inspection:
- `strnlen` is declared in `<string.h>`, which the file already includes; no new `#include` is needed.
- `strnlen(line, LINE_CAPACITY)`'s signature (`const char *, size_t`) matches the call: `line` decays to `const char *`, and `LINE_CAPACITY` is the same macro already used for the parameter's declared array bound, so the size argument matches the buffer's real capacity exactly.
- The `sscanf` call's format string still has exactly four conversions matching its four variadic arguments (`tag`, `out->nameBuf`, `out->state`, `&out->uptimeSeconds`), in the same order and with the same argument types as before; only the literal width token on the second conversion changed (`%s` to `%255s`).
- `out->nameBuf` is declared `char nameBuf[256]`, so `%255s` (writes at most 255 characters plus a NUL terminator) cannot overflow it.
- Both the new `if` block and the pre-existing code after it return `int` on every path, matching the function's declared return type; no signature or caller-visible type changed.
