## Verdict

exploitable (confidence: high)

CWE-121, Stack-based Buffer Overflow. `append_display_name` writes an attacker-controlled `first`/`last` combination into a fixed 32-byte stack buffer with no length check anywhere in the call chain, so any combined name of 31 characters or more (counting the joining space) overflows adjacent stack memory.

## Source

- **Source**: the `first` and `last` parameters of `render_badge_line` (lines 9-13) - external, unvalidated name fields (e.g. a badge/profile name) with no length constraint applied before use.
- **Sink**: `strcat(destination, last)` at line 6, inside `append_display_name` (lines 3-7). `destination` is the caller's `display_name[32]`, a fixed-size stack array declared at line 10.
- **Flow**: `render_badge_line` declares `char display_name[32]` and passes it straight to `append_display_name`, which performs `strcpy(destination, first)` (line 4, already unbounded), `strcat(destination, " ")` (line 5), then `strcat(destination, last)` (line 6, the flagged sink). None of the three calls is aware that `destination` has only 32 bytes - `sizeof(destination)` inside `append_display_name` would yield a pointer size, not the buffer's capacity, so the capacity has to be passed in explicitly. The combined length of `first` + `" "` + `last` is unconstrained, so any input whose total exceeds 31 characters overflows `display_name` and corrupts adjacent stack memory in `render_badge_line`.

## Fix

Vulnerable code:

```c
#include <string.h>

static void append_display_name(char *destination, const char *first, const char *last) {
    strcpy(destination, first);
    strcat(destination, " ");
    strcat(destination, last);      /* CWE-121 sink: unbounded write into a fixed-size stack buffer */
}

void render_badge_line(const char *first, const char *last, char *out) {
    char display_name[32];
    append_display_name(display_name, first, last);
    strcpy(out, display_name);
}
```

Fixed code:

```c
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool append_display_name(char *destination, size_t destination_size,
                                  const char *first, const char *last) {
    int written = snprintf(destination, destination_size, "%s %s", first, last);
    if (written < 0 || (size_t)written >= destination_size) {
        return false; /* combined name does not fit: reject rather than truncate */
    }
    return true;
}

bool render_badge_line(const char *first, const char *last, char *out) {
    char display_name[32];
    if (!append_display_name(display_name, sizeof display_name, first, last)) {
        return false;
    }
    strcpy(out, display_name);
    return true;
}
```

## Explanation

The fix replaces the two unbounded `strcpy`/`strcat` calls with a single `snprintf(destination, destination_size, "%s %s", first, last)`, which bounds both operands and the terminator against the destination's real capacity in one call, following the language guidance's preferred pattern over chained `strcpy`/`strcat`. `append_display_name` now takes an explicit `destination_size` parameter - since a buffer passed as a function argument decays to a pointer, `sizeof` inside the callee can't recover the caller's 32-byte capacity, so the size has to travel with the pointer; the call site passes `sizeof display_name`, the only place the true array size is still visible. `snprintf`'s return value is checked for both an encoding error (`written < 0`) and truncation (`written >= destination_size`); on either, the function rejects the input and returns `false` instead of writing a truncated name, per the guidance's preference for explicit rejection over silent truncation - a truncated name is a different value the rest of the program would otherwise treat as the caller's real input. This closes the write into `display_name` at its source; the final `strcpy(out, display_name)` is now safe because `display_name` is guaranteed null-terminated and at most 31 characters, well within its own 32-byte bound.

## Behaviour changes

- **Return type added**: `append_display_name` now returns `bool` instead of `void`, and `render_badge_line` now returns `bool` instead of `void`. Reason: the guidance calls for rejecting oversized input rather than truncating it, which requires a way to signal failure back to the caller; a `void` function has no such channel.
- **New parameter**: `append_display_name` gains a `destination_size` parameter. Reason: `snprintf` needs the destination's real capacity, and that capacity is not recoverable inside the callee once the array has decayed to a pointer.
- **On oversized input, `out` is left unwritten** instead of receiving a silently truncated name (the original code, being unbounded, never truncated - it overflowed instead). Reason: this is the direct consequence of the reject-not-truncate fix; a caller must now check the return value to know whether `out` was populated.
- **`out`'s buffer capacity is unchanged and still unverified by this function** - `strcpy(out, display_name)` remains a plain `strcpy`. This is unaffected by the CWE-121 finding, which is scoped to the `display_name` stack buffer; `out`'s size is part of `render_badge_line`'s pre-existing external contract with its own caller, not something introduced or altered by this fix. If `out`'s capacity is not independently guaranteed to be at least 32 bytes, that is a separate finding the caller should address.
