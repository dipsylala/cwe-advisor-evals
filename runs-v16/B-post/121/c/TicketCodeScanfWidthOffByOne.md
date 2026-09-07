## Verdict

Exploitable - The fixed-size stack buffer `code[16]` can receive unbounded input via `scanf("%s", ...)`, allowing any attacker-supplied string longer than 16 bytes to overflow the buffer and corrupt adjacent stack memory.

## Source

Attacker-controlled user input supplied via stdin and read by `scanf("%s", code)` on line 9.

## Fix

**Vulnerable code:**
```c
if (scanf("%s", code) != 1) {
    return -1;
}
```

**Fixed code:**
```c
if (scanf("%15s", code) != 1) {
    return -1;
}
```

## Explanation

The buffer `code` is declared with capacity 16 bytes. The format specifier `%s` in `scanf` with no width limit reads an entire whitespace-delimited string, which can exceed the buffer's capacity. Replacing `%s` with `%15s` restricts input to 15 characters, leaving 1 byte for the null terminator `scanf` automatically appends. This prevents any input longer than 15 characters from being written into the buffer, closing the stack overflow.

## Behaviour changes

Input strings longer than 15 characters are silently truncated by `scanf` rather than causing a buffer overflow. The function returns success (0) when truncation occurs; the caller receives the truncated code in the `out` buffer. The original code's post-copy length check against `out_capacity` remains valid and will still reject the truncated code if it does not fit into the caller's buffer.

Note: The C CWE-121 guidance recommends validating and explicitly rejecting truncated input rather than passing a silently truncated value downstream. A production fix should detect truncation (by peeking for remaining input with `getchar()` and draining to the next newline if data remains unread) and return an error. This minimal fix closes the stack overflow; a complete fix should add explicit truncation detection.
