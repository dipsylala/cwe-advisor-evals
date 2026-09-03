## Verdict

Exploitable. The `scanf("%s", code)` call on line 9 is an unbounded-read taint sink listed in CWE-121's C guidance. The format specifier `%s` reads until whitespace or EOF with no limit, and can write far beyond the 16-byte `code` buffer's capacity, corrupting adjacent stack memory.

## Source

Standard input (user-provided via `scanf`).

## Fix

Replace `scanf("%s", code)` with `fgets(code, sizeof code, stdin)` to bound the read to the buffer's actual capacity. Handle the newline character that `fgets` includes and detect truncation by checking whether the buffer was filled without a newline; if truncated, drain the remaining input and reject.

### Vulnerable Code
```c
int read_ticket_code(char *out, size_t out_capacity)
{
    char code[16];

    // SAST FINDING: CWE-121 (Stack-based Buffer Overflow) reported here. Sink is the next statement.
    if (scanf("%s", code) != 1) {
        return -1;
    }

    if (strlen(code) >= out_capacity) {
        return -1;
    }
    strcpy(out, code);
    return 0;
}
```

### Fixed Code
```c
int read_ticket_code(char *out, size_t out_capacity)
{
    char code[16];

    // Use fgets to bound the input read into code
    if (fgets(code, sizeof code, stdin) == NULL) {
        return -1;
    }

    // Remove trailing newline if present; detect truncation
    size_t len = strlen(code);
    if (len > 0 && code[len - 1] == '\n') {
        code[len - 1] = '\0';
        len--;
    } else if (len == sizeof code - 1) {
        // Buffer was filled without a newline - line was truncated
        // Drain the rest of the line and reject
        int c;
        while ((c = getchar()) != EOF && c != '\n');
        return -1;
    }

    if (len >= out_capacity) {
        return -1;
    }
    strcpy(out, code);
    return 0;
}
```

## Explanation

The vulnerability arises because `scanf("%s", code)` applies no size limit, reading until whitespace or end-of-file. Input longer than 15 bytes (one reserved for the null terminator in a 16-byte buffer) overflows `code` and corrupts adjacent stack memory. The fix replaces `scanf` with `fgets(code, sizeof code, stdin)`, which bounds the read to the buffer's declared size and includes the newline in the buffer if the line fits entirely. After removing the newline (which `scanf` would have discarded), the code checks for truncation: if the buffer filled completely but contains no newline, the input line was longer than the buffer allows, so the remaining input is drained from stdin and the call is rejected. This preserves the original function's contract—rejecting oversized input rather than silently truncating it—while closing the overflow.

## Behaviour changes

- **Error handling changed**: `fgets` returns `NULL` on error or EOF (distinct from truncation), whereas `scanf` returns 0 on matching failure. The check is updated accordingly.
- **Input handling changed**: `fgets` retains the newline in the buffer if the line is complete; the fixed code removes it to restore input equivalence with `scanf`, which discards whitespace.
- **Truncation detection added**: The original code did not detect when input exceeded the buffer; truncated input proceeded silently. The fixed code drains and rejects oversized input, making the boundary explicit rather than hidden.
- **getchar() calls added to drain input**: When truncation is detected, remaining input is consumed from stdin so the next read does not inherit leftover bytes.

