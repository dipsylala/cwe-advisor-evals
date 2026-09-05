## Verdict

**Exploitable**

## Source

stdin (user input from the command line)

## Fix

**Vulnerable Code (line 9):**
```c
int read_command_line(char *out, size_t out_capacity)
{
    char line[64];

    // SAST FINDING: CWE-121 (Stack-based Buffer Overflow) reported here. Sink is the next statement.
    gets(line);

    size_t len = strlen(line);
    if (len >= out_capacity) {
        return -1;
    }
    strcpy(out, line);
    return 0;
}
```

**Fixed Code:**
```c
int read_command_line(char *out, size_t out_capacity)
{
    char line[64];

    // Use fgets with explicit size limit to prevent buffer overflow
    if (fgets(line, sizeof(line), stdin) == NULL) {
        return -1;  // EOF or read error
    }

    // Check if the line was completely read (look for newline)
    // If no newline, the input was truncated; drain the rest and reject
    size_t len = strlen(line);
    if (line[len - 1] != '\n') {
        // Input was truncated; drain remaining characters
        int c;
        while ((c = getchar()) != '\n' && c != EOF)
            ;
        return -1;  // Reject oversized input
    }

    // Remove the trailing newline before length check
    line[len - 1] = '\0';
    len--;

    if (len >= out_capacity) {
        return -1;
    }
    strcpy(out, line);
    return 0;
}
```

## Explanation

The original code uses `gets(line)`, which reads from stdin into a 64-byte stack buffer with no size limit. An attacker can provide more than 64 bytes of input to corrupt the stack, including the saved return address, enabling code execution. The fix replaces `gets()` with `fgets(line, sizeof(line), stdin)`, which enforces a size limit at the read point. Additionally, the fix checks whether the entire line was read by looking for a newline character; if the newline is absent, the input was truncated (meaning more data remains in the input stream), so the code drains the excess and rejects the input rather than silently truncating. This prevents an attacker from forcing truncation as a side-channel to bypass length validation. The trailing newline inserted by `fgets()` is removed before the subsequent length check and copy, preserving the original contract where `line` contains the command text without the line terminator.

## Behaviour changes

- **Return value on EOF or read error**: the original code did not explicitly check the return value of `gets()` (which returns NULL on EOF); the fixed code now returns -1 on read failure, making the error case explicit and safely handled.
- **Input too long (truncation)**: the original code silently truncated input longer than 63 characters, allowing the excess to be read as a subsequent command on the next call. The fixed code now drains the remaining input and rejects the entire command, preventing truncation-based bypasses.
- **Newline character**: `fgets()` includes the trailing newline in the buffer (if the line is complete), whereas `gets()` removed it. The fixed code explicitly removes the newline after checking its presence, restoring the original behaviour for complete lines.
- **Caller responsibility**: the caller now must handle the additional -1 return value (EOF/read error, or truncation) in addition to the existing -1 case (output buffer too small). Both are distinct error conditions that should be handled the same way (reject the operation), so the caller sees no functional change.
