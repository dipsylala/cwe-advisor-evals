## Verdict

**VULNERABLE.** The `sprintf()` call at line 16 writes to a fixed 64-byte buffer without bounds checking. The three format arguments—timestamp, username, and message—are stated to be attacker-controlled in length. There is no mechanism to prevent them from exceeding the buffer capacity.

## Source

```c
char line[64];
sprintf(line, "[%s] %s: %s", timestamp, username, message);
```

Line 16 in `SprintfFixedBufferOverflow.c`: `sprintf()` performs unbounded writes to `line` based on the lengths of three user-supplied strings.

## Fix

Replace `sprintf()` with `snprintf()` and specify the buffer size:

```c
char line[64];
snprintf(line, sizeof(line), "[%s] %s: %s", timestamp, username, message);
```

`snprintf()` enforces an upper bound on the number of bytes written and truncates the output to fit within the buffer, preventing overflow.

## Explanation

`sprintf()` has no way to know the size of the destination buffer and trusts the caller to ensure it is large enough. When the formatted output exceeds 63 bytes (the usable space in a 64-byte buffer before the null terminator), the write proceeds past the buffer boundary, overwriting adjacent memory.

`snprintf(buffer, size, fmt, ...)` writes at most `size - 1` bytes to `buffer` plus a terminating null byte, ensuring the write never exceeds the buffer. The truncated message is still logged, but the buffer is protected.

Alternatively, for applications that cannot tolerate truncation, allocate a dynamic buffer sized to the actual input:

```c
int len = snprintf(NULL, 0, "[%s] %s: %s", timestamp, username, message);
if (len < 0) return -1;

char *line = malloc(len + 1);
if (!line) return -1;

snprintf(line, len + 1, "[%s] %s: %s", timestamp, username, message);
// ... use line ...
free(line);
```

This approach formats once to get the final length, then allocates exactly enough space and formats again into it.
