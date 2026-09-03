## Verdict

exploitable

## Source

The function parameters `username` and `action` are untrusted inputs passed to `build_audit_message()`. They originate from the caller and are never validated for length.

## Fix

**Vulnerable code:**
```c
char message[64];

strcpy(message, username);
strcat(message, ":");
strcat(message, action);
```

**Fixed code:**
```c
char message[64];

int written = snprintf(message, sizeof message, "%s:%s", username, action);
if (written < 0 || (size_t)written >= sizeof message) {
    return -1;
}
```

## Explanation

The vulnerability exists because `strcpy()` at line 11 copies `username` into a 64-byte stack buffer without checking its length, followed by two `strcat()` calls at lines 12 and 14 that unconditionally append ":" and `action` without verifying the buffer has capacity. If the combined length of `username` + ":" + `action` exceeds 63 bytes (leaving room for the NUL terminator), the buffer overflows, corrupting adjacent stack memory.

The fix replaces these three unbounded operations with a single `snprintf()` call that enforces the destination buffer size internally. The return value is checked to detect truncation: if `snprintf` returns a value indicating the formatted string would not fit (`written >= sizeof message`), the oversized input is rejected explicitly rather than silently truncated or overflowing.

## Behaviour changes

none
