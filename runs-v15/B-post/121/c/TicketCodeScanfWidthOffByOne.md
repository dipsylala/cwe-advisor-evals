## Verdict

exploitable

## Source

Standard input (stdin) via `scanf("%s", code)` at line 9. User input is read with no length limit.

## Fix

**Vulnerable code (line 9):**
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

The vulnerability is an unbounded `scanf("%s", ...)` call that reads user input into a 16-byte stack buffer (`char code[16]`). Without a width specifier, `scanf` will read input characters until it encounters whitespace, writing far beyond the buffer's capacity and corrupting adjacent stack memory. The fix adds a width specifier `%15s` to limit input to exactly 15 characters, leaving one byte for the automatic null terminator that `scanf` adds. This bounds all writes to the destination buffer's declared size and eliminates the overflow.

## Behaviour changes

none
