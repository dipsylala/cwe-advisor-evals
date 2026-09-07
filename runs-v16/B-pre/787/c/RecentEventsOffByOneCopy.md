## Verdict

exploitable

## Source

The function parameter `history`, accessed via `history[start + i]` on line 17. The value written is drawn from the source buffer and controlled by the caller.

## Fix

**Vulnerable code:**
```c
for (size_t i = 0; i <= n; i++) {
    // SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
    out[i] = history[start + i];
}
```

**Fixed code:**
```c
for (size_t i = 0; i < n; i++) {
    out[i] = history[start + i];
}
```

## Explanation

The loop condition `i <= n` causes an off-by-one error that writes one element past the destination buffer's allocated capacity. The variable `n` holds the count of elements to copy (clamped to `max_out`), so valid indices for `out` are `0` to `n-1`. Changing the loop condition to `i < n` ensures the loop iterates exactly `n` times, writing to indices `0` through `n-1` only, eliminating the out-of-bounds write.

## Behaviour changes

none

The fix preserves the function's contract: it still copies exactly `n` elements from the source to the destination and returns `n`. No arguments are added or removed, no implicit parameters change, and the return value and semantics are identical.
