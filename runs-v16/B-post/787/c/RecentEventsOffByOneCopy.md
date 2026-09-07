## Verdict

The vulnerability is confirmed. The loop condition contains an off-by-one error that writes beyond the allocated buffer.

## Source

The source of the unsafe index is the loop condition at line 15: `for (size_t i = 0; i <= n; i++)`. The variable `n` (line 12) represents the count of elements to copy; valid indices into `out` are therefore `0` to `n-1`. The loop condition `i <= n` causes the loop to execute when `i == n`, writing to `out[n]`, which is one element past the end of the buffer.

## Fix

Change line 15 from:
```c
    for (size_t i = 0; i <= n; i++) {
```

to:

```c
    for (size_t i = 0; i < n; i++) {
```

The complete corrected function:

```c
/* Copies at most max_out of the most recent entries from history into out.
 * Returns the number of entries copied. */
size_t copy_recent_events(const Event *history, size_t history_len, Event *out, size_t max_out)
{
    size_t n = history_len < max_out ? history_len : max_out;
    size_t start = history_len - n;

    for (size_t i = 0; i < n; i++) {
        out[i] = history[start + i];
    }

    return n;
}
```

## Explanation

An out-of-bounds write occurs because the loop iterates one time too many. The variable `n` represents the count of elements to copy into the destination buffer `out`. Valid array indices for a buffer of size `n` are `0` through `n-1`; an index of `n` accesses one element past the allocated space. The loop condition `i <= n` causes the final iteration to execute when `i` equals `n`, writing to `out[n]`. Changing the condition to `i < n` ensures the loop terminates before exceeding the buffer bounds. This is a standard application of the C-specific guidance in CWE-787: "valid indices are `0` to `size - 1`: a loop written `i <= size` writes one element past the end of every buffer it touches."

## Behaviour changes

- The loop now terminates after exactly `n` iterations instead of `n+1`.
- The function no longer writes to `out[n]`, preventing corruption of adjacent memory.
- The function still returns `n` and copies the same `n` elements from `history` into `out`, preserving the documented contract.
