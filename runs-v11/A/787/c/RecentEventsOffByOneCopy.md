## Verdict
True positive. An off-by-one loop condition causes out-of-bounds write at line 17.

## Source
```c
size_t copy_recent_events(const Event *history, size_t history_len, Event *out, size_t max_out)
{
    size_t n = history_len < max_out ? history_len : max_out;
    size_t start = history_len - n;

    for (size_t i = 0; i <= n; i++) {
        out[i] = history[start + i];
    }

    return n;
}
```

## Fix
Change the loop condition at line 15 from `i <= n` to `i < n`:

```c
for (size_t i = 0; i < n; i++) {
    out[i] = history[start + i];
}
```

## Explanation
The variable `n` holds the count of entries to copy. The loop must iterate from index 0 through n-1 (n iterations total), writing to `out[0]` through `out[n-1]`. The condition `i <= n` iterates one extra time with `i == n`, writing to `out[n]`, which exceeds the allocated buffer size. Changing the condition to `i < n` ensures the loop terminates before reaching the out-of-bounds index.
