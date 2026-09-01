## Verdict

**Confirmed**: Integer overflow in allocation size calculation. When `count * sizeof(ProductRow)` overflows `size_t`, the multiplication wraps to a small value. The allocation becomes undersized, and the subsequent loop writes past the allocated buffer into adjacent memory.

## Source

The vulnerability is in `load_product_batch()` at the point of allocation (line 21-22):

```c
size_t bytes = count * sizeof(ProductRow);
batch->rows = malloc(bytes);
```

When the caller supplies a large `count` value (specifically, `count > SIZE_MAX / sizeof(ProductRow)`), the multiplication overflows and wraps to a smaller value. The `malloc()` allocates fewer bytes than the loop will later write.

The loop at line 29-32 then writes:

```c
for (size_t i = 0; i < count; i++) {
    batch->rows[i] = input[i];
}
```

This writes `count` elements into an undersized allocation, corrupting heap memory.

## Fix

Replace the manual multiplication and `malloc()` call with `calloc()`:

**Original (lines 21-26):**
```c
    size_t bytes = count * sizeof(ProductRow);
    batch->rows = malloc(bytes);
    if (batch->rows == NULL) {
        free(batch);
        return NULL;
    }
```

**Fixed:**
```c
    batch->rows = calloc(count, sizeof(*batch->rows));
    if (batch->rows == NULL) {
        free(batch);
        return NULL;
    }
```

## Explanation

`calloc(count, size)` performs the multiplication `count * size` internally and detects overflow before allocation occurs. If the multiplication would overflow, `calloc()` fails and returns NULL. This replaces the manual multiplication that silently wraps on overflow.

The fix preserves the error-handling contract: both paths return NULL on allocation failure. `calloc()` also zero-initializes the memory, which is safe for this use case (copying ProductRow structures over it).

## Behaviour changes

- **Allocation size validation**: Oversized count values that would cause integer overflow now result in allocation failure (NULL return) instead of undersized allocation and out-of-bounds write.
- **Memory initialization**: Allocated memory is zero-initialized (calloc behavior) instead of containing arbitrary data (malloc behavior). For this code path, this is a benign side effect since the memory is immediately populated by the copy loop.
- **Error reporting**: Callers receive a NULL return when count exceeds SIZE_MAX / sizeof(ProductRow), allowing them to handle the error appropriately.
