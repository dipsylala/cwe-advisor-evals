## Verdict

Exploitable. Integer overflow in the size calculation `count * sizeof(ProductRow)` causes `malloc()` to allocate a smaller buffer than the loop will write to.

## Source

The `count` parameter to `load_product_batch()`, which is not validated for overflow before the multiplication at line 21.

## Fix

**Vulnerable code:**
```c
size_t bytes = count * sizeof(ProductRow);
batch->rows = malloc(bytes);
if (batch->rows == NULL) {
    free(batch);
    return NULL;
}
```

**Fixed code:**
```c
batch->rows = calloc(count, sizeof(ProductRow));
if (batch->rows == NULL) {
    free(batch);
    return NULL;
}
```

## Explanation

The vulnerability is an integer overflow: if `count` is very large (greater than `SIZE_MAX / sizeof(ProductRow)`), the multiplication `count * sizeof(ProductRow)` overflows and wraps to a small value. This causes `malloc()` to allocate far fewer bytes than the subsequent loop will write. The fix replaces the manual multiplication and `malloc()` with `calloc(count, sizeof(ProductRow))`, which performs the overflow check internally before allocation. If the multiplication would overflow, `calloc()` returns `NULL`, allowing the function to fail safely rather than proceed with an undersized buffer.

## Behaviour changes

- `calloc()` returns zero-initialized memory, whereas the original `malloc()` returned uninitialized memory. This is a beneficial side effect that hardens the code through defense-in-depth initialization.
- The intermediate `bytes` variable is eliminated; its sole purpose was to hold the product for the `malloc()` call, which is now unnecessary.
- The return value contract and error handling remain unchanged: `calloc()` returns `NULL` on failure, matching the original `malloc()` behavior.
