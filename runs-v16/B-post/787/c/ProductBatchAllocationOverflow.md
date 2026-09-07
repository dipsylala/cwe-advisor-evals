## Verdict

Out-of-bounds write confirmed. Integer overflow in allocation size calculation on line 21 allows a caller-supplied `count` value to wrap the multiplication `count * sizeof(ProductRow)` to a small allocation size, after which the loop at lines 29-32 writes past the end of the allocated buffer.

## Source

The vulnerability originates in the untrusted `count` parameter passed to `load_product_batch()`. No validation occurs before this value is used in the size calculation `count * sizeof(ProductRow)` on line 21. A sufficiently large `count` (e.g., `SIZE_MAX / sizeof(ProductRow) + 1`) causes the multiplication to overflow, wrapping to a small value.

## Fix

Replace the manual allocation and overflow-prone multiplication with `calloc()`, which performs the overflow check internally:

```c
ProductBatch *load_product_batch(const ProductRow *input, size_t count)
{
    ProductBatch *batch = malloc(sizeof(*batch));
    if (batch == NULL) {
        return NULL;
    }

    batch->rows = calloc(count, sizeof(ProductRow));
    if (batch->rows == NULL) {
        free(batch);
        return NULL;
    }
    batch->count = count;

    for (size_t i = 0; i < count; i++) {
        batch->rows[i] = input[i];
    }

    return batch;
}
```

The key change is replacing:
```c
size_t bytes = count * sizeof(ProductRow);
batch->rows = malloc(bytes);
```

with:
```c
batch->rows = calloc(count, sizeof(ProductRow));
```

## Explanation

`calloc(count, sizeof(ProductRow))` performs the same allocation as `malloc(count * sizeof(ProductRow))`, but detects and rejects any overflow in the multiplication before allocation occurs. If `count * sizeof(ProductRow)` would exceed `SIZE_MAX`, `calloc()` returns `NULL` and the function safely returns `NULL` to the caller, rather than allocating an undersized buffer that the subsequent write loop will overflow. `calloc()` is a standard C library function (available in all C implementations) and is portable across all platforms. The null check on line 23 (now line 16) catches this failure case.

## Behaviour changes

The fixed code produces identical output on valid inputs (where `count` does not cause overflow). On overflow-inducing inputs, the original code would write out of bounds and corrupt memory; the fixed code returns `NULL`, signaling allocation failure to the caller. This prevents the out-of-bounds write entirely. The return type and contract remain unchanged: callers already handle `NULL` returns from line 18 of the original code.
