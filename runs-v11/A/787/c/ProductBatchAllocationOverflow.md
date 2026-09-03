## Verdict
Out-of-bounds write due to integer overflow in size calculation.

## Source
Line 21: `size_t bytes = count * sizeof(ProductRow);`

The multiplication can overflow when `count` is sufficiently large, causing `malloc` to allocate far less memory than intended. Subsequent writes in the loop at line 31 then exceed the allocated buffer bounds.

## Fix
```c
ProductBatch *load_product_batch(const ProductRow *input, size_t count)
{
    ProductBatch *batch = malloc(sizeof(*batch));
    if (batch == NULL) {
        return NULL;
    }

    // Check for integer overflow: count * sizeof(ProductRow)
    if (count > SIZE_MAX / sizeof(ProductRow)) {
        free(batch);
        return NULL;
    }

    size_t bytes = count * sizeof(ProductRow);
    batch->rows = malloc(bytes);
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

## Explanation
The vulnerability occurs when `count * sizeof(ProductRow)` overflows. Multiply a large count by the struct size and it wraps to a small value, allocating insufficient memory. The subsequent loop writes `count` items into this undersized buffer, causing a heap overflow.

The fix adds an overflow check before multiplication: `count > SIZE_MAX / sizeof(ProductRow)` detects when the multiplication would exceed the maximum value for `size_t`. If overflow is detected, the function returns `NULL` after cleanup, preventing the vulnerable allocation and write sequence.
