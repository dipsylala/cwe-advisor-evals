## Verdict

This code is vulnerable to out-of-bounds write through integer overflow in the allocation size calculation.

## Source

Line 21: `size_t bytes = count * sizeof(ProductRow);`

The multiplication of `count` and `sizeof(ProductRow)` is not checked for overflow. If `count` is large enough, this multiplication wraps around, producing a `bytes` value smaller than the actual allocation needed. The subsequent allocation and write loop then access memory beyond the allocated buffer.

## Fix

```c
ProductBatch *load_product_batch(const ProductRow *input, size_t count)
{
    ProductBatch *batch = malloc(sizeof(*batch));
    if (batch == NULL) {
        return NULL;
    }

    // Check for multiplication overflow before allocating
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

The vulnerability occurs because the code multiplies `count` by `sizeof(ProductRow)` without checking if the result overflows. When `count` is sufficiently large (specifically, larger than `SIZE_MAX / sizeof(ProductRow)`), the multiplication wraps around to a small value. This causes `malloc(bytes)` to allocate a small buffer, but the subsequent loop writes `count` full elements into it, writing far beyond the allocated memory.

The fix adds an overflow check before the multiplication: if `count > SIZE_MAX / sizeof(ProductRow)`, the allocation cannot succeed safely, so the function returns `NULL` to signal an error. Only after confirming the multiplication is safe does the code proceed with allocation and copying.
