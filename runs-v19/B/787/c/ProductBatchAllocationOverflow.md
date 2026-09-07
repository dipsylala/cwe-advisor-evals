## Verdict

exploitable

## Source

The `count` parameter passed to `load_product_batch()`, which originates from a caller and may be untrusted or incorrect.

## Fix

### File: ProductBatchAllocationOverflow.c

```c
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint32_t sku;
    uint32_t quantity;
} ProductRow;

typedef struct {
    ProductRow *rows;
    size_t count;
} ProductBatch;

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

## Explanation

The original code multiplies `count * sizeof(ProductRow)` before passing to `malloc()`, which can overflow if `count` is sufficiently large. When this multiplication overflows, it wraps to a small value, causing `malloc()` to allocate a undersized buffer. The subsequent loop then writes out-of-bounds into this small allocation. The fix replaces this with `calloc(count, sizeof(ProductRow))`, which performs the overflow check internally before allocation and aborts if the multiplication would overflow. This is the C standard library's safe pattern for count-based allocations. The fix preserves the original error-handling contract: if allocation fails, both the batch and rows allocations are properly cleaned up and NULL is returned.

## Behaviour changes

The intermediate `bytes` variable is removed as it is no longer needed. The allocation now uses `calloc()` instead of `malloc()`, which initializes the allocated memory to zero. This is a safe behavioural change: the loop immediately overwrites every element with values from `input`, so zero-initialization adds no observable difference to callers, and it provides defence-in-depth against uninitialized memory reads. The error-handling path remains identical: on allocation failure, the partially-initialized `batch` struct is freed and NULL is returned.

