## Verdict

Confirmed. `load_product_batch` computes the allocation size for `batch->rows` with `size_t bytes = count * sizeof(ProductRow);` and then calls `malloc(bytes)`. Because `count` is caller-supplied and `sizeof(ProductRow)` is 8, this multiplication wraps around on overflow (e.g. `count >= SIZE_MAX/8 + 1` on a 64-bit platform, far smaller on 32-bit). When it wraps, `malloc` returns a buffer far smaller than `count * sizeof(ProductRow)` bytes, but the subsequent loop `for (size_t i = 0; i < count; i++) batch->rows[i] = input[i];` still iterates `count` times, writing past the end of the undersized heap buffer. That out-of-bounds write is the CWE-787 sink at line 31.

## Source

`count`, the `size_t` parameter passed into `load_product_batch(const ProductRow *input, size_t count)`, is the tainted value that drives both the allocation-size multiplication and the loop bound. It flows in from the function's caller with no upper-bound check before being used in `count * sizeof(ProductRow)`.

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

The root cause is the unchecked `count * sizeof(ProductRow)` multiplication used to size the `malloc` call. Replacing `malloc(count * sizeof(ProductRow))` with `calloc(count, sizeof(ProductRow))` removes the manual multiplication entirely: `calloc` takes the element count and element size as separate arguments and is required by the C standard to detect multiplication overflow internally, returning `NULL` instead of silently wrapping and handing back an undersized buffer. With that change, when `count` is large enough that `count * sizeof(ProductRow)` would have overflowed, `calloc` now fails cleanly and the existing `NULL` check (which already frees `batch` and returns `NULL`) handles it correctly, so the subsequent loop can never write past the end of the allocated buffer. This is a minimal, behavior-preserving fix: it does not change the function's signature, its success-path semantics, or add a redundant manual overflow check that would duplicate what `calloc` already guarantees; it also does not clamp or reject `count` values that don't overflow, since any count that fits without overflowing is a legitimate allocation size for the caller to request. The zero-initialization `calloc` performs is immediately overwritten by the loop, so there is no meaningful performance regression for realistic batch sizes.
