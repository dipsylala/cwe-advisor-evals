## Verdict

**Confirmed: CWE-787 (Out-of-bounds Write)**

The code is vulnerable to integer overflow in the allocation calculation. When `count` is sufficiently large, the multiplication `count * sizeof(ProductRow)` overflows, resulting in allocation of insufficient buffer space. Subsequent writes to `batch->rows[i]` then exceed the allocated bounds.

## Source

**File:** ProductBatchAllocationOverflow.c  
**Lines:** 21–31  
**Root cause:** Missing integer overflow check before buffer allocation

The vulnerability occurs because:
1. Line 21 multiplies `count * sizeof(ProductRow)` without overflow protection
2. If `count > SIZE_MAX / sizeof(ProductRow)`, the multiplication wraps to a smaller value
3. Line 22 allocates an undersized buffer
4. Line 31 writes beyond the allocated bounds when `i` reaches the wrapped allocation size

## Fix

### File: ProductBatchAllocationOverflow.c

```c
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

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

    // Check for integer overflow before multiplication
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

The fix adds an overflow check at line 24–26 before the multiplication:

```c
if (count > SIZE_MAX / sizeof(ProductRow)) {
    free(batch);
    return NULL;
}
```

This check ensures that `count * sizeof(ProductRow)` cannot overflow. If `count` is large enough to cause overflow, the function fails safely by freeing the batch structure and returning NULL.

The check is equivalent to testing whether the multiplication would exceed `SIZE_MAX`. By rearranging the inequality, we avoid performing the multiplication that would overflow. This is the standard portable defense against integer overflow in allocation calculations in C.
