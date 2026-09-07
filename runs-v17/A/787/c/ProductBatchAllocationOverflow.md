## Verdict
CONFIRMED - Out-of-bounds write due to integer overflow in multiplication before buffer allocation.

## Source
The vulnerability occurs at line 31 in the write operation `batch->rows[i] = input[i]`. The root cause is an unchecked integer overflow at line 21:

```
size_t bytes = count * sizeof(ProductRow);
```

When `count` exceeds `SIZE_MAX / sizeof(ProductRow)`, the multiplication overflows, producing a small value. This causes `malloc()` to allocate an undersized buffer, and the subsequent loop writes beyond the allocated memory.

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
    if (count > 0 && sizeof(ProductRow) > SIZE_MAX / count) {
        free(batch);
        return NULL;
    }

    // Validate input pointer when count is non-zero
    if (input == NULL && count > 0) {
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
The fix adds two critical validation checks before the vulnerable multiplication:

1. **Integer Overflow Check (lines 25-28):** Before computing `bytes = count * sizeof(ProductRow)`, verify that the multiplication will not overflow. If `count > SIZE_MAX / sizeof(ProductRow)`, the multiplication would wrap around to a small value, causing undersized allocation. The check prevents this by returning NULL early.

2. **Input Pointer Validation (lines 30-33):** When `count > 0`, the input pointer must be non-NULL to avoid reading from invalid memory during the copy loop. This prevents dereferencing a null pointer.

These checks ensure that the buffer allocated at line 22 is correctly sized for the number of elements being copied, preventing out-of-bounds writes at line 31.
