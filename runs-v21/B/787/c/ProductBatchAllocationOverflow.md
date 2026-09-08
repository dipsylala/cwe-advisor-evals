## Verdict

Out-of-bounds write confirmed at line 31. The vulnerability stems from an integer overflow in the size calculation on line 21, where `count * sizeof(ProductRow)` can wrap around if `count` is sufficiently large, resulting in an undersized allocation that is then overflowed by the copy loop.

## Source

**Input source**: `count` parameter (untrusted, caller-supplied)  
**Data flow**: `count` → size calculation line 21 → allocation on line 22 → array indexing on line 31  
**Vulnerable pattern**: Manual multiplication `count * sizeof(ProductRow)` without overflow check before allocation

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

    batch->rows = calloc(count, sizeof(*batch->rows));
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

The unsafe pattern was the manual multiplication of `count * sizeof(ProductRow)` without overflow detection. When `count` approaches SIZE_MAX, this multiplication wraps to a small value, producing an undersized heap allocation that the subsequent loop then overflows.

The fix replaces the unsafe multiplication with `calloc(count, sizeof(*batch->rows))`. The `calloc()` function performs internal overflow detection before allocating: it multiplies count and element size atomically and rejects the allocation if overflow would occur, returning NULL. This eliminates the integer overflow vulnerability while maintaining the same functional contract—allocating storage for count elements and zeroing them. The existing NULL check on line 23 now catches both allocation-failure and overflow-detection cases identically.

## Behaviour changes

None. The fixed code preserves the function's interface, return value handling, and success/failure semantics. The only change is replacement of the unsafe size calculation with a bounds-safe allocation primitive. All callers see identical behavior: successful allocation and copy on valid input, NULL return on overflow or allocation failure.
