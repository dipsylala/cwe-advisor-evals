## Verdict

The vulnerability is a multiplication integer overflow in the buffer allocation. When `count` is large enough, `count * sizeof(ProductRow)` wraps to a small value, allocating an undersized buffer that the loop subsequently overflows when writing `count` elements.

## Source

**File:** ProductBatchAllocationOverflow.c

**Lines 21-22 (vulnerable allocation):**
```c
size_t bytes = count * sizeof(ProductRow);
batch->rows = malloc(bytes);
```

**Line 31 (out-of-bounds write):**
```c
batch->rows[i] = input[i];
```

The vulnerability occurs because there is no check that the multiplication does not overflow before allocation, and no validation that the allocated capacity matches the loop's write count.

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

The fix replaces the vulnerable manual multiplication with `calloc()`. The `calloc()` function:
- Performs an internal overflow check on `count * sizeof(ProductRow)`, rejecting allocation if the multiplication would overflow
- Returns NULL if the overflow would occur or if memory allocation fails
- Initializes allocated memory to zero (a bonus safety property)

This eliminates the multiplication overflow vulnerability while maintaining the same semantics: allocate space for `count` elements of type `ProductRow`, or fail safely by returning NULL. The check at line 23 catches the NULL return from either allocation failure or overflow detection, freeing the already-allocated batch structure and propagating the error to the caller.

## Behaviour changes

- **Successful case (no overflow):** identical behavior; buffer is allocated and populated as before
- **Oversized count (multiplication overflow):** allocation now fails safely with NULL return instead of allocating an undersized buffer and overflowing it
- **Memory initialization:** calloc() zeros the allocated memory, whereas malloc() leaves it uninitialized; this is safe (the loop immediately fills it) and beneficial for defense-in-depth
