## Verdict
The vulnerability is real. An integer overflow in the size calculation enables an out-of-bounds write to `batch->rows`.

## Source
```c
ProductBatch *load_product_batch(const ProductRow *input, size_t count)
{
    ProductBatch *batch = malloc(sizeof(*batch));
    if (batch == NULL) {
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
        // SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
        batch->rows[i] = input[i];
    }

    return batch;
}
```

## Fix
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
    if (count > 0 && count > SIZE_MAX / sizeof(ProductRow)) {
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

    // Validate input pointer when count is non-zero
    if (count > 0 && input == NULL) {
        free(batch->rows);
        free(batch);
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        batch->rows[i] = input[i];
    }

    return batch;
}
```

## Explanation
The vulnerability stems from an unchecked integer overflow in the allocation size calculation. When `count` is very large (approaching `SIZE_MAX`), the multiplication `count * sizeof(ProductRow)` wraps around to a small value. This causes `malloc()` to allocate an undersized buffer, and the subsequent loop writes beyond the allocated bounds.

The fix adds two safeguards:

1. **Overflow check before multiplication**: `if (count > 0 && count > SIZE_MAX / sizeof(ProductRow))` prevents the multiplication from overflowing by validating that `count` is within the safe range. If overflow would occur, the function returns NULL with cleanup.

2. **Input validation**: `if (count > 0 && input == NULL)` ensures the input pointer is valid before dereferencing it in the loop. This prevents reading from an invalid pointer and writing potentially corrupted data.

These checks ensure that the loop at line 31 only executes when both the destination buffer `batch->rows[i]` and source array `input[i]` are valid and within bounds.
