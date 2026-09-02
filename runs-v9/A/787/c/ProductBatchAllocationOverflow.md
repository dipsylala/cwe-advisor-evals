## Verdict

Confirmed. `load_product_batch()` computes the allocation size for `batch->rows` with an unchecked multiplication, `count * sizeof(ProductRow)`, which can overflow `size_t` on a sufficiently large, attacker- or caller-influenced `count`. When it overflows, `malloc(bytes)` allocates a buffer far smaller than `count` elements actually require, and the subsequent copy loop writes `count` full `ProductRow` structs into it, producing a heap out-of-bounds write.

## Source

`count`, the `size_t` parameter passed into `load_product_batch()` (declared at line 14). It is used directly, with no upper-bound validation, to compute the byte size for the second allocation at line 21 (`size_t bytes = count * sizeof(ProductRow);`).

## Fix

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

    // calloc validates count * sizeof(ProductRow) for overflow internally
    // and fails (returns NULL) instead of silently wrapping and under-allocating.
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

The sink at line 31 (`batch->rows[i] = input[i];`) is not itself wrong; the bug is upstream, in how the destination buffer's size was computed at line 21. `count * sizeof(ProductRow)` is ordinary `size_t` arithmetic with no overflow check, so once `count` exceeds `SIZE_MAX / sizeof(ProductRow)` (on a common 64-bit platform with `sizeof(ProductRow) == 8`, that's `count >= 2^61`, but the same class of bug bites much sooner on 32-bit `size_t`, where the threshold is only `count >= 2^29`), the multiplication wraps around and `bytes` becomes a small, wrong value. `malloc(bytes)` then happily returns a buffer sized for far fewer than `count` rows. The loop, however, still trusts `count` as the number of elements to copy, so once `i` walks past the true capacity of the undersized buffer it keeps writing `ProductRow` structs past the end of the heap allocation — a classic integer-overflow-to-heap-buffer-overflow.

The fix replaces the manual `malloc(count * sizeof(ProductRow))` with `calloc(count, sizeof(ProductRow))`. The C standard requires `calloc` to fail and return `NULL` if the requested element count and size would overflow when multiplied, rather than silently truncating the way manual multiplication does, so an oversized `count` now safely fails allocation instead of producing an undersized buffer. This removes the root cause without touching the copy loop itself. If `calloc`'s zero-initialization overhead is unwanted for large batches, an equivalent alternative is to keep `malloc` but add an explicit pre-check (e.g., reject `count > SIZE_MAX / sizeof(ProductRow)`) before computing `bytes`; either approach closes the same gap. The existing `batch->rows == NULL` check after the allocation call already handles the failure path correctly and needed no change.
