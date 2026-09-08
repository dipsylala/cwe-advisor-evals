## Verdict

Confirmed. CWE-787 (Out-of-bounds Write), rooted in an unchecked integer-overflow size calculation (CWE-131/190-adjacent allocation pattern) in `load_product_batch`.

## Source

`count`, the `size_t` parameter passed in to `load_product_batch`, is treated as attacker-influenced (the caller marshals it from external batch data before invoking this function). No caller-side bound on `count` is visible in this file, so it is traced as unconstrained.

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

The size calculation `size_t bytes = count * sizeof(ProductRow);` at line 21 can overflow `size_t` when `count` is large enough (on a 32-bit `size_t`, any `count > SIZE_MAX / sizeof(ProductRow)`, i.e. roughly `count > 536,870,911`, since `sizeof(ProductRow)` is 8). The multiplication wraps around to a small value, `malloc` succeeds with an undersized allocation, and the subsequent loop at line 31 (`batch->rows[i] = input[i];`) then writes `count` elements into a buffer sized for far fewer, corrupting heap memory past the allocation — the out-of-bounds write the scanner flagged.

The fix replaces the hand-rolled `count * sizeof(ProductRow)` multiplication and `malloc` call with `calloc(count, sizeof(ProductRow))`. `calloc` performs the multiplication internally with its own overflow check and returns `NULL` if the product would overflow, so an oversized `count` now fails allocation cleanly instead of silently under-allocating. The existing `if (batch->rows == NULL)` failure path already frees `batch` and returns `NULL`, so no new error-handling branch is needed — the overflow case now simply routes through that same, already-correct path. The now-unused `bytes` local was removed since nothing else referenced it.

## Behaviour changes

- On an overflowing `count`, the function now returns `NULL` (allocation failure) instead of proceeding to corrupt heap memory. Any caller must already handle a `NULL` return from `load_product_batch` (the function could always fail on OOM), so this does not introduce a new caller obligation.
- `calloc` zero-initializes the buffer before the copy loop overwrites it; since every element is unconditionally written by the loop (`batch->rows[i] = input[i]` for all `i < count`), this has no observable effect on the returned data.
- For `count == 0`, both the original `malloc(0)` and the replacement `calloc(0, sizeof(ProductRow))` are implementation-defined as to whether they return `NULL` or a unique non-NULL pointer; this ambiguity was already present in the original code and is unchanged by the fix.
- No API, signature, or return-type change; the function's contract with its caller is otherwise identical.

Check performed: no C compiler (`gcc`, `clang`, `cc`, `cl`) was reachable in this environment, so the fix was verified by manual read: `calloc` is declared in `<stdlib.h>`, already included; its signature `void *calloc(size_t nmemb, size_t size)` matches the call `calloc(count, sizeof(ProductRow))` (`count` is `size_t`, `sizeof(ProductRow)` is `size_t`); the `void *` return converts implicitly to `ProductRow *` under C's implicit-conversion rules, exactly as `malloc`'s return did. No other symbol, signature, or caller in the file changed.
