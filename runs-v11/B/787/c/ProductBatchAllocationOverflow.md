## Verdict

**CONFIRMED.** The code is vulnerable to out-of-bounds write due to an unchecked integer overflow in the heap allocation size calculation.

## Source

The vulnerability is an integer overflow in the size calculation at line 21:

```c
size_t bytes = count * sizeof(ProductRow);
batch->rows = malloc(bytes);
```

If `count` is very large (for example, greater than `SIZE_MAX / sizeof(ProductRow)`), the multiplication `count * sizeof(ProductRow)` wraps around due to unsigned integer overflow, resulting in a small allocation. The subsequent loop at line 31 then writes `count` full elements into this undersized buffer, causing an out-of-bounds write to allocated memory on the heap.

## Fix

Replace the manual size calculation and `malloc()` with `calloc()`, which performs overflow checking internally:

```c
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

The key change is line 8: `calloc(count, sizeof(ProductRow))` instead of `malloc(bytes)`. The `calloc()` function:
- Takes count and element size as separate parameters (not a pre-calculated product)
- Performs overflow detection: if `count > SIZE_MAX / sizeof(ProductRow)`, it safely returns NULL
- Also initializes the allocated memory to zero, which is a defensive bonus

## Explanation

CWE-787 defines out-of-bounds write as writing to memory past the end of an allocated buffer. This occurs here when:

1. An attacker passes a very large `count` value (e.g., `SIZE_MAX / 2`)
2. The calculation `count * sizeof(ProductRow)` silently wraps around to a small value due to unsigned integer overflow
3. `malloc()` is called with this small wrapped value, allocating only a few bytes
4. The loop writes `count` full `ProductRow` structures (8 bytes each on most platforms) into the small buffer
5. This write extends far past the allocated block, corrupting adjacent heap objects

The fix prevents this by:
- Deferring the multiplication to `calloc()`, which performs the multiplication internally with overflow detection
- `calloc()` returns NULL if overflow is detected, allowing safe error handling
- The check at line 11 (now) catches this and safely cleans up without corruption

## Behaviour changes

- On valid inputs with `count <= SIZE_MAX / sizeof(ProductRow)`: behavior is identical
- On oversized `count` values that would previously overflow and corrupt memory: `calloc()` returns NULL, the function returns NULL, and the caller must handle the allocation failure
- The zeroed initialization from `calloc()` is a minor change: previously uninitialized structure members are now zero, which improves predictability
