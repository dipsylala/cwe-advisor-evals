## Verdict

**exploitable** (confidence: high)

CWE-787, Out-of-bounds Write, in `load_product_batch()`, `ProductBatchAllocationOverflow.c:31`. The write itself is bounds-correct against the loop's own limit; the flaw is upstream, in the unchecked size calculation that sizes the destination buffer.

## Source

`count`, the `size_t` element-count parameter to `load_product_batch(const ProductRow *input, size_t count)`. No caller is present in this file, so `count` is treated as externally influenced - the batch size for a "product batch" load is the kind of value that originates from a file header, network payload, or other untrusted input describing how many rows follow (assumption, since the call site is not in scope).

## Fix

No third-party library is required; the fix is a standard-library substitution.

**Vulnerable code** (lines 21-22):

```c
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
```

`count * sizeof(ProductRow)` is computed with no overflow check. On a platform where `size_t` is 32-bit, any `count > SIZE_MAX / sizeof(ProductRow)` (roughly 536,870,911 rows, since `sizeof(ProductRow)` is 8) wraps the multiplication to a small value; `malloc` then succeeds with a far smaller allocation than the loop believes it has. The loop bound is `count`, not the (wrapped) allocation size, so the assignment at line 31 walks off the end of the undersized `rows` buffer - a heap out-of-bounds write.

**Fixed code**:

```c
batch->rows = calloc(count, sizeof(ProductRow));
if (batch->rows == NULL) {
    free(batch);
    return NULL;
}
batch->count = count;

for (size_t i = 0; i < count; i++) {
    batch->rows[i] = input[i];
}
```

## Explanation

The hand-rolled `count * sizeof(ProductRow)` multiplication is replaced with `calloc(count, sizeof(ProductRow))`, which performs the element-count-times-element-size multiplication internally with its own overflow check and returns `NULL` if the product would overflow, instead of silently wrapping to an undersized allocation. The existing `NULL` check (`free(batch); return NULL;`) already handles that failure path unchanged, so an oversized `count` now causes the function to fail cleanly rather than allocate a too-small buffer that the subsequent loop writes past. This closes the weakness at its source - the size calculation - rather than at the write itself, which is what the knowledge base's C-specific guidance (`cwe/787/c/INDEX.md`) prescribes for this exact pattern ("an unchecked `count * sizeof(T)` before allocation").

## Behaviour changes

- `calloc` zero-initializes the allocated memory before the function returns, where `malloc` left it uninitialized. Every element is unconditionally overwritten by the `for` loop immediately afterward, so this has no observable effect on the returned `ProductBatch` - it only adds a memory-clear that is subsequently discarded, with no functional or security-relevant difference.
- No other difference: return value, `NULL`-failure path, `batch->count` assignment, and the copy loop are all unchanged.
