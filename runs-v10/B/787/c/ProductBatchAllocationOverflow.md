## Verdict

Exploitable. The allocation at line 21 does not check for integer overflow in the multiplication `count * sizeof(ProductRow)`, allowing an attacker to cause a small heap allocation through overflow. The subsequent loop at line 31 then writes past the end of the allocated buffer.

## Source

The `count` parameter on line 14 is untrusted external input. It flows directly to the multiplication on line 21 without validation.

## Fix

**Vulnerable code (line 21-22):**
```c
    size_t bytes = count * sizeof(ProductRow);
    batch->rows = malloc(bytes);
```

**Fixed code:**
```c
    batch->rows = calloc(count, sizeof(ProductRow));
```

## Explanation

The original code multiplies `count` by `sizeof(ProductRow)` without checking for integer overflow. If `count` is large enough, this multiplication wraps to a small value, resulting in a heap allocation far smaller than needed. The loop then writes beyond the allocated region. `calloc()` performs overflow checking internally: it rejects the allocation and returns `NULL` if `count * sizeof(ProductRow)` would overflow. This eliminates the out-of-bounds write by preventing the undersized allocation in the first place.

## Behaviour changes

The memory is now zero-initialized by `calloc()`, whereas `malloc()` left it uninitialized. Since the code immediately overwrites each element in the loop, this has no functional effect on the output but is a minor performance difference (zero-initialization cost). The behavior of the existing NULL-check at line 23 is unchanged; `calloc()` failure still returns NULL and the cleanup proceeds identically.
