## Verdict

CONFIRMED. The code uses `std::vector::reserve()` to allocate capacity but does not increase the vector's size. Subsequent indexed writes via `operator[]` with indices `0` through `count-1` access a vector of size 0, resulting in out-of-bounds writes to unallocated heap memory.

## Source

The vulnerability is at line 15 in the loop body: `packet[i] = fields[i]`.

**Data flow:** The `count` parameter (line 10) is user-supplied and externally controlled. It is used in line 12 to call `reserve(count)`, which allocates capacity but leaves the vector's size unchanged (at 0). The loop at line 14 then iterates from `i = 0` to `i = count-1`, and each iteration indexes the vector with an unchecked subscript at line 15.

**Root cause:** `reserve()` pre-allocates buffer space for growth but does not update the container's size. The vector remains empty (size 0) until elements are explicitly added. Using `operator[]` with any non-zero index on an empty vector is undefined behavior because the vector reports no valid elements.

## Fix

Replace line 12:
```cpp
    packet.reserve(count);
```

With:
```cpp
    packet.resize(count);
```

**Rationale:** `resize(count)` allocates capacity *and* sets the vector's size to `count`, default-constructing any new elements. Once the resize completes, indices `0` through `count-1` are valid for `operator[]` access.

## Explanation

The root issue is conflating capacity (how much memory is allocated) with size (how many elements are logically in the container). `reserve()` is a capacity hint for future growth; it does not make elements accessible. `resize()` actually grows the logical size of the container and initializes the new elements.

The fix uses `resize()` to bring the vector's size in line with the number of elements to be assigned. This eliminates the out-of-bounds access by making indices 0 to `count-1` valid within the container. No bounds checking is required in the loop because the size is now correct; however, `.at()` could be substituted for `operator[]` if checked access is desired.

## Behaviour changes

**Before fix:** The vector is logically empty after `reserve()`. Writes via `packet[i]` corrupt heap memory adjacent to the vector's allocation without throwing or failing. The returned packet appears empty (size 0) to the caller, despite the heap write side effects.

**After fix:** The vector's size is set to `count` after `resize()`. Elements accessed via `packet[i]` are within the vector's logical bounds. The returned packet correctly contains all assigned `PacketField` values, with size equal to `count`.

The fix preserves the function's signature and return type. The caller receives a valid, properly-populated vector where they previously received an empty vector (with hidden heap corruption).
