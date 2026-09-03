## Verdict

The use-after-free vulnerability is confirmed. A reference to a vector element is held across a `push_back()` operation, which can trigger reallocation and invalidate the reference. The reference is subsequently used at line 36, potentially accessing freed memory.

## Source

**File:** `evals/cases/416/cpp/VectorReallocationInvalidatesReference/VectorReallocationInvalidatesReference.cpp`

**Lines 28–36:**
```cpp
Task& current = tasks[activeIndex];
current.completed = true;

Task follow = makeFollowUpTask(current);
follow.priority = completionPriority;
tasks.push_back(follow);

// SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
current.priority = completionPriority;
```

The vulnerability occurs because:
1. Line 28 acquires a reference to a vector element via index access
2. Line 33 calls `push_back()`, which may reallocate the underlying vector if capacity is exceeded
3. All references to previous elements are invalidated by reallocation
4. Line 36 dereferences the now-invalid reference

## Fix

Replace the reference-based approach with index-based access to avoid holding a reference across the `push_back()`:

```cpp
void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
    tasks[activeIndex].completed = true;
    
    Task follow = makeFollowUpTask(tasks[activeIndex]);
    follow.priority = completionPriority;
    tasks.push_back(follow);
    
    tasks[activeIndex].priority = completionPriority;
}
```

The key changes:
- Line 1 (formerly 28): Remove the reference variable `Task& current`
- Lines 3 and 9: Use `tasks[activeIndex]` directly instead of the reference
- This ensures no references are held across the `push_back()` call

## Explanation

When a `std::vector` grows beyond its current capacity, it allocates a new buffer and moves all elements into it, leaving the old buffer deallocated. Any references, pointers, or iterators to the old buffer become invalid—they point to freed memory.

The original code violates this constraint by:
1. Taking a reference at line 28 before the capacity-expanding operation
2. Calling `push_back()` at line 33, which may invalidate that reference
3. Dereferencing the reference at line 36

The fix uses indices instead, which remain valid across reallocation. When `tasks[activeIndex]` is accessed after the `push_back()`, the vector resolves the current address of the element at that index, circumventing the use-after-free.

This pattern—switching from reference/pointer to index when the container may be modified—is the standard mitigation for reference-invalidation bugs in standard containers.
