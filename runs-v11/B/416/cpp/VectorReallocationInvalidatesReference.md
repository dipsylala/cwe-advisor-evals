## Verdict

Exploitable. A reference to a `std::vector` element taken at line 28 is used at line 36 after a `push_back()` at line 33 that may trigger vector reallocation, invalidating the reference.

## Source

`tasks[activeIndex]` - the vector element accessed via subscript operator and bound to a reference at line 28.

## Fix

**Vulnerable code (line 27–37):**
```cpp
void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
    Task& current = tasks[activeIndex];
    current.completed = true;

    Task follow = makeFollowUpTask(current);
    follow.priority = completionPriority;
    tasks.push_back(follow);  // May invalidate 'current' reference via reallocation

    current.priority = completionPriority;  // Use of potentially dangling reference
}
```

**Fixed code:**
```cpp
void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
    Task& current = tasks[activeIndex];
    current.completed = true;

    Task follow = makeFollowUpTask(current);
    follow.priority = completionPriority;
    tasks.push_back(follow);

    // Re-acquire reference via index after push_back to avoid invalidation
    tasks[activeIndex].priority = completionPriority;
}
```

## Explanation

When a `std::vector` reallocates its backing store during `push_back()`, all outstanding references, pointers, and iterators to its elements are invalidated. The original code holds a reference `current` to an element of `tasks`, then calls `push_back()` which may trigger reallocation if the vector has reached its capacity. Any subsequent use of `current` accesses memory that may no longer be valid for that object. The fix eliminates the stale reference by re-accessing the element through its stable index after the mutation, ensuring the reference is valid at the point of use. This matches the C++ guidance pattern: "re-acquire an iterator or pointer after any operation that can invalidate it, rather than reusing one taken before."

## Behaviour changes

None. The fix preserves all the original function semantics—the same task is marked completed and its priority is set to `completionPriority`—while ensuring memory safety. The only change is the address at which the priority is written (obtained fresh from the vector after `push_back`) instead of through a potentially stale reference.
