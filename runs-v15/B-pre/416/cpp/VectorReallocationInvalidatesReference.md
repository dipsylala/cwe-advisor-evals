## Verdict

Confirmed use-after-free: A reference to a `std::vector` element is taken at line 28, then the vector is modified with `push_back()` at line 33 (which may reallocate the backing store), and the now-invalid reference is dereferenced at line 36.

## Source

```cpp
void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
    Task& current = tasks[activeIndex];  // Line 28: reference to vector element
    current.completed = true;

    Task follow = makeFollowUpTask(current);
    follow.priority = completionPriority;
    tasks.push_back(follow);  // Line 33: may reallocate, invalidating 'current'

    // Line 36: SINK - dereference of invalidated reference
    current.priority = completionPriority;
}
```

The issue is that `std::vector::push_back()` can trigger a reallocation if the vector is at capacity, which invalidates all outstanding references and pointers to existing elements. The reference `current` becomes a dangling reference after line 33.

## Fix

```cpp
void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
    Task& current = tasks[activeIndex];
    current.completed = true;

    Task follow = makeFollowUpTask(current);
    follow.priority = completionPriority;
    tasks.push_back(follow);

    // Re-acquire the reference after the push_back, or use the index directly
    tasks[activeIndex].priority = completionPriority;
}
```

## Explanation

The fix replaces the use of the stale reference `current` at line 36 with a direct access through the index `tasks[activeIndex]`. Since the index `activeIndex` remains valid after the `push_back()` operation (only the reference is invalidated), this safely accesses the same element without relying on a dangling reference. 

In C++, `std::vector` invalidates all references, pointers, and iterators to existing elements when reallocation occurs. The safest approach after any vector mutation is to re-acquire access via the index (which remains stable) or by re-fetching the reference after the operation. This follows the C++ guidance principle: "Bind, encode, validate, or authorize - re-acquire an iterator or pointer after any operation that can invalidate it, rather than reusing one taken before."

## Behaviour changes

The behaviour is functionally unchanged. Both the original and fixed code set the same priority value on the same task at `activeIndex`. The fix eliminates undefined behaviour by ensuring we are not dereferencing an invalidated reference; the completed task's priority is correctly updated after the follow-up task has been queued.
