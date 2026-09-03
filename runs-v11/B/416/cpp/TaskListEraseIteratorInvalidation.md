## Verdict

**CONFIRMED**: Use-after-free via invalidated iterator in vector erase loop.

## Source

The vulnerability occurs at line 12 in `TaskListEraseIteratorInvalidation.cpp`. The loop calls `tasks.erase(it)` inside the for-loop body, which invalidates the iterator. The loop's increment expression `++it` on the next iteration then dereferences the invalidated iterator, violating the iterator lifetime contract and creating a use-after-free condition.

The specific issue: `std::vector::erase()` returns an iterator to the element following the erased element, but the code discards this return value. The loop then continues with `++it`, which operates on an iterator that is no longer valid after the erase operation.

## Fix

Replace the erase-and-continue pattern with the iterator-per-element approach, using the return value from `erase()`:

```cpp
void removeCompletedTasks(std::vector<Task> &tasks) {
    for (auto it = tasks.begin(); it != tasks.end(); ) {
        if (it->completed) {
            it = tasks.erase(it);  // erase() returns iterator to next element
        } else {
            ++it;
        }
    }
}
```

The key changes:
1. Remove the increment from the for-loop's third clause (leaving it empty).
2. Capture the return value of `erase()`, which points to the element following the erased one.
3. For non-erased elements, explicitly increment the iterator with `++it`.

This guarantees that `it` always references a valid element or `end()` on each loop iteration.

## Explanation

In C++, `std::vector::erase()` invalidates all iterators at and after the erased position. The original code attempted to increment an invalidated iterator on the next loop iteration, which is undefined behavior. The C++ standard library provides a mechanism to avoid this: `erase()` returns an iterator to the element after the erased one, which is safe to use immediately.

By using the return value of `erase()`, we skip the invalidation trap entirely. For non-erased elements, we manually increment with `++it`, maintaining control of the iterator throughout. This pattern is the idiomatic C++ solution for safe element removal from a vector during iteration.

## Behaviour changes

**Before**: Iterator invalidation caused undefined behavior on loop continuation. Possible crashes, memory corruption, or silent data corruption depending on memory layout.

**After**: Iterator remains valid on every loop iteration. Elements marked as completed are reliably removed without corrupting memory or crashing.
