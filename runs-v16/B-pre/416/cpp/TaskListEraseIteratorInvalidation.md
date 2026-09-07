## Verdict

exploitable

## Source

Iterator `it` obtained from `tasks.begin()` at line 9, used in the loop increment at line 9 after being invalidated by `tasks.erase(it)` at line 12.

## Fix

**Vulnerable code:**
```cpp
void removeCompletedTasks(std::vector<Task> &tasks) {
    for (auto it = tasks.begin(); it != tasks.end(); ++it) {
        if (it->completed) {
            // Line 12: erase() invalidates the iterator
            tasks.erase(it);
        }
    }
}
```

**Fixed code:**
```cpp
void removeCompletedTasks(std::vector<Task> &tasks) {
    for (auto it = tasks.begin(); it != tasks.end(); ) {
        if (it->completed) {
            // erase() returns an iterator to the next element
            it = tasks.erase(it);
        } else {
            ++it;
        }
    }
}
```

## Explanation

The vulnerability occurs because `std::vector::erase()` invalidates the iterator passed to it and all iterators at or following the erased position. The original loop increments `it` on the next iteration without accounting for this invalidation, resulting in undefined behavior when dereferencing or incrementing a stale iterator.

The fix uses the return value of `erase()`, which returns an iterator to the element following the erased element (or `end()` if erasing the last element). By assigning this returned iterator back to `it`, the loop maintains a valid iterator for the next iteration. When an element is not completed, the loop explicitly increments `it` before continuing, ensuring a valid iterator is always available for the next loop condition check.

## Behaviour changes

The loop control changes from always incrementing `it` to conditionally incrementing it only when an element is not erased. The behavior remains functionally equivalent—all completed tasks are removed—but now correctly handles iterator invalidation. The fix respects `std::vector`'s iterator invalidation contract: insertion or removal of elements invalidates iterators at or after the modified position.

