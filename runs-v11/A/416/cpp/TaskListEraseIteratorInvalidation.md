## Verdict
Confirmed. CWE-416 (Use After Free) via iterator invalidation at line 12.

## Source
```cpp
void removeCompletedTasks(std::vector<Task> &tasks) {
    for (auto it = tasks.begin(); it != tasks.end(); ++it) {
        if (it->completed) {
            tasks.erase(it);  // Line 12: erase invalidates it
        }
    }
}
```

## Fix
```cpp
void removeCompletedTasks(std::vector<Task> &tasks) {
    for (auto it = tasks.begin(); it != tasks.end(); ) {
        if (it->completed) {
            it = tasks.erase(it);  // erase returns iterator to next element
        } else {
            ++it;
        }
    }
}
```

## Explanation
When `std::vector::erase()` removes an element, all iterators at or after that position are invalidated. In the original code, after `tasks.erase(it)` completes, `it` becomes invalid. The loop then attempts `++it` on the next iteration, dereferencing and incrementing a dangling iterator—a use-after-free.

The fix leverages that `erase()` returns an iterator to the element following the erased one. Assigning this return value to `it` keeps the iterator valid. When an element is erased, we do not increment; when an element is kept, we explicitly increment. This ensures the loop always operates on valid iterators and safely traverses the entire vector while removing matching elements.
