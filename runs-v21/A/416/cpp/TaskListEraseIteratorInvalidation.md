## Verdict
Confirmed. CWE-416 (Use After Free) exists at line 12.

## Source
The vulnerability occurs in the loop at lines 9-14. When `tasks.erase(it)` is called, it invalidates the iterator `it`. The for loop then attempts to increment this invalidated iterator with `++it` in the loop header, resulting in a use-after-free.

## Fix
### File: TaskListEraseIteratorInvalidation.cpp
```cpp
#include <vector>

struct Task {
    int id;
    bool completed;
};

void removeCompletedTasks(std::vector<Task> &tasks) {
    for (auto it = tasks.begin(); it != tasks.end(); ) {
        if (it->completed) {
            it = tasks.erase(it);
        } else {
            ++it;
        }
    }
}
```

## Explanation
The fix uses the return value of `std::vector::erase()`, which returns an iterator to the element following the erased element. This avoids iterator invalidation:

1. When a task is marked completed, `it = tasks.erase(it)` erases the element and updates `it` to point to the next element. No additional increment is performed.

2. When a task is not completed, `++it` manually advances the iterator to check the next element.

The loop termination condition `it != tasks.end()` remains valid because:
- After erasure, `erase()` returns a valid iterator (either to the next element or `end()`)
- After manual increment, the iterator is valid or becomes `end()`

This pattern is the standard C++ idiom for safe element removal during iteration over a `std::vector`.
