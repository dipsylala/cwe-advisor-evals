## Verdict
The code contains a use-after-free vulnerability. When `std::vector::erase()` is called on an iterator, it invalidates that iterator. The subsequent loop increment `++it` operates on an invalidated iterator, causing undefined behavior.

## Source
The vulnerable pattern is in the loop at lines 9-14:
```
for (auto it = tasks.begin(); it != tasks.end(); ++it) {
    if (it->completed) {
        tasks.erase(it);  // Invalidates 'it'
    }
}
```

After `erase(it)` is called, the iterator `it` is invalid. The next iteration attempts to use it in `++it`, which is a use-after-free error.

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
The fix uses the return value of `std::vector::erase()`, which returns an iterator to the element following the erased element. This valid iterator is then assigned back to `it`, avoiding the invalidation problem.

The loop increment is moved into conditional logic: when an element is erased, `it` already points to the next element (via the return value), so we do not increment. When an element is not erased, we increment `it` normally to move to the next position. This ensures `it` is always valid at the start of each iteration.
