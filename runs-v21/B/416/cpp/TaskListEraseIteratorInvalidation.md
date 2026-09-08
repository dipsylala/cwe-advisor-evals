## Verdict

Exploitable. The code calls `tasks.erase(it)` on line 12, invalidating the iterator. The for loop then attempts to use the invalidated iterator in the increment expression (`++it`), which is undefined behavior and constitutes a use-after-free of the iterator.

## Source

Line 9: Iterator `it` initialized from `tasks.begin()` in the for loop.

## Sink

Line 12: `tasks.erase(it)` invalidates the iterator. The loop's increment step (`++it`) then uses this invalidated iterator, which is undefined behavior.

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

The original code calls `tasks.erase(it)` while iterating, which invalidates the iterator `it` according to the C++ standard. Subsequent use of `it` in the for loop's increment expression results in undefined behavior. The fix applies the standard C++ idiom for erasing elements during iteration: capture and use the return value of `erase()`, which is guaranteed to be a valid iterator pointing to the element following the erased element (or `end()` if erasing the last element). The loop only increments `it` explicitly when an element is not erased; when an element is erased, `it` is assigned the return value of `erase()`, which already points to the next element. This ensures every access to `it` uses a valid iterator.

## Behaviour changes

The loop structure changes from a traditional for loop with post-increment to one with conditional increment. Specifically:
- The increment step of the for loop becomes empty (no post-increment of `it`)
- When an element is not completed, `++it` is explicitly called in the else branch
- When an element is completed, `it` is assigned the return value of `erase()`, which is the next valid iterator

This preserves the original behavior—all completed tasks are still removed—while eliminating the undefined behavior. The return value of `erase()` is well-defined by the C++ standard and is designed for exactly this use case. No other aspects of the code's contract change; the function still modifies the vector in-place and returns void.
