## Verdict

Confirmed use-after-free via iterator invalidation. After `std::vector::erase()` is called on line 12, the iterator `it` becomes invalid. The loop's increment expression `++it` then attempts to increment an invalid iterator, which is undefined behavior equivalent to a use-after-free. The vulnerability is exploitable because the code mutates a container while iterating over it without accounting for iterator invalidation semantics.

## Source

The vulnerability is in the loop at lines 9-14. The function iterates through a vector and attempts to erase elements where `completed` is true. However, `std::vector::erase()` invalidates the passed iterator and all iterators following it. The loop then increments this invalidated iterator, causing undefined behavior:

```cpp
for (auto it = tasks.begin(); it != tasks.end(); ++it) {
    if (it->completed) {
        tasks.erase(it);  // Invalidates 'it'
                          // Loop increment ++it uses invalid 'it' → UB
    }
}
```

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

The fix uses `std::vector::erase()`'s return value, which yields an iterator to the element following the erased element (or `end()` if the erased element was the last). By assigning this returned iterator back to `it`, we guarantee that `it` is always valid before the next iteration. The loop's increment expression is removed from the for statement and moved into the conditional branches: after an erase, the returned iterator already points to the next element (no increment needed), while in the non-erased path, we manually increment. This way, `it` is never used after the operation that invalidates it, and the loop always works with a valid iterator.

This pattern is the standard C++ idiom for conditional removal during iteration over a vector, and is recommended in the C++ standard library documentation.

## Behaviour changes

- **Correctness**: The function now correctly removes all completed tasks without undefined behavior.
- **Performance**: Unchanged. The fix uses the same `erase()` operation; it only reorders the iterator management.
- **Postcondition**: The vector contains all tasks with `completed == false`, in their original relative order. Tasks with `completed == true` are removed. This behaviour is unchanged from the intended design; only the unsafe iterator reuse is fixed.
- **No observable difference when unsafe code would not crash**: If the undefined behavior did not result in a crash in the original (a common situation with modern allocators), the fixed and broken versions produce the same output. The fix prevents potential crashes and memory corruption as the vector grows or the allocator reuses memory.
