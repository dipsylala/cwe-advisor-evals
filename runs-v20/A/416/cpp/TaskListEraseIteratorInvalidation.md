## Verdict

Confirmed. `std::vector::erase(it)` invalidates `it` and every iterator from that point to `end()`. The loop's `++it` in the `for` statement then increments (and the next comparison/dereference uses) an invalidated iterator, which is undefined behavior and a use-after-free on the underlying buffer element.

## Source

`tasks` is the `std::vector<Task>&` parameter to `removeCompletedTasks`; the loop iterates it with `it`, and `it->completed` is read to decide which elements to remove.

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

`std::vector::erase` shifts all elements after the erased one down by one position and shrinks the vector, which invalidates the erased iterator along with every iterator, pointer, and reference at or beyond that position. The original code called `tasks.erase(it)` and then let the `for` loop's `++it` run on that now-invalid iterator - accessing freed/moved-from storage (use-after-free) and skipping the element that shifted into the erased slot on top of it.

The fix uses `erase`'s return value, which is a valid iterator to the element that now occupies the erased position (or `end()` if the erased element was last), and assigns it back to `it`. When no erase happens, `it` is advanced explicitly with `++it` in the loop body instead of the `for` statement, since the `for` statement's increment clause is now empty. This keeps `it` valid on every iteration and correctly visits every remaining element exactly once, including the one that shifted into the freed element's position.
