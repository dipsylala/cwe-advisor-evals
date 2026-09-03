## Verdict

The code contains a use-after-free vulnerability at line 12. Calling `tasks.erase(it)` invalidates the iterator, and the loop's increment expression `++it` in the for statement subsequently dereferences the dangling iterator.

## Source

```cpp
void removeCompletedTasks(std::vector<Task> &tasks) {
    for (auto it = tasks.begin(); it != tasks.end(); ++it) {
        if (it->completed) {
            tasks.erase(it);  // Line 12: erase invalidates iterator
        }
    }
}
```

The issue occurs because `std::vector::erase()` invalidates all iterators at or after the erased position. When an element is erased, the loop's implicit increment `++it` operates on an invalid iterator.

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

The fix uses the return value of `erase()`, which provides a valid iterator to the element following the erased element. The loop increment is moved into a conditional: increment only when no erase occurs, since `erase()` already advances to the next element.

## Explanation

The vulnerability stems from invalidating an iterator while iterating. `std::vector::erase()` returns an iterator to the element following the erased element (or `end()` if the last element was erased). By capturing this return value and assigning it to `it`, the code maintains a valid iterator for the next iteration. The loop condition check `it != tasks.end()` still works correctly because the returned iterator is always valid relative to the current container state. This pattern ensures that every element is visited exactly once, and no dangling iterators are dereferenced.

