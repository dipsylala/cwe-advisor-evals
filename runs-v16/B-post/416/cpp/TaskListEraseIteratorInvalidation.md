## Verdict

exploitable

## Source

Line 9: Loop initialization with `tasks.begin()` where `tasks` is a reference parameter passed to the function.

## Fix

**Vulnerable code (line 8-15):**
```cpp
void removeCompletedTasks(std::vector<Task> &tasks) {
    for (auto it = tasks.begin(); it != tasks.end(); ++it) {
        if (it->completed) {
            // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
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
            it = tasks.erase(it);
        } else {
            ++it;
        }
    }
}
```

## Explanation

The original code calls `tasks.erase(it)` on line 12, which removes the element at iterator `it` and invalidates that iterator along with all iterators at or after the erased position. After the call returns, control flow loops back to line 9, where the loop condition `it != tasks.end()` evaluates with the now-invalid iterator, and line 9 attempts to increment it with `++it`, causing undefined behavior and a use-after-free vulnerability.

The fix uses the return value of `std::vector::erase()`, which yields an iterator to the element immediately following the erased element (or `end()` if the last element was erased). Assigning this return value to `it` ensures that every subsequent use of the iterator is valid. The loop increment `++it` is moved into an else block and executes only when no element was erased; this way, the iterator advances correctly regardless of whether the current element was removed.

## Behaviour changes

Moved the loop increment from the `for` statement into an else block, executed only when no element is erased. This prevents double-incrementing when `erase()` already advances past the removed element. The fix preserves the original function's contract: all completed tasks are removed, and the function returns void with the vector modified in-place.
