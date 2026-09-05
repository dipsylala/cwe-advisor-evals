# CWE-416 Remediation: TaskListEraseIteratorInvalidation

## Verdict

Exploitable. The iterator `it` becomes invalid after `tasks.erase(it)` on line 12, and the for-loop's implicit increment (`++it`) on the next iteration dereferences this invalid iterator, causing undefined behavior that can lead to memory corruption or a crash.

## Source

Iterator `it` obtained from `tasks.begin()` on line 9 of the for-loop initialization.

## Fix

**Vulnerable Code:**
```cpp
void removeCompletedTasks(std::vector<Task> &tasks) {
    for (auto it = tasks.begin(); it != tasks.end(); ++it) {
        if (it->completed) {
            tasks.erase(it);  // Line 12: iterator invalidated here
        }
    }
}
```

**Fixed Code:**
```cpp
void removeCompletedTasks(std::vector<Task> &tasks) {
    for (auto it = tasks.begin(); it != tasks.end(); ) {
        if (it->completed) {
            it = tasks.erase(it);  // erase() returns iterator to next valid element
        } else {
            ++it;
        }
    }
}
```

## Explanation

The vulnerability occurs because `std::vector::erase()` invalidates all iterators at or following the erased element. In the original code, after erasing an element, the for-loop attempts to increment the now-invalid iterator `it`, resulting in undefined behavior—a use-after-free of the iterator. The fix leverages C++11's guarantee that `erase()` returns an iterator to the element following the erased element (or `end()` if the last element was erased). By assigning this return value back to `it`, we maintain a valid iterator for the next loop iteration. When an element is not erased, we manually increment `it` to move to the next element. This pattern is safe and efficient, avoiding the need to restart iteration or use additional data structures.

## Behaviour changes

The loop increment logic is refactored from automatic (in the for-statement) to conditional (either from `erase()` return value or manual `++it`). This change preserves the original contract: the loop still iterates through the vector and removes all completed tasks. No return value is altered, no output is discarded, and the function still maintains the same interface and side effects on the input vector.
