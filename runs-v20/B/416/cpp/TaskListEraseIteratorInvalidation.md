## Verdict

exploitable

## Source

The `tasks` vector reference parameter of `removeCompletedTasks(std::vector<Task> &tasks)` - any `Task` in the caller's list whose `completed` flag is `true` drives the erase.

## Fix

`std::vector<Task>::erase(it)` at line 12.

Sink contract:
- **Returns** - `erase(it)` returns a valid iterator to the element that now occupies the erased position (or `end()` if the last element was erased). The original code discards this return value entirely.
- **Discards** - the replacement iterator described above; that discarded value is exactly what the caller needs to keep iterating safely.
- **Arguments left implicit** - none; `erase` takes only the iterator to remove.
- **Failure behaviour** - `erase` does not throw for a valid iterator into the vector; passing a stale/invalidated iterator is undefined behaviour rather than a reported error, which is the defect here.

`std::vector::erase` invalidates the erased iterator and every iterator/reference from that point to `end()`, including `end()` itself. The `for` loop's own increment clause, `++it`, unconditionally runs after the `if` body on every iteration - including the one that just called `erase(it)` - so it advances an iterator that the erase call has already invalidated. That is a direct use of a dangling iterator (the standard library's typical implementation dereferences the freed/moved storage during the increment), matching CWE-416: the object erase() just released is accessed immediately afterward through the stale `it`. It is exploitable in the sense that it is reliably undefined behaviour on every call where a completed task is not the last element being visited, not merely a theoretical path - it fires on ordinary, non-adversarial input.

## Explanation

The loop is rewritten from a three-clause `for` with an unconditional `++it` in its increment clause to a `for` with an empty increment clause, so the iterator is advanced exactly once per loop body and only along a path that knows whether `it` was just invalidated. When `it->completed` is true, `it` is reassigned from the value `tasks.erase(it)` returns - the next valid iterator - instead of being left stale and then incremented. When it is false, `++it` runs exactly as before. This uses `erase`'s return value, which the original code silently discarded, to re-acquire a live iterator after the invalidating operation, per the CWE-416 C++ guidance's rule to "re-acquire an iterator or pointer after any operation that can invalidate it, rather than reusing one taken before." No ownership model change was needed here since the container already owns its elements by value; the defect was purely a stale-iterator access, not a lifetime/ownership gap.

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

## Behaviour changes

none - the function removes exactly the same set of elements (every `Task` with `completed == true`) in the same relative order of the survivors, and the signature, parameter, and return type are unchanged. The only change is how the loop advances its iterator after an erase, which is required to close the use-after-free and does not alter observable output.

**Verification**: no C++ compiler or syntax checker was reachable in this environment (`g++`, `clang++`, and `cl` all absent from PATH). Verified by manual read instead: the loop bounds (`it != tasks.end()`) and body are unchanged; `std::vector<Task>::erase(iterator)` is a standard-library member that returns `iterator` (the type of `it`, declared via `auto` from `tasks.begin()`), so `it = tasks.erase(it);` type-checks against `it`'s declared type; the `else` branch preserves the original unconditional `++it` for the non-erasing path; no new symbol, header, or dependency was introduced beyond what the original file already included (`<vector>`).

**Assumptions**: none beyond the language inference (C++, from the `.cpp` extension and `#include <vector>`/`std::vector` usage), which was unambiguous.
