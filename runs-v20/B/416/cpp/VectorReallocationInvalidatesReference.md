## Verdict

exploitable (confidence: high)

- cwe_id: 416
- location: `VectorReallocationInvalidatesReference.cpp`, line 36 (`current.priority = completionPriority;`)

## Source

`Task& current = tasks[activeIndex];` at line 28 binds a reference into the backing store of `TaskScheduler::tasks` (a `std::vector<Task>`). `activeIndex` is caller-supplied and not otherwise relevant to the defect - the vulnerability is intrinsic to holding the reference across a mutating call, independent of the index value.

## Fix

### File: VectorReallocationInvalidatesReference.cpp

```cpp
// Task scheduler: promotes the currently active task and queues a follow-up
// task in the same batch. Demonstrates a reference into a std::vector being
// invalidated by a subsequent push_back that reallocates the backing store.

#include <string>
#include <vector>

struct Task {
    std::string name;
    int priority;
    bool completed;
};

Task makeFollowUpTask(const Task& source) {
    return Task{source.name + "-followup", source.priority, false};
}

class TaskScheduler {
public:
    void addTask(const std::string& name, int priority) {
        tasks.push_back(Task{name, priority, false});
    }

    // Marks the task at activeIndex complete, then queues a follow-up task
    // derived from it, and finally records the completion time on the
    // original task. The index is re-applied after push_back rather than
    // reusing a reference taken before it, because push_back can reallocate
    // the vector's backing store and invalidate every outstanding reference.
    void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
        tasks[activeIndex].completed = true;

        Task follow = makeFollowUpTask(tasks[activeIndex]);
        follow.priority = completionPriority;
        tasks.push_back(follow);

        // Re-index instead of reusing a reference taken before push_back:
        // the reallocation above may have moved the backing store, so any
        // reference obtained beforehand is dangling here.
        tasks[activeIndex].priority = completionPriority;
    }

    const std::vector<Task>& allTasks() const {
        return tasks;
    }

private:
    std::vector<Task> tasks;
};
```

## Explanation

`tasks.push_back(follow)` can force `std::vector<Task>` to reallocate its backing store when capacity is exhausted, which copies or moves every existing `Task` into a new allocation and frees the old one. The `Task&` reference `current`, taken before that call, still points at the freed allocation; the subsequent `current.priority = completionPriority` at line 36 is a write through a dangling reference - the classic use-after-free shape called out for `std::vector` in this repository's CWE-416 C++ guidance ("a `vector` reallocation invalidates it even while the owner is alive"). The fix removes the long-lived reference entirely and re-indexes the vector (`tasks[activeIndex]`) at each access point, including after the `push_back`. `activeIndex` is a plain `std::size_t`, not an iterator or reference, so it is not invalidated by reallocation and always resolves to the correct element regardless of where the backing store now lives, per the guidance's remediation step to "re-acquire an iterator or pointer after any operation that can invalidate it, rather than reusing one taken before."

## Behaviour changes

- Removed the local `Task& current` binding; all three accesses (`completed = true`, building `follow`, and the final `priority` assignment) now go through `tasks[activeIndex]` directly. This changes no observable behavior for any `activeIndex` in bounds: each access still targets the same element, and the value read for `makeFollowUpTask` is identical (`current` and `tasks[activeIndex]` were equal at that point in both versions, since no invalidating call had happened yet).
- No arguments, return values, or error/failure behavior changed. `completeAndQueueFollowUp` still returns `void`, and out-of-bounds behavior for `activeIndex` is unchanged (`operator[]` gives undefined behavior in both the original and fixed code; this finding is about the dangling reference, not bounds checking, so that pre-existing characteristic was left alone).
- Net effect: `none` beyond closing the weakness.

## Verification

No C++ compiler (g++, clang++, or cl) was reachable in this environment, so the fix was checked by hand rather than compiled. Confirmed: `tasks` is a private member accessible from `TaskScheduler`'s own methods, `operator[]` on `std::vector<Task>` returns `Task&` (matching how it was already used at line 28 in the original), `makeFollowUpTask` still receives a `const Task&` (satisfied by `tasks[activeIndex]`), and no new symbol, header, or signature was introduced - `std::size_t` was already used unmodified in the function's parameter list in the original file. Every reference to `current` was replaced consistently; no stray use of the removed name remains.
