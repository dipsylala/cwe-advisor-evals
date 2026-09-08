## Verdict

Confirmed. `completeAndQueueFollowUp` takes a reference (`current`) into `tasks` at line 28, then calls `tasks.push_back(follow)` at line 33. `push_back` can trigger a reallocation of the vector's backing store, which invalidates every existing reference, pointer, and iterator into the vector, including `current`. Line 36 (`current.priority = completionPriority;`) then writes through that potentially-dangling reference — a classic use-after-free on the reallocated buffer.

## Source

- Reference obtained at `Task& current = tasks[activeIndex];` (line 28), inside `TaskScheduler::completeAndQueueFollowUp`.
- Invalidating operation: `tasks.push_back(follow);` (line 33), which may reallocate `tasks`' backing array.
- Sink: `current.priority = completionPriority;` (line 36), a write through the (possibly invalidated) reference after the reallocating call.

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
    // original task. The task is re-accessed by index after push_back
    // rather than held via a reference across it, since push_back may
    // reallocate the vector's backing store and invalidate any prior
    // reference, pointer, or iterator into it.
    void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
        tasks[activeIndex].completed = true;

        Task follow = makeFollowUpTask(tasks[activeIndex]);
        follow.priority = completionPriority;
        tasks.push_back(follow);

        // Re-index here: `tasks` may have reallocated during push_back
        // above, so any reference taken before that call could be dangling.
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

The original code cached a `Task&` (`current`) before calling `tasks.push_back(follow)`. `std::vector::push_back` gives no guarantee that the existing buffer is reused; when capacity is exhausted it allocates a new, larger buffer, copies/moves all existing elements into it, and frees the old buffer. Any reference, pointer, or iterator obtained before that call and used afterward refers to freed memory — reading or writing through it is undefined behavior, and in this case line 36 writes through it.

The fix removes the long-lived reference entirely and instead re-looks-up `tasks[activeIndex]` each time the task is touched. `tasks[activeIndex].completed = true;` and the read for `makeFollowUpTask` both happen before the `push_back`, when the reference/temporary access is still valid, and the final `tasks[activeIndex].priority = completionPriority;` happens after `push_back`, re-indexing into whatever buffer the vector currently owns rather than reusing a pointer that may have been freed. This preserves the original behavior (mark the active task completed, queue a follow-up derived from its pre-completion state, then stamp the active task's own priority) while eliminating the dangling-reference write. `activeIndex` itself remains valid across a reallocation because indices, unlike references/pointers/iterators, are not invalidated by `push_back`.

An alternative fix of calling `tasks.reserve()` up front to avoid reallocation would be fragile, since it depends on capacity assumptions the caller doesn't control; re-indexing by position is the robust fix and requires no assumption about vector growth policy.
