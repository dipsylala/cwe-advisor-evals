## Verdict

CONFIRMED — Use-after-free via stale reference after vector reallocation.

## Source

Line 28 takes a reference to a vector element: `Task& current = tasks[activeIndex];`

Line 33 calls `tasks.push_back(follow)`, which may reallocate the vector's backing store, invalidating the reference `current`.

Line 36 dereferences the now-invalid reference: `current.priority = completionPriority;`

## Fix

The unsafe pattern: storing a reference to a vector element and dereferencing it after a push_back that may reallocate.

The safe pattern: re-acquire access to the element by index after any operation that can invalidate references.

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
    // original task via the index, not via a stale reference.
    void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
        Task& current = tasks[activeIndex];
        current.completed = true;

        Task follow = makeFollowUpTask(current);
        follow.priority = completionPriority;
        tasks.push_back(follow);

        // Re-access the element by index instead of using the stale reference,
        // since push_back may have reallocated the vector's backing store.
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

The original code held a reference to a vector element (`Task& current`) early in the function, then called `push_back()`, which may trigger reallocation of the vector's internal buffer. When a vector reallocates, all outstanding references and iterators to its elements are invalidated, because the elements are moved to a different memory location. The subsequent use of `current` on line 36 accesses memory that is no longer valid.

The fix changes line 36 to access the element by index (`tasks[activeIndex].priority`) instead of by the invalid reference. Since the index-based access re-acquires the reference after the push_back, it accounts for any reallocation that may have occurred. This follows the remediation pattern: "re-acquire an iterator or pointer after any operation that can invalidate it, rather than reusing one taken before."

The reference `current` taken on line 28 is still valid and used correctly on lines 29 and 31 (before the push_back), so no change is needed there. Only the final access, which occurs after the invalidating operation, is replaced.

## Behaviour changes

- The function now safely handles vector reallocation by re-acquiring the element by index.
- No functional change to the output or logic; the task's priority is still updated correctly regardless of whether reallocation occurred.
- Under `-fsanitize=address` or equivalent tooling, the original code would likely fault at the use-after-free on line 36; the fixed code will not.
