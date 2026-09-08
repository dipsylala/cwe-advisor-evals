## Verdict

Exploitable

## Source

The `Task` object at index `activeIndex` in the `tasks` vector, obtained via reference on line 28.

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
    // original task via index-based access to avoid invalidation.
    void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
        tasks[activeIndex].completed = true;

        Task follow = makeFollowUpTask(tasks[activeIndex]);
        follow.priority = completionPriority;
        tasks.push_back(follow);

        // Safe: access through the stable index, not a stored reference.
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

The original code obtained a reference to a vector element on line 28 (`Task& current = tasks[activeIndex]`), then used that reference after a `push_back` that could reallocate the backing store. Vector reallocation invalidates all outstanding references and iterators, making the stored reference dangling. The fix replaces the stored reference with index-based access: each access to `tasks[activeIndex]` re-acquires the element fresh after any operation that might reallocate. Since the index remains valid across reallocation, this eliminates the use-after-free. The fix follows the C++ guidance pattern: "re-acquire an iterator or pointer after any operation that can invalidate it, rather than reusing one taken before."

## Behaviour changes

None. Index-based access to a vector element provides the same read/write semantics and object lifetime as a reference to that element. The `activeIndex` parameter remains valid throughout the function, and accessing `tasks[activeIndex]` at each point in the function accesses the same logical element as the original reference would have, had it not been invalidated. No implicit parameters were supplied, no defaults were changed, and the return value remains void.

