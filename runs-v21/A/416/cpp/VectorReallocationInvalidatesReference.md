## Verdict
Use-after-free vulnerability confirmed. The reference `current` obtained at line 28 is invalidated by the `push_back()` call at line 33, which may reallocate the vector's backing storage. The subsequent use at line 36 accesses freed memory.

## Source
`completeAndQueueFollowUp()` at line 27 stores a reference to a vector element before performing a `push_back()` that can trigger reallocation, then uses the invalidated reference after the reallocation.

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
    // original task via the reference taken at the top of the function.
    void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
        tasks[activeIndex].completed = true;

        Task follow = makeFollowUpTask(tasks[activeIndex]);
        follow.priority = completionPriority;
        tasks.push_back(follow);

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
The fix eliminates the invalidated reference by using the index `activeIndex` directly instead of storing a reference to `tasks[activeIndex]`. This approach:

1. Avoids taking a reference before `push_back()` that may reallocate
2. Re-accesses the element by index after each operation, ensuring the access remains valid even if reallocation occurs
3. Maintains the same logical flow and semantics as the original code

The vector reallocation during `push_back()` does not change the index; only references and pointers to elements are invalidated. By working through the index, we guarantee that subsequent accesses correctly locate the intended element in the vector, whether or not reallocation happened.
