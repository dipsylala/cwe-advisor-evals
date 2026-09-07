## Verdict

The finding is **confirmed**. The reference taken at line 28 is invalidated by the `push_back()` at line 33, and the subsequent access at line 36 operates on a dangling reference.

## Source

```cpp
void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
    Task& current = tasks[activeIndex];           // Line 28: reference taken
    current.completed = true;
    
    Task follow = makeFollowUpTask(current);
    follow.priority = completionPriority;
    tasks.push_back(follow);                       // Line 33: reallocation may occur
    
    current.priority = completionPriority;         // Line 36: use-after-free
}
```

The `push_back()` call may trigger vector reallocation, invalidating the `current` reference to an element in the old storage.

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
    // original task via index access after the vector operation.
    void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
        tasks[activeIndex].completed = true;
        
        Task follow = makeFollowUpTask(tasks[activeIndex]);
        follow.priority = completionPriority;
        tasks.push_back(follow);
        
        // Access via index instead of reference to avoid invalidation by reallocation
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

The fix eliminates the use of a reference that can be invalidated by vector reallocation:

- **Original issue**: Holding `Task& current = tasks[activeIndex]` and then calling `push_back()` creates a use-after-free if reallocation occurs.
- **Solution**: Access the task at `activeIndex` directly through `tasks[activeIndex]` at each point of use. This is safe because the index remains valid even if the vector reallocates.
- **Why this works**: Although `push_back()` may reallocate the backing storage, the index `activeIndex` still correctly identifies which task we need, and after reallocation the new storage contains the same data. No reference is held across the reallocation.

This is the standard defensive pattern for vector operations in C++: prefer index-based access over holding references when the vector's size might change.
