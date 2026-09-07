## Verdict
Confirmed. The reference `current` to `tasks[activeIndex]` is invalidated by `push_back()` on line 33, which may reallocate the vector's backing store. The subsequent use on line 36 accesses a dangling reference.

## Source
```cpp
void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
    Task& current = tasks[activeIndex];  // Reference into vector
    current.completed = true;

    Task follow = makeFollowUpTask(current);
    follow.priority = completionPriority;
    tasks.push_back(follow);  // May reallocate, invalidating current

    // Line 36: Use-after-free via invalid reference
    current.priority = completionPriority;
}
```

## Fix
```cpp
void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
    Task& current = tasks[activeIndex];
    current.completed = true;
    current.priority = completionPriority;

    Task follow = makeFollowUpTask(current);
    follow.priority = completionPriority;
    tasks.push_back(follow);
}
```

## Explanation
Move the `current.priority = completionPriority` assignment to line 32, before the `push_back()` call that may invalidate the reference. This preserves the original semantics—the current task's priority is updated before the follow-up is queued—while avoiding any vector reallocation that would render `current` a dangling reference.

The reference remains valid throughout because it is no longer used after `push_back()`. If vector reallocation occurs, it happens only after all modifications through the reference are complete.
