## Verdict

exploitable

## Source

Line 28: `Task& current = tasks[activeIndex];` - A reference into the `std::vector<Task>` is captured and held across a container modification.

## Fix

**Vulnerable code:**
```cpp
void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
    Task& current = tasks[activeIndex];  // Reference into vector
    current.completed = true;

    Task follow = makeFollowUpTask(current);
    follow.priority = completionPriority;
    tasks.push_back(follow);  // May reallocate, invalidating 'current'

    // CWE-416: 'current' reference may now be dangling
    current.priority = completionPriority;
}
```

**Fixed code:**
```cpp
void completeAndQueueFollowUp(std::size_t activeIndex, int completionPriority) {
    tasks[activeIndex].completed = true;

    Task follow = makeFollowUpTask(tasks[activeIndex]);
    follow.priority = completionPriority;
    tasks.push_back(follow);

    // Re-acquire through index after potential reallocation
    tasks[activeIndex].priority = completionPriority;
}
```

## Explanation

A `std::vector` reference or iterator is invalidated when the vector reallocates its backing storage during insertion. This occurs when `push_back()` causes capacity to be exceeded. The original code holds a reference to `tasks[activeIndex]` from line 28, then calls `tasks.push_back(follow)` at line 33, which can trigger reallocation and invalidate the reference. The subsequent use of `current` at line 36 is a use-after-free: the reference points to freed memory that may have been reallocated for unrelated data.

The fix eliminates the held reference and instead uses index-based access throughout. The index remains valid across vector reallocation (it points to the same logical position), and re-acquiring the reference at line 36 after the `push_back()` ensures the reference is always valid before use. This follows the C++ guidance principle: "re-acquire an iterator or pointer after any operation that can invalidate it, rather than reusing one taken before."

## Behaviour changes

- Removed the reference variable `current` and replaced all accesses with index-based lookups `tasks[activeIndex]`.
- No change to the function's input parameters, return value, or external observable behaviour.
- The function still marks the task completed, creates and queues a follow-up task, and updates the priority on the original task in the exact same order.
- Accessing through the index guarantees the reference is fresh after any container modification, eliminating the invalidation risk entirely.
