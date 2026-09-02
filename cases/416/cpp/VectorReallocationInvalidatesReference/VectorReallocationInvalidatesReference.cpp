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
        Task& current = tasks[activeIndex];
        current.completed = true;

        Task follow = makeFollowUpTask(current);
        follow.priority = completionPriority;
        tasks.push_back(follow);

        // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
        current.priority = completionPriority;
    }

    const std::vector<Task>& allTasks() const {
        return tasks;
    }

private:
    std::vector<Task> tasks;
};
