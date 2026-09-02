#include <vector>

struct Task {
    int id;
    bool completed;
};

void removeCompletedTasks(std::vector<Task> &tasks) {
    for (auto it = tasks.begin(); it != tasks.end(); ++it) {
        if (it->completed) {
            // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
            tasks.erase(it);
        }
    }
}
