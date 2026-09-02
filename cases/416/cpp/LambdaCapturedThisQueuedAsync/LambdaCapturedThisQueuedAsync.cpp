#include <functional>
#include <vector>

// Minimal deferred task queue standing in for a real async executor, such
// as asio::io_context::post() or a thread pool's submit().
class TaskQueue {
public:
    void post(std::function<void()> task) {
        tasks_.push_back(std::move(task));
    }

    void runPending() {
        for (auto& task : tasks_) {
            task();
        }
        tasks_.clear();
    }

private:
    std::vector<std::function<void()>> tasks_;
};

class Widget {
public:
    explicit Widget(int id) : id_(id) {}

    // Arms a deferred callback that fires once the owning event loop gets
    // around to draining the queue, which may be long after this call
    // returns.
    void startTimer(TaskQueue& queue) {
        // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
        queue.post([this]() { this->onTimerFired(); });
    }

    void onTimerFired() {
        lastFiredId_ = id_;
    }

    int lastFiredId() const { return lastFiredId_; }

private:
    int id_;
    int lastFiredId_ = 0;
};

// Simulates a request handler that creates a short-lived Widget, arms its
// timer against the shared queue, and returns. The Widget is destroyed at
// the end of this function, well before runPending() ever drains the
// queue, so the queued lambda's captured `this` is left dangling.
void handleRequest(TaskQueue& queue) {
    Widget widget(42);
    widget.startTimer(queue);
} // widget destroyed here; queue still holds a lambda capturing its raw `this`

void runEventLoop(TaskQueue& queue) {
    handleRequest(queue);
    // The lambda captured earlier now runs, dereferencing a dangling
    // `this` pointer into memory the Widget object used to occupy.
    queue.runPending();
}

int main() {
    TaskQueue queue;
    runEventLoop(queue);
    return 0;
}
