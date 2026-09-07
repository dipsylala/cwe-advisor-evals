## Verdict
VULNERABLE - CWE-416 (Use After Free)

The lambda at line 32 captures `this` as a raw pointer. When the Widget is destroyed at the end of handleRequest(), the captured pointer becomes dangling. Later execution of runPending() dereferences this dangling pointer.

## Source
The vulnerability originates in handleRequest() where a Widget with local scope (line 51) is queued with a task that captures its raw `this` pointer, then destroyed before the task executes.

## Fix
### File: LambdaCapturedThisQueuedAsync.cpp
```cpp
#include <functional>
#include <vector>
#include <memory>

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

class Widget : public std::enable_shared_from_this<Widget> {
public:
    explicit Widget(int id) : id_(id) {}

    // Arms a deferred callback that fires once the owning event loop gets
    // around to draining the queue, which may be long after this call
    // returns.
    void startTimer(TaskQueue& queue) {
        // Capture shared_ptr to keep this Widget alive until the task executes
        queue.post([self = shared_from_this()]() { self->onTimerFired(); });
    }

    void onTimerFired() {
        lastFiredId_ = id_;
    }

    int lastFiredId() const { return lastFiredId_; }

private:
    int id_;
    int lastFiredId_ = 0;
};

// Simulates a request handler that creates a Widget managed by shared_ptr,
// arms its timer against the shared queue, and returns. The Widget remains
// alive as long as the queued lambda holds a reference to it.
void handleRequest(TaskQueue& queue) {
    auto widget = std::make_shared<Widget>(42);
    widget->startTimer(queue);
} // widget local variable goes out of scope, but shared_ptr reference in lambda keeps object alive

void runEventLoop(TaskQueue& queue) {
    handleRequest(queue);
    // The lambda's captured shared_ptr keeps the Widget alive, so dereferencing
    // self in onTimerFired() is safe.
    queue.runPending();
}

int main() {
    TaskQueue queue;
    runEventLoop(queue);
    return 0;
}
```

## Explanation
The fix uses `std::enable_shared_from_this<Widget>` and captures `shared_from_this()` in the lambda instead of a raw `this` pointer. This ensures the Widget object remains alive for the lifetime of the queued task.

Key changes:
1. Widget inherits from `std::enable_shared_from_this<Widget>` to access a shared_ptr to itself
2. In startTimer(), the lambda captures `self = shared_from_this()` instead of `[this]`
3. handleRequest() creates the Widget using `std::make_shared` instead of a stack variable
4. The shared_ptr captured in the lambda prevents the Widget from being destroyed until the task completes

This is the idiomatic C++ pattern for extending object lifetimes across asynchronous boundaries.
