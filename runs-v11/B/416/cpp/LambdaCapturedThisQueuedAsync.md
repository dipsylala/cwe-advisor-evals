## Verdict

Use-after-free confirmed. Lambda captures raw `this` pointer; Widget is destroyed before the queued lambda executes, leaving a dangling pointer dereference.

## Source

Line 32: `queue.post([this]() { this->onTimerFired(); });`

The lambda captures `this` by value but holds no ownership. Widget is destroyed at line 53 before the lambda runs at line 59.

## Fix

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
        // Capture shared_ptr to keep Widget alive while lambda is queued
        auto self = shared_from_this();
        queue.post([self]() { self->onTimerFired(); });
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
    auto widget = std::make_shared<Widget>(42);
    widget->startTimer(queue);
} // widget's shared_ptr is released here, but queued lambda holds a shared_ptr keeping it alive

void runEventLoop(TaskQueue& queue) {
    handleRequest(queue);
    // The lambda captured earlier now runs with a valid shared_ptr to the Widget
    queue.runPending();
}

int main() {
    TaskQueue queue;
    runEventLoop(queue);
    return 0;
}
```

## Explanation

The fix transforms ownership by making Widget derive from `std::enable_shared_from_this<Widget>` and capturing `shared_from_this()` instead of raw `this`. This creates a second owner of the Widget: the lambda holds a `shared_ptr` that keeps the object alive until the lambda completes and releases it. The handleRequest function now allocates Widget via `std::make_shared`, establishing the initial shared ownership. When handleRequest exits, its local `shared_ptr` is released, but the queued lambda still holds a valid reference, keeping the Widget alive until runPending() executes it. At that point, both owners release and the Widget is destroyed. Dereferencing through `shared_ptr` is safe because the object cannot be freed while any `shared_ptr` to it exists.

## Behaviour changes

- Widget is now always owned by a `shared_ptr` rather than being stack-allocated in handleRequest
- Widget stays alive as long as any queued lambda holds a reference to it
- No observable change to caller semantics: handleRequest still arms the timer and returns; runEventLoop still processes the queue as before
- The Widget's lastFiredId is still set to 42 when the deferred timer fires, as in the original
