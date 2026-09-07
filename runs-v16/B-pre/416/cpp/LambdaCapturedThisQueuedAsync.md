## Verdict

Use-after-free confirmed. The lambda captures raw `this` and is stored in a queue that outlives the Widget object, resulting in a dangling pointer dereference when the queued task runs.

## Source

Line 32: `queue.post([this]() { this->onTimerFired(); });`

The lambda captures raw `this` and is posted to a task queue. The Widget object that `this` refers to is destroyed at the end of `handleRequest()` (line 53), but the lambda remains in the queue until `runPending()` executes it. At that point, `this` is a dangling pointer into freed memory.

## Fix

Make `Widget` derive from `std::enable_shared_from_this<Widget>`, and change `handleRequest()` to manage the Widget with `std::shared_ptr`. Capture `shared_from_this()` instead of raw `this`:

```cpp
#include <functional>
#include <memory>
#include <vector>

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

    void startTimer(TaskQueue& queue) {
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

void handleRequest(TaskQueue& queue) {
    auto widget = std::make_shared<Widget>(42);
    widget->startTimer(queue);
}

void runEventLoop(TaskQueue& queue) {
    handleRequest(queue);
    queue.runPending();
}

int main() {
    TaskQueue queue;
    runEventLoop(queue);
    return 0;
}
```

## Explanation

The vulnerability occurs because the lambda's captured `this` pointer points to a Widget object that is destroyed before the lambda executes. By deriving from `std::enable_shared_from_this<Widget>` and capturing the result of `shared_from_this()`, the lambda now holds an owning reference to the Widget through a shared_ptr. This keeps the Widget alive until the lambda has finished executing. The change also updates `handleRequest()` to use `std::make_shared<Widget>()` instead of a stack-allocated object, which is required for `enable_shared_from_this` to work correctly. Inside the lambda, `self` is a `std::shared_ptr<Widget>`, so `self->onTimerFired()` safely accesses the object through the smart pointer.

## Behaviour changes

- Widget is now heap-allocated via `std::make_shared` in `handleRequest()` instead of stack-allocated
- Widget lifetime is extended by the queued lambda; it is destroyed after `runPending()` completes rather than at the end of `handleRequest()`
- A new include `<memory>` is required for `std::enable_shared_from_this` and `std::make_shared`
- The lambda's capture changes from capturing raw `this` to capturing `self`, a `std::shared_ptr<Widget>`
