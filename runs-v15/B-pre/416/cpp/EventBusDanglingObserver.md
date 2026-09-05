## Verdict

Exploitable. The EventBus stores raw pointers to Observer objects that may be destroyed independently. When an observer goes out of scope after subscription, the EventBus holds a dangling pointer. The next publish() call dereferences it, triggering use-after-free.

## Source

Stack-allocated `SensorObserver observer` created in `monitorOnce()` (sensor_monitor.cpp, line 24). A raw pointer to it is subscribed to the EventBus.

## Fix

**Vulnerable code** (event_bus.cpp, lines 10-20):

```cpp
void subscribe(Observer *observer) {
    observers_.push_back(observer);
}

void publish(int code) {
    for (Observer *observer : observers_) {
        // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
        observer->onEvent(code);
    }
}

private:
    std::vector<Observer *> observers_;
```

**Fixed code**:

```cpp
#include <memory>

void subscribe(std::shared_ptr<Observer> observer) {
    observers_.push_back(observer);
}

void publish(int code) {
    for (auto& weakObs : observers_) {
        if (auto observer = weakObs.lock()) {
            observer->onEvent(code);
        }
    }
}

private:
    std::vector<std::weak_ptr<Observer>> observers_;
```

## Explanation

The fix ties observer lifetime to reference counting. Subscribers now pass `std::shared_ptr<Observer>`, signaling shared ownership. The EventBus stores `std::weak_ptr<Observer>` — it does not extend the observer's lifetime, but allows detection when an observer is destroyed. At line 18 (the sink), `lock()` atomically checks whether the observer still exists and acquires a temporary shared owner if it does. If the observer was destroyed, `lock()` returns nullptr and the observer is safely skipped. This pattern (per C++ guidance) ensures no dereference of a released allocation occurs: the observer cannot be released between the `lock()` check and the `onEvent()` call because `lock()` produced an owner that keeps it alive for the scope of the if-block.

## Behaviour changes

- **Subscribe signature:** Changes from `subscribe(Observer*)` to `subscribe(std::shared_ptr<Observer>)`. Callers must use `shared_ptr` for their observer objects, signaling that the EventBus may hold references to them across their original scope. This is a contract change: observers can no longer be created as stack locals and passed as raw pointers; they must be dynamically allocated and owned by `shared_ptr`.
- **Publish safety:** Observers that are destroyed no longer cause use-after-free; `lock()` detects expiry and skips them.
- **Performance:** Weak pointer overhead (additional indirection and atomic reference count checks on `lock()`), and the cost of `lock()` on every observer during publish.
- **Subscription cleanup:** Expired observers are detected and skipped on every publish but remain in the vector until explicitly cleared. For long-running services with frequent observer creation/destruction, consider periodic cleanup (erase-remove idiom with `expired()` check).
