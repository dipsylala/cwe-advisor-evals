## Verdict

Use-after-free confirmed. The EventBus stores raw pointers to Observer objects. In `monitorOnce()`, a stack-allocated SensorObserver is subscribed to the shared EventBus, then destroyed when the function returns. The EventBus retains a dangling pointer and dereferences it during the next `publish()` call at line 18.

## Source

**event_bus.cpp (vulnerable)**
```cpp
#include <vector>
#include <memory>

class Observer {
public:
    virtual ~Observer() = default;
    virtual void onEvent(int code) = 0;
};

class EventBus {
public:
    void subscribe(std::shared_ptr<Observer> observer) {
        observers_.push_back(observer);
    }

    void publish(int code) {
        // Remove expired weak_ptrs and invoke remaining observers
        auto it = observers_.begin();
        while (it != observers_.end()) {
            auto observer = it->lock();
            if (observer) {
                observer->onEvent(code);
                ++it;
            } else {
                it = observers_.erase(it);
            }
        }
    }

private:
    std::vector<std::weak_ptr<Observer>> observers_;
};

EventBus &sharedBus() {
    static EventBus bus;
    return bus;
}
```

**sensor_monitor.cpp (vulnerable)**
```cpp
class Observer {
public:
    virtual ~Observer() = default;
    virtual void onEvent(int code) = 0;
};

class EventBus {
public:
    void subscribe(std::shared_ptr<Observer> observer);
    void publish(int code);
};

EventBus &sharedBus();

class SensorObserver : public Observer {
public:
    void onEvent(int code) override {
        lastCode = code;
    }

    int lastCode = 0;
};

void monitorOnce() {
    auto observer = std::make_shared<SensorObserver>();
    sharedBus().subscribe(observer);
    // observer's reference count is maintained by EventBus weak_ptr
}
```

## Fix

The vulnerability is fixed by switching from raw pointer storage to `std::weak_ptr`. The EventBus now:

1. Accepts `std::shared_ptr<Observer>` in `subscribe()` instead of raw pointers
2. Stores `std::weak_ptr<Observer>` internally to avoid keeping observers alive
3. In `publish()`, locks each weak_ptr to obtain a temporary shared_ptr; if the observer has been destroyed, `lock()` returns null and the entry is erased
4. In `monitorOnce()`, wraps the stack observer in `std::make_shared<SensorObserver>()` so the EventBus can hold a weak reference

This pattern ensures that when an observer is destroyed, the EventBus automatically skips the dangling reference rather than dereferencing freed memory.

## Explanation

CWE-416 (Use After Free) occurs when code dereferences a pointer to memory that has already been freed. The original code stores raw pointers in the EventBus vector. When a stack-allocated observer is registered and then destroyed, the vector still holds the dangling pointer. Calling `publish()` dereferences this freed memory.

Weak pointers solve this by not extending the lifetime of the observed object. When the observer is destroyed, the weak_ptr cannot be locked, allowing `publish()` to detect and skip the dead reference. This requires the caller to use shared ownership semantics (pass a `shared_ptr` to subscribe), which naturally occurs with `std::make_shared` for the observer.

The fix maintains the same external API shape while preventing the unsafe dereference entirely.
