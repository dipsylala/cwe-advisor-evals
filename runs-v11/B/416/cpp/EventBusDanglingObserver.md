## Verdict

Confirmed. The EventBus stores raw pointers to Observer objects in `observers_`, but has no mechanism to remove them when the Observer is destroyed. When `SensorObserver` is created as a local variable, subscribed to the EventBus, and then destroyed at function exit, the EventBus retains a dangling pointer. Any subsequent call to `publish()` dereferences the destroyed object.

## Source

**event_bus.cpp, line 18:** `observer->onEvent(code);` dereferences a raw pointer that may point to destroyed memory.

**Data flow:** `SensorObserver` (stack-allocated in `monitorOnce()`, line 25) → `sharedBus().subscribe(&observer)` stores raw pointer in EventBus → `observer` destroyed at line 29 → dangling pointer remains in `observers_` vector → `publish()` at line 18 dereferences freed memory.

## Fix

Replace the subscriber storage and access pattern to use `std::shared_ptr` and `std::weak_ptr`, ensuring observers remain alive for as long as the EventBus holds a reference to them, and gracefully handling the case when an observer is destroyed.

**event_bus.cpp:**
```cpp
#include <vector>
#include <memory>
#include <algorithm>

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

    void unsubscribe(std::shared_ptr<Observer> observer) {
        observers_.erase(
            std::remove_if(observers_.begin(), observers_.end(),
                [&observer](const std::weak_ptr<Observer>& obs) {
                    return obs.expired() || obs.lock() == observer;
                }),
            observers_.end()
        );
    }

    void publish(int code) {
        // Remove expired observers
        observers_.erase(
            std::remove_if(observers_.begin(), observers_.end(),
                [](const std::weak_ptr<Observer>& obs) { return obs.expired(); }),
            observers_.end()
        );

        for (auto& weak_observer : observers_) {
            if (auto observer = weak_observer.lock()) {
                observer->onEvent(code);
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

**sensor_monitor.cpp:**
```cpp
#include <memory>

class Observer {
public:
    virtual ~Observer() = default;
    virtual void onEvent(int code) = 0;
};

class EventBus {
public:
    void subscribe(std::shared_ptr<Observer> observer);
    void unsubscribe(std::shared_ptr<Observer> observer);
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
    // observer is held by both the local shared_ptr and the EventBus via weak_ptr
    // If subscribe() copies the shared_ptr, observer stays alive
    // If the local shared_ptr goes out of scope, EventBus weak_ptr detects it on publish()
}
```

## Explanation

**Root cause:** The EventBus stored raw pointers, creating a contract that subscribers must outlive the EventBus - but the API gave no way to enforce or check this. The SensorObserver violates this contract by being destroyed before the EventBus.

**Why the fix works:**
1. **Ownership transfer:** `subscribe()` now takes a `std::shared_ptr<Observer>`, which means if the EventBus stores it (via `weak_ptr`), it can keep the observer alive by holding a shared reference. The local `auto observer = std::make_shared<SensorObserver>()` creates ownership that is transferable.
2. **Weak reference:** EventBus stores `std::weak_ptr` rather than `std::shared_ptr`, so it does not extend the observer's lifetime - it merely observes it. When the last strong reference (the local variable or some caller) is destroyed, the weak pointer detects this.
3. **Safe dereference:** On `publish()`, the code calls `lock()` on each weak pointer. `lock()` returns a new `shared_ptr` if the observer is still alive, or `nullptr` if it has been destroyed. The call to `onEvent()` only happens inside the `if (auto observer = weak_observer.lock())` guard, so it never dereferences a dangling pointer.
4. **Cleanup:** Expired observers are removed from the vector to prevent unbounded growth and avoid repeated lock/unlock cycles.

This pattern is called "observer pattern with weak references" and is the idiomatic C++ solution when callbacks must outlive the object that registered them.

## Behaviour changes

- **API change:** `subscribe()` now requires `std::shared_ptr<Observer>` instead of a raw pointer. Callers must wrap their observer in a shared_ptr.
- **Graceful degradation:** If an observer is destroyed before `publish()` is called, the weak pointer simply skips that observer rather than crashing.
- **No unsubscribe required:** Although an `unsubscribe()` method is provided, it is now optional - observers are automatically cleaned up when destroyed.
- **Lifetime ownership:** The observer's lifetime is now explicitly managed: as long as the subscriber (or any other code) holds a shared_ptr to the observer, it remains alive. Once all shared references are released, the observer is destroyed and automatically skipped by the EventBus.
