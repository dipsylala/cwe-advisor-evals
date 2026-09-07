## Verdict

**CONFIRMED**: Use-after-free at line 18 of event_bus.cpp. The `EventBus` stores raw pointers to `Observer` objects in a vector. When an observer (like `SensorObserver` in `monitorOnce()`) is stack-allocated and goes out of scope, the vector still holds a dangling pointer. Subsequent `publish()` calls dereference this stale pointer, causing undefined behavior.

## Source

**event_bus.cpp, line 18:**
```cpp
observer->onEvent(code);  // Dereference of stale pointer
```

The observer pointer comes from `observers_` vector populated by `subscribe()` at line 12:
```cpp
void subscribe(Observer *observer) {
    observers_.push_back(observer);  // Stores raw pointer
}
```

**sensor_monitor.cpp, lines 25-26:**
```cpp
SensorObserver observer;  // Stack-allocated
sharedBus().subscribe(&observer);  // Passes address to registry
// Line 29: observer destroyed here, but EventBus still holds &observer
```

## Fix

**event_bus.cpp** — Use `std::weak_ptr` to store non-owning references; `lock()` at the point of use to safely check if the observer still exists:

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
        for (auto &weak_observer : observers_) {
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

**sensor_monitor.cpp** — Create the observer as a `std::shared_ptr` so its lifetime is properly tracked:

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
    // observer shared_ptr goes out of scope here. EventBus holds only a
    // weak_ptr, so the observer can be destroyed. On next publish(), the
    // weak_ptr.lock() will fail and the observer will be safely skipped.
}
```

## Explanation

The fix follows CWE-416 C++ guidance: use `std::weak_ptr` for observers that may outlive the registry, and call `lock()` at the point of use.

**What changed:**
- `EventBus::observers_` now stores `std::vector<std::weak_ptr<Observer>>` instead of `std::vector<Observer*>`, making explicit that these are non-owning references.
- `subscribe()` now takes `std::shared_ptr<Observer>` instead of raw pointer. The method internally stores only the weak_ptr, so it does not extend the observer's lifetime.
- `publish()` now calls `lock()` on each weak_ptr. If the observer has been destroyed, `lock()` returns `nullptr`, and the observer is safely skipped. If the observer is still alive, `lock()` returns a temporary `shared_ptr` that keeps it alive for the duration of the `onEvent()` call.
- `SensorObserver` in `monitorOnce()` is now created as `std::make_shared<SensorObserver>()`. When the function returns and the local shared_ptr goes out of scope, the object is destroyed. The EventBus's weak_ptr becomes invalid, so the stale-pointer dereference cannot occur.

This enforces the principle: "Invalidate cached pointers or references when the underlying resource is closed or freed elsewhere." The weak_ptr automatically invalidates when the last owning shared_ptr is released, and the `lock()` check prevents any attempt to dereference it.

## Behaviour changes

1. **Observer lifetime**: Observers are no longer required to outlive their subscription. An observer can be destroyed at any time; the EventBus gracefully handles the destruction by skipping it on the next `publish()` call.

2. **Memory management**: The caller is now responsible for keeping a `shared_ptr` to the observer for as long as the observer should receive events. Once all shared_ptrs are released, the observer is destroyed and automatically removed from the active registry.

3. **Iteration safety**: In the original code, iterating over destroyed pointers was undefined behavior. The fixed code never dereferences an invalid pointer; `lock()` returns `nullptr` for expired weak_ptrs, and the observer is simply skipped.

4. **No explicit unsubscribe required**: Unlike the original pattern (which would require an explicit unsubscribe in the observer's destructor to prevent this bug), the fix handles cleanup automatically through reference counting. This is exception-safe and does not rely on discipline in destructor ordering.

5. **Performance**: One additional level of indirection (weak_ptr) and a `lock()` call per observer per `publish()`. For typical observer counts, this overhead is negligible and is a worthwhile trade for use-after-free safety.
