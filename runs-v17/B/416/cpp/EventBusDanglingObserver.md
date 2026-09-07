## Verdict

Use-after-free confirmed. EventBus stores raw pointers to Observer objects but does not own them. When an observer is destroyed (e.g., a stack-allocated SensorObserver in monitorOnce()), the EventBus retains a dangling pointer. On the next publish() call, line 18 dereferences this stale pointer, resulting in undefined behavior - reading/writing memory that has been freed and potentially reallocated.

## Source

**event_bus.cpp, line 18**: `observer->onEvent(code)` - dereference of a raw pointer that may point to destroyed memory

**sensor_monitor.cpp, lines 25-26**: A stack-allocated SensorObserver is registered with the static shared EventBus via a raw pointer, then destroyed when the function returns, but EventBus retains the stale pointer.

## Fix

### File: event_bus.cpp
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

    void publish(int code) {
        // Remove expired weak_ptr entries (observers that have been destroyed)
        observers_.erase(
            std::remove_if(observers_.begin(), observers_.end(),
                [](const std::weak_ptr<Observer> &obs) {
                    return obs.expired();
                }),
            observers_.end());

        // Call onEvent on remaining observers
        for (auto &observer_weak : observers_) {
            if (auto observer = observer_weak.lock()) {
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

### File: sensor_monitor.cpp
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
    // observer is now managed by shared_ptr and stored as weak_ptr in EventBus.
    // When observer goes out of scope, the shared_ptr reference count decreases,
    // but EventBus's weak_ptr will detect it as expired and skip it on next publish().
}
```

## Explanation

The fix replaces raw pointer storage with `std::weak_ptr` to detect when observers have been destroyed, and requires observers to be managed by `std::shared_ptr` in the caller. 

In EventBus:
- `subscribe()` now accepts `std::shared_ptr<Observer>` instead of a raw pointer. This establishes that observers are owned externally as shared_ptr instances.
- `observers_` now stores `std::weak_ptr<Observer>` instead of raw pointers. Weak pointers do not extend the lifetime of the referred-to object; when an observer is destroyed (its last shared_ptr is released), the weak_ptr automatically becomes "expired."
- In `publish()`, expired weak_ptrs are cleaned up with `remove_if` and `std::weak_ptr::expired()`. 
- Before dereferencing each observer, `lock()` is called to attempt upgrading the weak_ptr to a temporary shared_ptr. If the observer has been destroyed, `lock()` returns a null shared_ptr and the observer is skipped. If the observer still exists, `lock()` returns a valid shared_ptr that keeps the observer alive for the duration of the call.

In sensor_monitor.cpp:
- `monitorOnce()` now uses `std::make_shared<SensorObserver>()` to create an observer as a shared_ptr, and passes this shared_ptr to `subscribe()`. When the function returns, the local shared_ptr goes out of scope, but as long as EventBus holds a weak_ptr, the observer remains alive. When EventBus's weak_ptr detects the observer has been destroyed (typically at the next `publish()` call), it skips that observer rather than dereferencing a dangling pointer.

This follows C++ CWE-416 guidance: "Use `std::weak_ptr` for an observer that may outlive the object, and `lock()` at the point of use so the check and the access cannot be separated." The fix guarantees that no reference to a released allocation is ever dereferenced by using weak_ptr to detect destruction and lock() to safely check and access the object atomically.

## Behaviour changes

- **API change**: `subscribe()` now requires `std::shared_ptr<Observer>` instead of raw pointers. Code calling `subscribe(&observer)` with a raw pointer will not compile and must be updated to use `std::make_shared` or another shared_ptr constructor.
- **Automatic cleanup**: Expired observers (those whose last shared_ptr has been released) are automatically removed from the observers list during `publish()`. Previously, the list would retain dangling pointers indefinitely.
- **Graceful degradation**: If an observer is destroyed while still registered (e.g., a stack-allocated observer), the next `publish()` will silently skip it rather than crashing or corrupting memory. This prevents crashes and undefined behavior in scenarios where an observer's lifetime ends before unsubscription occurs.
- **No unsubscribe method needed**: Previously, callers would need to manually unsubscribe before destroying an observer. With the weak_ptr approach, this is optional - the EventBus automatically handles destroyed observers. Manual unsubscription via an `unsubscribe()` method is still possible to add if needed for performance (to avoid the cleanup pass in `publish()`), but it is not required for correctness.
- **Performance**: The `publish()` method now performs `remove_if` cleanup on every call, which is O(n). If performance is critical with a large number of observers, an explicit `unsubscribe()` method can be added to remove an observer on demand rather than deferring cleanup until the next publish().
