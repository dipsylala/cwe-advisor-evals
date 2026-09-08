## Verdict

Confirmed. `EventBus::publish` dereferences a raw `Observer *` pulled from `observers_` with no lifetime guarantee that the pointed-to object still exists.

## Source

`sensor_monitor.cpp`, `monitorOnce()`: a stack-local `SensorObserver observer` is registered with `sharedBus().subscribe(&observer)`. `EventBus` is a function-local `static`, so it outlives the function call. When `monitorOnce()` returns, `observer` is destroyed, but its address remains stored in `EventBus::observers_` with nothing removing it. The next call to `sharedBus().publish(...)` walks that vector and calls `observer->onEvent(code)` (`event_bus.cpp:18`) on a pointer to a destroyed stack object - a use-after-free.

## Fix

### File: event_bus.cpp

```cpp
#include <algorithm>
#include <vector>

class Observer {
public:
    virtual ~Observer() = default;
    virtual void onEvent(int code) = 0;
};

class EventBus {
public:
    void subscribe(Observer *observer) {
        observers_.push_back(observer);
    }

    void unsubscribe(Observer *observer) {
        observers_.erase(std::remove(observers_.begin(), observers_.end(), observer), observers_.end());
    }

    void publish(int code) {
        for (Observer *observer : observers_) {
            observer->onEvent(code);
        }
    }

private:
    std::vector<Observer *> observers_;
};

EventBus &sharedBus() {
    static EventBus bus;
    return bus;
}
```

### File: sensor_monitor.cpp

```cpp
class Observer {
public:
    virtual ~Observer() = default;
    virtual void onEvent(int code) = 0;
};

class EventBus {
public:
    void subscribe(Observer *observer);
    void unsubscribe(Observer *observer);
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

class ScopedSubscription {
public:
    ScopedSubscription(EventBus &bus, Observer *observer) : bus_(bus), observer_(observer) {
        bus_.subscribe(observer_);
    }

    ~ScopedSubscription() {
        bus_.unsubscribe(observer_);
    }

    ScopedSubscription(const ScopedSubscription &) = delete;
    ScopedSubscription &operator=(const ScopedSubscription &) = delete;

private:
    EventBus &bus_;
    Observer *observer_;
};

void monitorOnce() {
    SensorObserver observer;
    ScopedSubscription subscription(sharedBus(), &observer);
    // subscription's destructor runs before observer's (reverse construction
    // order), unsubscribing it from sharedBus() so the bus never retains a
    // pointer to a destroyed SensorObserver.
}
```

## Explanation

`EventBus` had no way to remove a registered observer, so any subscriber with a shorter lifetime than the bus left a dangling pointer behind as soon as it went out of scope. The fix adds `EventBus::unsubscribe`, which erases the matching pointer from `observers_`, and pairs every `subscribe` call with a guaranteed `unsubscribe` via `ScopedSubscription`, an RAII guard that unsubscribes in its destructor. Because C++ destroys stack objects in the reverse order of construction, `subscription` (constructed after `observer`) is destroyed before `observer`, so the dangling-pointer window is closed even if `monitorOnce()` returns early or an exception unwinds the stack. `publish()` itself is unchanged: once subscribers are reliably removed on destruction, iterating `observers_` and calling `onEvent` is safe.
