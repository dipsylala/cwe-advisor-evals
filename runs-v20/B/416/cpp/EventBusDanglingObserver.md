## Verdict

Exploitable. Confidence: high.

- CWE-416 (Use After Free)
- Location: `event_bus.cpp:18`, `EventBus::publish()`, `observer->onEvent(code)`

## Source

- `sensor_monitor.cpp:25-26` - `monitorOnce()` creates `SensorObserver observer;` as a stack local and calls `sharedBus().subscribe(&observer);`, handing the bus a raw pointer to that stack object.
- `event_bus.cpp:11-13` - `EventBus::subscribe()` stores the raw `Observer *` in the member vector `observers_` with no ownership and no unsubscribe path.
- `sensor_monitor.cpp:29` - `monitorOnce()` returns; `observer` goes out of scope and is destroyed, but the pointer copy inside `sharedBus()`'s `observers_` is never cleared, because `EventBus` is a function-local `static` (`event_bus.cpp:26-29`) that outlives every caller of `monitorOnce()`.
- `event_bus.cpp:16-18` (sink) - a later call to `EventBus::publish()` iterates `observers_` and calls `observer->onEvent(code)` on the now-dangling pointer, reading/writing through memory that belonged to the destroyed `SensorObserver`.

Nothing in the chain re-validates or nulls the pointer between destruction and the next `publish()`, so the path is live: any caller of `monitorOnce()` followed by any caller of `sharedBus().publish()` triggers the use-after-free.

## Fix

### File: event_bus.cpp

```cpp
#include <memory>
#include <vector>

class Observer {
public:
    virtual ~Observer() = default;
    virtual void onEvent(int code) = 0;
};

class EventBus {
public:
    void subscribe(std::weak_ptr<Observer> observer) {
        observers_.push_back(std::move(observer));
    }

    void publish(int code) {
        for (auto it = observers_.begin(); it != observers_.end(); ) {
            if (auto observer = it->lock()) {
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
    void subscribe(std::weak_ptr<Observer> observer);
    void publish(int code);
};

EventBus &sharedBus();

class SensorObserver : public Observer, public std::enable_shared_from_this<SensorObserver> {
public:
    void onEvent(int code) override {
        lastCode = code;
    }

    int lastCode = 0;
};

void monitorOnce() {
    auto observer = std::make_shared<SensorObserver>();
    sharedBus().subscribe(observer);
    // observer is a shared_ptr; the bus stores only a weak_ptr, so when this
    // shared_ptr goes out of scope the SensorObserver is destroyed and the
    // bus's weak_ptr safely reports expired instead of dangling.
}
```

## Explanation

`EventBus` previously stored a bare `Observer *`, giving it no say in the subscriber's lifetime, while the only caller in this chain subscribed a stack local that was destroyed as soon as `monitorOnce()` returned. `subscribe()` now takes a `std::weak_ptr<Observer>`, a non-owning handle that can be asked whether the object it refers to is still alive; `observers_` is a `std::vector<std::weak_ptr<Observer>>` instead of a vector of raw pointers. `publish()` calls `lock()` on each entry, which atomically produces a `shared_ptr` if the object is still alive or a null one if it is not - resolving the liveness check and the dereference as a single operation with no window for the object to be freed in between. A `lock()` that fails means the subscriber has already been destroyed, so `publish()` erases that entry and moves on instead of dereferencing it. On the subscriber side, `monitorOnce()` now owns the `SensorObserver` through a `shared_ptr` created with `std::make_shared`, and `subscribe()` takes a `weak_ptr` copy of it (the implicit `shared_ptr<SensorObserver>` -> `weak_ptr<Observer>` conversion is well-formed because `SensorObserver` publicly derives from `Observer`). The object's destruction is unchanged - it is still destroyed when `monitorOnce()` returns and the `shared_ptr` refcount drops to zero - but the bus's reference to it no longer outlives that destruction as a live-looking pointer; it becomes an expired `weak_ptr` that `lock()` reports as such.

## Behaviour changes

- `EventBus::subscribe()`'s parameter type changes from `Observer *` to `std::weak_ptr<Observer>`. Every subscriber must be owned by a `shared_ptr` rather than passed as a raw address; this is the mechanism the fix relies on, not an incidental change. `SensorObserver` moves from a stack local to a `std::make_shared`-allocated object for this reason.
- `EventBus::publish()` no longer delivers `onEvent()` to a subscriber whose owning `shared_ptr`(s) have all gone out of scope - it silently skips it and removes it from `observers_`. Previously this case was not "handled" at all: it was the undefined-behaviour use-after-free being fixed. There is no explicit unsubscribe API in either file, so this lazy prune on `publish()` is the only removal path; a bus that is rarely published to could retain expired-but-not-yet-pruned entries for longer between calls than before, but each stored entry is now a small `weak_ptr` rather than a dangling raw pointer, so this has no correctness impact.
- No change to `EventBus::publish()`'s return type, `onEvent()`'s signature, or the order in which live observers are notified.

## Verification

No C++ compiler (`g++`, `clang++`, `cl`) was reachable in this environment, so the fix was checked by hand rather than compiled. Confirmed by inspection: every new symbol (`std::weak_ptr`, `std::shared_ptr`, `std::make_shared`, `std::enable_shared_from_this`, `std::move`, `std::vector::erase`) is standard library, declared via the added `#include <memory>`; the `subscribe()` declaration in `sensor_monitor.cpp` matches the definition in `event_bus.cpp`; the implicit `shared_ptr<SensorObserver>` to `weak_ptr<Observer>` conversion passed to `subscribe()` is well-formed per the standard's `weak_ptr` converting constructor, since `SensorObserver` is publicly and unambiguously derived from `Observer`; and the `publish()` loop's erase-or-increment pattern only advances `it` on the branch that does not erase, avoiding iterator invalidation.

## Assumptions

- `monitorOnce()` and `sharedBus()` are the only call sites for this pattern in scope; the fix assumes every other subscriber to `EventBus` in the wider codebase can be migrated to hold the observer through a `shared_ptr` (introducing one at the point of construction where it does not already exist). No other call sites were provided in this chain.
