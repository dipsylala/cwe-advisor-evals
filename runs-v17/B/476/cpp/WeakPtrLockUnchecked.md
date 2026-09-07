## Verdict
Real vulnerability confirmed. `std::weak_ptr::lock()` returns an empty `std::shared_ptr` when the referenced object has been destroyed. The code dereferences this pointer without checking, causing undefined behavior.

## Source
Line 14-15 in `WeakPtrLockUnchecked.cpp`:
```cpp
auto connection = connection_.lock();
connection->send(message);  // undefined behaviour if lock() returns empty shared_ptr
```

The weak pointer's target (`ClientConnection`) may be destroyed at any time, making `lock()` return an empty `shared_ptr`. The code proceeds to dereference it without validation.

## Fix
### File: WeakPtrLockUnchecked.cpp

```cpp
#include <memory>
#include <string>

class ClientConnection {
public:
    void send(const std::string& message);
};

class Notifier {
public:
    explicit Notifier(std::weak_ptr<ClientConnection> connection) : connection_(connection) {}

    void notify(const std::string& message) {
        auto connection = connection_.lock();
        if (!connection) {
            return;
        }
        connection->send(message);
    }

private:
    std::weak_ptr<ClientConnection> connection_;
};
```

## Explanation
Added a null check after `lock()` returns. The `if (!connection)` guard tests whether the `shared_ptr` is valid before dereferencing it. If the target object has been destroyed and `lock()` returned an empty pointer, the function returns early rather than attempting the dereference. This prevents the undefined behavior while preserving the notification's intended contract: if the connection is gone, there is nothing to notify, so returning silently is correct.

## Behaviour changes
- If the target `ClientConnection` has been destroyed, `notify()` returns without crashing.
- The message is sent only if the connection remains alive at the moment of the call.
- No exception is thrown; the absence of a live connection is silently handled as a normal condition.
