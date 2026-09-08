## Verdict

CONFIRMED: The code dereferences a `shared_ptr` without checking if `weak_ptr::lock()` succeeded. When the weak pointer expires (the original object is deleted), `lock()` returns an empty `shared_ptr`. Dereferencing it on line 15 causes undefined behavior.

## Source

**File:** E:\Github\cwe-advisor\evals\cases\476\cpp\WeakPtrLockUnchecked\WeakPtrLockUnchecked.cpp  
**Line:** 15

**Code:**
```cpp
void notify(const std::string& message) {
    auto connection = connection_.lock();
    connection->send(message);  // Dereferences without null check
}
```

The `weak_ptr::lock()` method on line 14 returns a `shared_ptr` that may be empty if the managed object has been deleted. This empty pointer is immediately dereferenced on line 15 without validation.

## Fix

### File: WeakPtrLockUnchecked.cpp

```cpp
#include <memory>
#include <string>
#include <stdexcept>

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
            throw std::runtime_error("Connection expired: cannot send message");
        }
        connection->send(message);
    }

private:
    std::weak_ptr<ClientConnection> connection_;
};
```

## Explanation

The fix adds a null check immediately after `lock()` before any dereference. When `lock()` returns an empty `shared_ptr` (indicating the weak pointer has expired), the code now throws `std::runtime_error` with a descriptive message rather than attempting to dereference null.

This aligns with the C++ guidance: "`std::weak_ptr` must be locked and the result tested - `lock()` returns an empty `shared_ptr` when the object is gone, which is the designed way to observe expiry, not an exceptional path." The check occurs at the point where the failure originates (when the weak pointer expires), ensuring the condition is observable and handled explicitly rather than at an arbitrary crash point downstream.

## Behaviour changes

- **On success (object still alive):** Behavior unchanged. The connection is locked, validated, and `send()` is called normally.
- **On failure (object expired):** Now throws `std::runtime_error` with message "Connection expired: cannot send message" instead of causing undefined behavior from dereferencing null. This provides a clean, observable failure point that the caller can handle with standard exception handling.
- **New requirement:** Callers of `notify()` should expect and handle `std::runtime_error` exceptions. This is a signature change that makes the failure mode explicit in the contract.
