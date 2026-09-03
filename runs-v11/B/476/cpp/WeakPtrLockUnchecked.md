## Verdict
exploitable

## Source
`connection_` weak pointer member variable, passed from constructor parameter at line 11. The weak pointer's underlying object can be destroyed at any time, causing `lock()` to return an empty shared pointer.

## Fix

**Vulnerable Code (line 13-16):**
```cpp
void notify(const std::string& message) {
    auto connection = connection_.lock();
    connection->send(message);  // Undefined behaviour if lock() returned null
}
```

**Fixed Code:**
```cpp
void notify(const std::string& message) {
    auto connection = connection_.lock();
    if (connection) {
        connection->send(message);
    }
}
```

## Explanation
`std::weak_ptr::lock()` returns an empty `shared_ptr` when the pointed-to object has already been destroyed, which is the designed way to observe expiry of a weakly-referenced object. Dereferencing this empty shared pointer with `->` causes a null pointer dereference, resulting in undefined behaviour. The fix adds an explicit check using the `if (connection)` guard before dereferencing. This is the standard C++ pattern for handling weak pointer expiry and aligns with the language's type-system expectations that shared pointers be tested before use.

## Behaviour changes
**When the weak pointer's object is still alive:** No change; `send()` is called normally.

**When the weak pointer's object has been destroyed:** The original code crashes with a null dereference. The fixed code silently skips the send operation. This is the intended behaviour for an observer pattern where a notifier may outlive the connection it references. If the caller requires notification of expiry (e.g., to log, retry, or propagate an error), the fix should be extended with explicit error handling in place of the silent skip—for example, returning a status code or throwing an exception to signal that the notification could not be delivered.
