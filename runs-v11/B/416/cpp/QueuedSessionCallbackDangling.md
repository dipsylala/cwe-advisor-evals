## Verdict

Real use-after-free: A raw pointer captured in a lambda is dereferenced after the object it references has been explicitly deleted.

## Source

The vulnerability is at line 33, `raw->touch()`, where `raw` is a raw pointer to a `Session` object that was extracted from a `std::unique_ptr` and captured by value in a lambda. After the lambda is enqueued, `session.reset()` on line 36 deletes the object, but the enqueued lambda still holds and will eventually dereference the stale pointer.

## Fix

Change the function to use `std::shared_ptr` and capture it in the lambda, so the object stays alive as long as the lambda exists:

```cpp
void scheduleSessionTouch(std::shared_ptr<Session> session, CallbackQueue &queue)
{
    queue.enqueue([session]() {
        session->touch();
    });
}
```

Alternatively, if the caller still uses `std::unique_ptr`, convert it at the call site:
- Change parameter type from `std::unique_ptr<Session>` to `std::shared_ptr<Session>`
- At call sites, pass `std::make_shared<Session>(...)` instead of `std::make_unique<Session>(...)`

Or, if the session must remain unique-owner but the callback needs to run later, use `std::weak_ptr` and check liveness at the point of use:

```cpp
void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    auto weak_session = std::make_shared<Session>(std::move(*session));
    auto weak = std::weak_ptr<Session>(weak_session);
    
    queue.enqueue([weak]() {
        if (auto session = weak.lock()) {
            session->touch();
        }
    });
}
```

The first option (converting to `shared_ptr` throughout) is preferred for simplicity and matches the guidance's recommendation: "capture a `shared_ptr` (or `weak_ptr`) instead" of a raw pointer in a callback.

## Explanation

The root cause is that the function extracts a raw pointer from a `unique_ptr` and captures it in a lambda that outlives the `unique_ptr`'s lifetime. When the `unique_ptr` is reset, the object is deleted, but the lambda still holds the stale raw pointer. Raw pointers carry no ownership information, so they cannot prevent the object from being deleted.

The fix ensures the object remains alive for as long as the lambda might be executed by transferring ownership into `shared_ptr` (which reference-counts all owners) and capturing that in the lambda. Since the lambda now holds a shared owner, the object cannot be deleted until all lambdas are executed and destroyed. This is the primary defense prescribed by the C++ guidance: "Make every reference an owner where the language allows it, so release is whatever happens last."

## Behaviour changes

- **Object lifetime extended**: The Session object now lives until the last callback holding it is destroyed, rather than being deleted immediately after `scheduleSessionTouch` returns.
- **Callback execution guaranteed**: The callback will always execute with a valid object; there is no race or deferred-deletion issue.
- **Reference counting overhead**: Using `shared_ptr` introduces atomic increment/decrement on copy and destruction, but this is negligible for typical callback patterns.
- **No early return**: The original code paths are preserved; only the ownership model changes.
