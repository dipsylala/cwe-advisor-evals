## Verdict
Confirmed use-after-free vulnerability at line 33.

## Source
The vulnerability occurs because:
1. Line 29 extracts a raw pointer from the `unique_ptr<Session>`
2. Line 31 captures only the raw pointer in the lambda
3. Line 36 calls `session.reset()`, which deletes the Session object
4. When the lambda executes later, line 33 dereferences the dangling raw pointer

## Fix
Transfer ownership of the `unique_ptr` into the lambda's capture list instead of capturing only the raw pointer. This extends the Session's lifetime until the callback executes:

```cpp
void scheduleSessionTouch(std::unique_ptr<Session> session, CallbackQueue &queue)
{
    queue.enqueue([session = std::move(session)]() {
        session->touch();
    });
}
```

The lambda now captures `session` by move-constructing a new `unique_ptr` in its capture list. The Session object remains alive as long as the lambda exists, and is destroyed when the lambda is destroyed (after it executes).

## Explanation
CWE-416 (Use After Free) occurs when code accesses memory that has already been freed. In this case, capturing only the raw pointer severs the connection between the callback and the object's lifetime. By capturing the `unique_ptr` itself (via move), the lambda takes ownership and ensures the Session is not destroyed until after the callback runs. This is the idiomatic C++ pattern for passing ownership into a callback or asynchronous operation.
