## Verdict

Exploitable. The callback context captures a pointer to the Connection struct. When the connection is released via `handle_connection_reset()`, the original pointer in `main()` is nulled, but the copy stored in the queued CallbackContext remains a stale reference. When `process_work_queue()` later dereferences `ctx->conn->fd` at line 84, it reads from freed memory.

## Source

Line 61: `ctx->conn = conn;` captures a copy of the Connection pointer into the callback context. The calling code then immediately releases the connection through its owning variable, leaving the callback's copy dangling.

## Sink

Line 84: `ctx->conn->fd` dereferences the stale pointer captured earlier.

## Fix

### Vulnerable code:

```c
struct CallbackContext {
    struct Connection *conn;
    int request_id;
};

void enqueue_completion(struct Connection *conn, int request_id)
{
    struct CallbackContext *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return;
    }
    ctx->conn = conn;          /* copy of the pointer, not the owner */
    ctx->request_id = request_id;
    work_queue_push(ctx);
}

void process_work_queue(void)
{
    struct CallbackContext *ctx;
    while ((ctx = work_queue_pop()) != NULL) {
        // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
        printf("completing request %d for fd %d\n", ctx->request_id, ctx->conn->fd);
        free(ctx);
    }
}
```

### Fixed code:

```c
struct CallbackContext {
    int conn_fd;
    int request_id;
};

void enqueue_completion(struct Connection *conn, int request_id)
{
    struct CallbackContext *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return;
    }
    ctx->conn_fd = conn->fd;     /* capture the fd value, not the pointer */
    ctx->request_id = request_id;
    work_queue_push(ctx);
}

void process_work_queue(void)
{
    struct CallbackContext *ctx;
    while ((ctx = work_queue_pop()) != NULL) {
        printf("completing request %d for fd %d\n", ctx->request_id, ctx->conn_fd);
        free(ctx);
    }
}
```

## Explanation

The vulnerability arises because the callback context captures a raw pointer to the Connection struct, which is released asynchronously before the callback runs. Nulling only affects the owning variable in `main()`, not the copy held in the queued context. The fix replaces the dangling pointer with a capture of the concrete data the callback actually uses—the file descriptor number. This eliminates the stale pointer dereference entirely: the callback no longer needs to traverse through the freed memory to extract the fd. The same pattern applies to any data the callback needs: capture the value at enqueue time, not a pointer to a structure that will be freed.

## Behaviour changes

- `CallbackContext` now stores `int conn_fd` instead of `struct Connection *conn`.
- `enqueue_completion()` assigns `conn->fd` directly instead of storing the pointer.
- `process_work_queue()` uses `ctx->conn_fd` instead of dereferencing `ctx->conn->fd`.
- The callback no longer holds any reference to the Connection struct, so the timing of its release is decoupled from the callback's execution.
- No change to the release semantics or error handling: the sink's contract (reading an integer and printing it) is preserved.
