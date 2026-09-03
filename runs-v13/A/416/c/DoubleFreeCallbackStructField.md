## Verdict

Use-after-free confirmed. The `CallbackContext` captures a non-owning pointer to `Connection` at line 61. When `handle_connection_reset()` frees the connection at line 75, the queued callback still holds the stale pointer. The deference at line 84 accesses freed memory.

## Source

The vulnerability spans the call chain:
- Line 61: `ctx->conn = conn` captures non-owning pointer in queued context
- Line 75: `connection_release(conn)` frees the Connection struct and nulls the caller's variable, but does not invalidate the queued reference
- Line 84: `ctx->conn->fd` dereferences the freed pointer

## Fix

Copy the value the callback needs directly into `CallbackContext` instead of holding a pointer to the mutable `Connection`:

```c
struct CallbackContext {
    int fd;                    /* Copy of the file descriptor, not a pointer */
    int request_id;
};

void enqueue_completion(struct Connection *conn, int request_id)
{
    struct CallbackContext *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return;
    }
    ctx->fd = conn->fd;        /* Copy the value */
    ctx->request_id = request_id;
    work_queue_push(ctx);
}

void process_work_queue(void)
{
    struct CallbackContext *ctx;
    while ((ctx = work_queue_pop()) != NULL) {
        printf("completing request %d for fd %d\n", ctx->request_id, ctx->fd);
        free(ctx);
    }
}
```

## Explanation

The root cause is that `CallbackContext` holds a non-owning reference to `Connection`. When the connection is released through its proper owner variable, any queued callbacks that captured a pointer become stale. The fix decouples the callback from the Connection lifetime by copying only the data the callback needs (`fd` and `request_id`) directly into the context structure. This eliminates the dependency on the Connection object and ensures the callback can execute safely regardless of when the connection is freed. The callback now owns all its required state.
