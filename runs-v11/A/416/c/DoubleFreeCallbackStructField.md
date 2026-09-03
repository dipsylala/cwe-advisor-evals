## Verdict

Use-after-free confirmed. The queued `CallbackContext` holds a pointer to a `Connection` that is freed by `handle_connection_reset()` before `process_work_queue()` dereferences it at line 84.

## Source

Ownership violation between `enqueue_completion()` and `handle_connection_reset()`:

1. `enqueue_completion()` (line 55–64) captures a pointer to the caller's connection in a `CallbackContext` and queues it. The comment at line 61 notes this is "not the owner."
2. `handle_connection_reset()` (line 72–76) frees the connection via `connection_release(conn)`, which sets the caller's pointer to NULL.
3. `process_work_queue()` (line 79–87) dequeues the context and dereferences `ctx->conn->fd` at line 84, but the connection has already been freed.

The root cause: the queued context holds a dangling pointer because ownership was never transferred to it, and `connection_release()` only nulls the caller's own pointer, not the copy held by the queued context.

## Fix

Transfer ownership of the connection to the `CallbackContext` when it is queued, and release it when the context is processed:

```c
/* Enqueue: transfer ownership to the context. */
void enqueue_completion(struct Connection *conn, int request_id)
{
    struct CallbackContext *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
        connection_release(&conn);  /* release on malloc failure */
        return;
    }
    ctx->conn = conn;          /* ownership transferred; caller must not use conn after this */
    ctx->request_id = request_id;
    work_queue_push(ctx);
}

/* Dequeue and release: the context owns the connection. */
void process_work_queue(void)
{
    struct CallbackContext *ctx;
    while ((ctx = work_queue_pop()) != NULL) {
        printf("completing request %d for fd %d\n", ctx->request_id, ctx->conn->fd);
        connection_release(&ctx->conn);  /* release owned connection */
        free(ctx);
    }
}

/* Caller must not invoke handle_connection_reset() on a connection
 * that has been queued. Alternatively, drain the queue first. */
```

## Explanation

The vulnerability arises because a queued callback holds a non-owning pointer to shared state. Once that state is freed by the owner, the deferred callback dereferences a freed pointer.

The fix establishes clear ownership: when a connection is queued, the context assumes full responsibility for it. The caller relinquishes the pointer and must not free it. The context releases the connection only when it is processed.

This pattern prevents dangling-pointer reuse by ensuring the object's lifetime extends at least until the last reference to it is consumed. The queue's queuing operation becomes a transfer operation, and the dequeue operation becomes a release operation.
