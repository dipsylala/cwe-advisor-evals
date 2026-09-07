## Verdict

exploitable

## Source

Connection struct allocated at line 91 in `main()`, pointer passed to `enqueue_completion()` at line 95.

## Fix

### File: DoubleFreeCallbackStructField.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_QUEUE 16

struct Connection {
    int fd;
    char *peer_addr;
};

struct CallbackContext {
    int fd;           /* value copied at enqueue time, not a pointer */
    int request_id;
};

struct WorkQueue {
    struct CallbackContext *entries[MAX_QUEUE];
    int head;
    int tail;
};

static struct WorkQueue g_work_queue = { .head = 0, .tail = 0 };

/* Single-owner release: takes the address of the caller's own variable
 * and nulls it once the connection is torn down. */
static void connection_release(struct Connection **conn)
{
    if (conn == NULL || *conn == NULL) {
        return;
    }
    free((*conn)->peer_addr);
    free(*conn);
    *conn = NULL;
}

static void work_queue_push(struct CallbackContext *ctx)
{
    g_work_queue.entries[g_work_queue.tail % MAX_QUEUE] = ctx;
    g_work_queue.tail++;
}

static struct CallbackContext *work_queue_pop(void)
{
    if (g_work_queue.head == g_work_queue.tail) {
        return NULL;
    }
    struct CallbackContext *ctx = g_work_queue.entries[g_work_queue.head % MAX_QUEUE];
    g_work_queue.head++;
    return ctx;
}

/* Called when a request finishes reading its body; queues the completion
 * work to run on the next event loop tick instead of finishing inline. */
void enqueue_completion(struct Connection *conn, int request_id)
{
    struct CallbackContext *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return;
    }
    ctx->fd = conn->fd;            /* copy the value, not the pointer */
    ctx->request_id = request_id;
    work_queue_push(ctx);
}

/* Error path invoked when the peer resets the connection mid-request.
 * This function holds the connection's single owning variable, so
 * releasing here is correct - and any CallbackContext already queued
 * for this connection carries a copy of the fd value captured at enqueue
 * time, not a stale pointer. */
void handle_connection_reset(struct Connection **conn)
{
    fprintf(stderr, "connection reset, releasing\n");
    connection_release(conn);   /* frees *conn and sets it NULL */
}

/* Event loop tick: drains queued completions. */
void process_work_queue(void)
{
    struct CallbackContext *ctx;
    while ((ctx = work_queue_pop()) != NULL) {
        printf("completing request %d for fd %d\n", ctx->request_id, ctx->fd);
        free(ctx);
    }
}

int main(void)
{
    struct Connection *conn = malloc(sizeof(*conn));
    conn->fd = 42;
    conn->peer_addr = strdup("203.0.113.7");

    enqueue_completion(conn, 1001);

    /* Peer resets before the queued completion runs; the connection is
     * released through its proper owner-nulling path. */
    handle_connection_reset(&conn);

    /* Event loop tick processes the queued callback, using the fd value
     * that was captured at enqueue time - no use-after-free. */
    process_work_queue();

    return 0;
}
```

## Explanation

The use-after-free occurred because `CallbackContext` stored a pointer to the `Connection` struct without taking ownership of it. When the connection was released via `handle_connection_reset()`, the queued callback still held a stale pointer. Later, `process_work_queue()` dereferenced that stale pointer at line 84.

The fix decouples the callback's data from the connection's lifetime by extracting and storing only the value needed (`fd`) at enqueue time, rather than storing a pointer that can become stale. The `CallbackContext` struct now contains `int fd` instead of `struct Connection *conn`, and `enqueue_completion()` copies the fd value directly. The sink at line 84 is updated to use `ctx->fd` instead of `ctx->conn->fd`. Since the callback now carries its own copy of the required data, it no longer depends on the connection remaining allocated.

## Behaviour changes

The only change to runtime behaviour is that `enqueue_completion()` now extracts and stores the fd value from the connection at the time of queueing, rather than storing a stale pointer. This is a semantic improvement: the callback's data is now decoupled from the connection's lifetime, eliminating the dependency that created the use-after-free vulnerability.

The `printf()` call at line 84 still prints the same output (request_id and fd), so the observable behaviour of the program is unchanged except that it no longer accesses freed memory.

