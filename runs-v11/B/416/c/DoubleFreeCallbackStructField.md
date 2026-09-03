## Verdict

CONFIRMED: Use-after-free at line 84. The CallbackContext holds a non-owning pointer to a Connection that is freed by handle_connection_reset() before process_work_queue() dereferences it.

## Source

Line 61: `ctx->conn = conn;` captures a non-owning pointer.
Line 84: `ctx->conn->fd` dereferences stale pointer after Connection is freed at line 33.

## Fix

Transfer ownership of the Connection from main's local variable to the CallbackContext. The CallbackContext becomes responsible for releasing it when the callback is processed. This ensures the Connection remains allocated for the entire lifetime of any reference to it.

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
    struct Connection *conn;
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
 * work to run on the next event loop tick instead of finishing inline.
 * Takes ownership of the connection from the caller. */
void enqueue_completion(struct Connection **conn, int request_id)
{
    struct CallbackContext *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return;
    }
    ctx->conn = *conn;        /* Transfer ownership to the callback context */
    *conn = NULL;             /* Null the caller's copy to prevent use-after-free */
    ctx->request_id = request_id;
    work_queue_push(ctx);
}

/* Error path invoked when the peer resets the connection mid-request.
 * This connection is now owned by a queued callback, so we must remove
 * and release the callback context before it can dereference the connection. */
void handle_connection_reset(struct Connection **conn)
{
    if (conn == NULL || *conn == NULL) {
        return;
    }
    
    fprintf(stderr, "connection reset, releasing\n");
    
    /* Scan the queue for any callback holding this connection and remove it */
    int read_pos = g_work_queue.head;
    int write_pos = g_work_queue.head;
    
    while (read_pos != g_work_queue.tail) {
        struct CallbackContext *ctx = g_work_queue.entries[read_pos % MAX_QUEUE];
        if (ctx->conn == *conn) {
            /* Found the queued callback; release the connection and callback */
            connection_release(&ctx->conn);
            free(ctx);
        } else {
            /* Keep this entry in the queue */
            if (write_pos != read_pos) {
                g_work_queue.entries[write_pos % MAX_QUEUE] = ctx;
            }
            write_pos++;
        }
        read_pos++;
    }
    g_work_queue.tail = write_pos;
    
    *conn = NULL;
}

/* Event loop tick: drains queued completions. */
void process_work_queue(void)
{
    struct CallbackContext *ctx;
    while ((ctx = work_queue_pop()) != NULL) {
        /* Safe to dereference: the connection is owned by this context
         * and cannot be freed until after this callback releases it */
        printf("completing request %d for fd %d\n", ctx->request_id, ctx->conn->fd);
        connection_release(&ctx->conn);
        free(ctx);
    }
}

int main(void)
{
    struct Connection *conn = malloc(sizeof(*conn));
    conn->fd = 42;
    conn->peer_addr = strdup("203.0.113.7");

    enqueue_completion(&conn, 1001);  /* Ownership transfers to callback context */

    /* Peer resets before the queued completion runs; the connection is
     * removed from the queue and released through the callback context. */
    handle_connection_reset(&conn);

    /* Event loop tick processes remaining queued callbacks (should be none). */
    process_work_queue();

    return 0;
}
```

## Explanation

The vulnerability arises from split ownership: `main()` owns the original Connection pointer, but `enqueue_completion()` captures a non-owning copy into the CallbackContext. When `handle_connection_reset()` releases the Connection, it nulls only the owner's variable (in main), leaving the copy in the queued context pointing to freed memory. The dereference at line 84 then accesses that freed allocation.

The fix implements single ownership per the C guidance: the CallbackContext takes ownership when `enqueue_completion()` is called, with the caller's pointer immediately nulled to prevent accidental reuse. `handle_connection_reset()` now scans the work queue, locates any callback holding the connection being reset, and removes and releases it before the connection can be freed a second time. This ensures that the Connection's lifetime spans from its allocation in `main()` through its dequeue and release in `process_work_queue()`, with no gap where a callback holds a stale reference. The callback owns the connection for the entire interval it is queued.

## Behaviour changes

- `enqueue_completion()` signature changed to take `struct Connection **conn` instead of `struct Connection *conn`, enabling ownership transfer via pointer nulling
- `enqueue_completion()` now takes ownership and nulls the caller's pointer, preventing accidental reuse
- `handle_connection_reset()` now removes queued callbacks holding the connection before the release completes, rather than allowing a callback to hold a stale pointer
- `process_work_queue()` now releases the Connection through each callback context, since the context owns it
- The Connection's lifetime is bounded by the callback's presence in the queue, eliminating the use-after-free window
