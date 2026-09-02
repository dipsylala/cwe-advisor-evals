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
 * work to run on the next event loop tick instead of finishing inline. */
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

/* Error path invoked when the peer resets the connection mid-request.
 * This function holds the connection's single owning variable, so
 * releasing here is correct - but any CallbackContext already queued
 * for this connection still holds the now-stale address, since nulling
 * only reaches the caller's own "conn" variable, not the copy captured
 * inside the queued context. */
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
        // SAST FINDING: CWE-416 (Use After Free) reported here. Sink is the next statement.
        printf("completing request %d for fd %d\n", ctx->request_id, ctx->conn->fd);
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

    /* Event loop tick processes the queued callback, dereferencing the
     * stale conn pointer captured earlier. */
    process_work_queue();

    return 0;
}
