
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

typedef struct {
    ngx_uint_t  entries;
} ngx_io_uring_conf_t;


static ngx_int_t ngx_io_uring_init(ngx_cycle_t *cycle, ngx_msec_t timer);
static void ngx_io_uring_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_io_uring_add_event(ngx_event_t *ev,
                                        ngx_int_t event,
                                        ngx_uint_t flags);
static ngx_int_t ngx_io_uring_add_event_with_iovec(ngx_event_t *ev,
                                        ngx_int_t event,
                                        struct iovec *iov,
                                        ngx_int_t count);
static ngx_int_t ngx_io_uring_add_event_with_buf(ngx_event_t *ev,
                                        ngx_int_t event,
                                        u_char *buf,
                                        size_t size);
static ngx_int_t ngx_io_uring_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_io_uring_add_connection(ngx_connection_t *c);
static ngx_int_t ngx_io_uring_del_connection(ngx_connection_t *c,
    ngx_uint_t flags);
static ngx_int_t ngx_io_uring_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags);

static void *ngx_io_uring_create_conf(ngx_cycle_t *cycle);
static char *ngx_io_uring_init_conf(ngx_cycle_t *cycle, void *conf);

static struct io_uring_cqe  **cqes;
static ngx_uint_t           nevents;

struct io_uring             ngx_ring;

static ngx_str_t      io_uring_name = ngx_string("io_uring");

static ngx_command_t  ngx_io_uring_commands[] = {

    { ngx_string("io_uring_entries"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_io_uring_conf_t, entries),
      NULL },

      ngx_null_command
};

static ngx_event_module_t  ngx_io_uring_module_ctx = {
    &io_uring_name,
    ngx_io_uring_create_conf,               /* create configuration */
    ngx_io_uring_init_conf,                 /* init configuration */

    {
        ngx_io_uring_add_event,             /* add an event */
        ngx_io_uring_add_event_with_iovec,
        ngx_io_uring_add_event_with_buf,
        ngx_io_uring_del_event,             /* delete an event */
        ngx_io_uring_add_event,             /* enable an event */
        ngx_io_uring_del_event,             /* disable an event */
        ngx_io_uring_add_connection,        /* add an connection */
        ngx_io_uring_del_connection,        /* delete an connection */
        NULL,                               /* trigger a notify */
        ngx_io_uring_process_events,        /* process the events */
        ngx_io_uring_init,                  /* init the events */
        ngx_io_uring_done,                  /* done the events */
    }
};

ngx_module_t  ngx_io_uring_module = {
    NGX_MODULE_V1,
    &ngx_io_uring_module_ctx,            /* module context */
    ngx_io_uring_commands,               /* module directives */
    NGX_EVENT_MODULE,                    /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_io_uring_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    ngx_io_uring_conf_t  *urcf;

    urcf = ngx_event_get_conf(cycle->conf_ctx, ngx_io_uring_module);

    if (ngx_ring.ring_fd == 0) {
        if (io_uring_queue_init(urcf->entries, &ngx_ring, 0) < 0) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "io_uring_queue_init() failed");
            return NGX_ERROR;
        }
    }

    if (nevents < urcf->entries / 2) {
        if (cqes) {
            ngx_free(cqes);
        }

        cqes = ngx_alloc(sizeof(struct io_uring_cqe *) * urcf->entries / 2,
                               cycle->log);
        if (cqes == NULL) {
            return NGX_ERROR;
        }
    }

    nevents = urcf->entries / 2;

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_io_uring_module_ctx.actions;

    ngx_event_flags = NGX_USE_CLEAR_EVENT
                      | NGX_USE_GREEDY_EVENT
                      | NGX_USE_EPOLL_EVENT
                      | NGX_USE_IO_URING_EVENT;

    return NGX_OK;
}

static void
ngx_io_uring_done(ngx_cycle_t *cycle)
{
    io_uring_queue_exit(&ngx_ring);
    ngx_ring.ring_fd = 0;
    ngx_free(cqes);
}

static void
io_uring_add_poll(struct io_uring *ring, int fd,
                  int event, void *data)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

    /* TODO: !sqe ? */
    if (!sqe) ngx_abort();
    io_uring_prep_poll_add(sqe, fd, event);
    io_uring_sqe_set_data(sqe, data);
}

static void
io_uring_remove_poll(struct io_uring *ring, void *data)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

    /* TODO: !sqe ? */
    if (!sqe) ngx_abort();
    io_uring_prep_poll_remove(sqe, data);
    io_uring_sqe_set_data(sqe, NULL);
}

static void
io_uring_add_recv(struct io_uring *ring, int fd,
                   u_char *buf,
                   size_t size, void *data)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

    /* TODO: !sqe ? */
    if (!sqe) ngx_abort();
    io_uring_prep_recv(sqe, fd, buf, size, 0);
    io_uring_sqe_set_data(sqe, data);
}

static void
io_uring_add_send(struct io_uring *ring, int fd,
                  u_char *buf,
                  size_t size, void *data)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

    /* TODO: !sqe ? */
    if (!sqe) ngx_abort();
    io_uring_prep_send(sqe, fd, buf, size, 0);
    io_uring_sqe_set_data(sqe, data);
}

static void
io_uring_add_readv(struct io_uring *ring, int fd,
                   struct iovec *iov,
                   ngx_int_t count, void *data)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

    /* TODO: !sqe ? */
    if (!sqe) ngx_abort();
    io_uring_prep_readv(sqe, fd, iov, count, 0);
    io_uring_sqe_set_data(sqe, data);
}

static void
io_uring_add_writev(struct io_uring *ring, int fd,
                    struct iovec *iov,
                    ngx_int_t count, void *data)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

    /* TODO: !sqe ? */
    if (!sqe) ngx_abort();
    io_uring_prep_writev(sqe, fd, iov, count, 0);
    io_uring_sqe_set_data(sqe, data);
}

static ngx_int_t ngx_io_uring_add_event_with_buf(ngx_event_t *ev,
                                        ngx_int_t event,
                                        u_char *buf,
                                        size_t size)
{
    ngx_connection_t *c = ev->data;

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "io_uring add event with buf: fd:%d ev:%08XD, data:%p, size %uz",
                   c->fd, event, (void *) ((uintptr_t) c), size);

    if (event == NGX_READ_EVENT) {
        io_uring_add_recv(&ngx_ring, c->fd, buf, size,
                           (void *) ((uintptr_t) c | ev->instance | 0x6));
    } else {
        io_uring_add_send(&ngx_ring, c->fd, buf, size,
                           (void *) ((uintptr_t) c | ev->instance | 0x2));
    }

    ev->active = 1;
    ev->complete = 0;

    return NGX_OK;

}

static ngx_int_t ngx_io_uring_add_event_with_iovec(ngx_event_t *ev,
                                        ngx_int_t event,
                                        struct iovec *iov,
                                        ngx_int_t count)
{
    ngx_connection_t *c = ev->data;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "io_uring add event with iovec: fd:%d ev:%08XD, data:%p",
                   c->fd, event, (void *) ((uintptr_t) c));

    if (event == NGX_READ_EVENT) {
        io_uring_add_readv(&ngx_ring, c->fd, iov, count,
                           (void *) ((uintptr_t) c | ev->instance | 0x6));
    } else {
        io_uring_add_writev(&ngx_ring, c->fd, iov, count,
                           (void *) ((uintptr_t) c | ev->instance | 0x2));
    }

    ev->active = 1;
    ev->complete = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_io_uring_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    ngx_connection_t *c = ev->data;

    if (event == NGX_READ_EVENT) {
#if (NGX_READ_EVENT != EPOLLIN|EPOLLRDHUP)
        event = EPOLLIN|EPOLLRDHUP;
#endif
    } else {
#if (NGX_WRITE_EVENT != EPOLLOUT)
        event = EPOLLOUT;
#endif
    }

#if (NGX_HAVE_EPOLLEXCLUSIVE && NGX_HAVE_EPOLLRDHUP)
    if (flags & NGX_EXCLUSIVE_EVENT) {
        event &= ~EPOLLRDHUP;
    }
#endif

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "io_uring add event: fd:%d ev:%08XD, data:%p",
                   c->fd, event, (void *) ((uintptr_t) c | ev->instance));

    io_uring_add_poll(&ngx_ring, c->fd, event | (uint32_t) flags,
                      (void *) ((uintptr_t) c | ev->instance));
    ev->active = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_io_uring_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    ngx_connection_t *c = ev->data;

    if (flags & NGX_CLOSE_EVENT) {
        ev->active = 0;
        return NGX_OK;
    }

    io_uring_remove_poll(&ngx_ring, (void *) ((uintptr_t) c | ev->instance));

    ev->active = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_io_uring_add_connection(ngx_connection_t *c)
{
    ngx_int_t event = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "io_uring add connection: fd:%d ev:%08XD", c->fd, event);

    io_uring_add_poll(&ngx_ring, c->fd, event,
                      (void *) ((uintptr_t) c | c->read->instance));
    c->read->active = 1;
    c->write->active = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_io_uring_del_connection(ngx_connection_t *c, ngx_uint_t flags)
{
    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        c->read->active = 0;
        c->write->active = 0;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll del connection: fd:%d", c->fd);

    io_uring_remove_poll(&ngx_ring, (void *) ((uintptr_t) c | c->read->instance));

    c->read->active = 0;
    c->write->active = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_io_uring_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
{
    uint32_t           cqe_count, revents;
    ngx_int_t          instance, i, rw;
    ngx_uint_t         level;
    ngx_err_t          err = NGX_OK;
    ngx_event_t       *rev, *wev;
    ngx_queue_t       *queue;
    ngx_connection_t  *c;
    void *data;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "io_uring timer: %M", timer);

    if (io_uring_submit_and_wait(&ngx_ring, 1) < 0)
        err = ngx_errno;

    if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
        ngx_time_update();
    }

    if (err && err != NGX_EBUSY) {
        if (err == NGX_EINTR) {

            if (ngx_event_timer_alarm) {
                ngx_event_timer_alarm = 0;
                return NGX_OK;
            }

            level = NGX_LOG_INFO;

        } else {
            level = NGX_LOG_ALERT;
        }

        ngx_log_error(level, cycle->log, err, "io_uring_submit_and_wait() failed");
        return NGX_ERROR;
    }

    cqe_count = io_uring_peek_batch_cqe(&ngx_ring, cqes, nevents);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "cqe count: %d", cqe_count);

    for (i = 0; i < cqe_count; i++) {
        struct io_uring_cqe *cqe = cqes[i];

        data = io_uring_cqe_get_data(cqe);
        instance = (uintptr_t) data & 1;
        rw = (uintptr_t) data & 0x2;
        c = (ngx_connection_t *) ((uintptr_t) data & (uintptr_t) ~0x7);

        rev = c->read;

        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "io_uring: stale event fd:%d d:%p instance:%d rev_instance:%d",
			   c, c->fd, instance, rev->instance);
            io_uring_cqe_seen(&ngx_ring, cqe);
            continue;
        }

        ngx_log_debug5(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "io_uring_peek_cqe: fd:%d res:%d d:%p listening:%p active:%d",
                       c->fd, cqe->res, data, c->listening, rev->active);

        if (!rw) { /* poll_add request */
            revents = cqe->res;
            io_uring_cqe_seen(&ngx_ring, cqe);

            if (cqe->res < 0) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, revents, "poll request failed");
                continue;
            }
            if (revents & (EPOLLERR|EPOLLHUP)) {
                ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "io_uring_peek_cqe error on fd:%d ev:%04XD",
                               c->fd, revents);

                /*
                 * if the error events were returned, add EPOLLIN and EPOLLOUT
                 * to handle the events at least in one active handler
                 */

                revents |= EPOLLIN|EPOLLOUT;
            }

            if ((revents & EPOLLIN) && rev->active) {
                rev->ready = 1;
                rev->available = -1;
                rev->active = 0;

                if (flags & NGX_POST_EVENTS) {
                    queue = rev->accept ? &ngx_posted_accept_events
                                        : &ngx_posted_events;

                    ngx_post_event(rev, queue);

                } else {
                   rev->handler(rev);
                }
            }

            wev = c->write;

            if ((revents & EPOLLOUT) && wev->active) {

                if (c->fd == -1 || wev->instance != instance) {

                    /*
                     * the stale event from a file descriptor
                     * that was just closed in this iteration
                     */

                    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                                   "epoll: stale event %p", c);
                    continue;
                }

                wev->ready = 1;
                wev->active = 0;
#if (NGX_THREADS)
                wev->complete = 1;
#endif

                if (flags & NGX_POST_EVENTS) {
                    ngx_post_event(wev, &ngx_posted_events);

                } else {
                    wev->handler(wev);
                }
            }
	    continue;
        }

	/* readv/writev request */
	if (((uintptr_t) data) & 0x4) {
            if (!rev->active) {
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "readv: not active %p", c);

                io_uring_cqe_seen(&ngx_ring, cqe);
                continue;
	    }
            rev->nbytes = cqe->res;
            rev->available = -1;
            rev->active = 0;
            rev->complete = 1;
            io_uring_cqe_seen(&ngx_ring, cqe);

            ngx_log_debug5(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "io_uring_read_ready: fd:%d d:%p connection:%p active:%d nbytes:%uz",
                           c->fd, data, c, rev->active, rev->nbytes);

            if (flags & NGX_POST_EVENTS) {
                ngx_post_event(rev, &ngx_posted_events);
            } else {
                rev->handler(rev);
            }
	} else {
            wev = c->write;
            if (!wev->active) {
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "writev: not active %p", c);

                io_uring_cqe_seen(&ngx_ring, cqe);
                continue;
            }

            if (c->fd == -1 || wev->instance != instance) {
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "writev: stale event %p", c);
                io_uring_cqe_seen(&ngx_ring, cqe);
                continue;
	    }
	    wev->nbytes = cqe->res;
            wev->complete = 1;
            wev->active = 0;
            io_uring_cqe_seen(&ngx_ring, cqe);

            ngx_log_debug5(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "io_uring_write_ready: fd:%d d:%p connection:%p active:%d nbytes:%uz",
                           c->fd, data, c, wev->active, wev->nbytes);

            if (flags & NGX_POST_EVENTS) {
                ngx_post_event(wev, &ngx_posted_events);
            } else {
                wev->handler(wev);
            }
        }
    }

    return NGX_OK;
}

static void *
ngx_io_uring_create_conf(ngx_cycle_t *cycle)
{
    ngx_io_uring_conf_t  *urcf;

    urcf = ngx_palloc(cycle->pool, sizeof(ngx_io_uring_conf_t));
    if (urcf == NULL) {
        return NULL;
    }

    urcf->entries = NGX_CONF_UNSET;

    return urcf;
}

static char *
ngx_io_uring_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_io_uring_conf_t *urcf = conf;

    ngx_conf_init_uint_value(urcf->entries, 512);

    return NGX_CONF_OK;
}
