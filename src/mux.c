/**
 * Copyright (c) 2015 Parrot S.A.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of 'Parrot S.A' nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL 'Parrot S.A' BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @file mux.c
 *
 */

#include "mux_priv.h"

/** Rx buffer size when fd is managed internally */
#define MUX_RX_BUFFER_SIZE		16384

/* Magic bytes */
#define MUX_PROT_HEADER_MAGIC_0		'M'	/**< Magic byte 0 */
#define MUX_PROT_HEADER_MAGIC_1		'U'	/**< Magic byte 1 */
#define MUX_PROT_HEADER_MAGIC_2		'X'	/**< Magic byte 2 */
#define MUX_PROT_HEADER_MAGIC_3		'!'	/**< Magic byte 3 */

/** Size of protocol header */
#define MUX_PROT_HEADER_SIZE		12

/**
 * Determine if a read/write error in non-blocking could not be completed.
 * POSIX.1-2001 allows either error to be returned for this case, and
 * does not require these constants to have the same value, so a portable
 * application should check for both possibilities. */
#define MUX_WOULD_BLOCK(_err) \
	( \
		(_err) == EAGAIN || \
		(_err) == EWOULDBLOCK \
	)

/** Protocol header */
struct mux_prot_header {
	uint8_t		magic[4];	/**< Magic */
	uint32_t	chanid;		/**< Channel id */
	uint32_t	size;		/**< Size of frame (with header) */
};

/** Protocol decoding state */
enum mux_prot_state {
	MUX_PROT_STATE_IDLE = 0,	/**< Idle */
	MUX_PROT_STATE_HEADER_MAGIC_0,	/**< Waiting for magic 0 */
	MUX_PROT_STATE_HEADER_MAGIC_1,	/**< Waiting for magic 1 */
	MUX_PROT_STATE_HEADER_MAGIC_2,	/**< Waiting for magic 2 */
	MUX_PROT_STATE_HEADER_MAGIC_3,	/**< Waiting for magic 3 */
	MUX_PROT_STATE_HEADER,		/**< Reading header */
	MUX_PROT_STATE_PAYLOAD,		/**< Reading payload */
};

/** Resolution Request. */
struct mux_resolve_request {
	/** Proxy identifier. */
	uint32_t proxy_id;
	/** Proxy protocol. */
	struct mux_ip_proxy_protocol protocol;
	/** Host name. */
	char *hostname;
	/** Host port. */
	uint16_t hostport;
	/** Node. */
	struct list_node node;
};

/** Mux Context. */
struct mux_ctx {
	/** Reference count */
	uint32_t		refcount;

	/** Event loop */
	struct pomp_loop	*loop;

	/** 0 if loop is internal, 1 if external */
	int			extloop;

	/** Loop synchronization */
	struct {
		pthread_t	owner;		/**< Current owner */
		pthread_mutex_t	mutex;		/**< Lock */
		pthread_cond_t	cond_count;	/**< Count condition */
		pthread_cond_t	cond_waiters;	/**< Waiter condition */
		uint32_t	count;		/**< Acquire recursion */
		uint32_t	waiters;	/**< Waiter count */
	} loop_sync;

	/** File descriptor to use for rx/tx operations */
	int			fd;

	/** EOF detection flag */
	int			eof;

	/** EOF notified flag */
	int			eof_notified;

	/** Misc flags */
	uint32_t		flags;

	/** Callbacks */
	struct mux_ops		ops;

	/** Synchronization lock */
	pthread_mutex_t		mutex;

	/** To stop all operations */
	int			stopped;

	/** Decoding state */
	enum mux_prot_state	state;

	/** Buffer to read message header */
	uint8_t			headerbuf[MUX_PROT_HEADER_SIZE];

	/** Current frame header */
	struct mux_prot_header	header;

	/** Current offset in header decoding */
	size_t			offheader;

	/** Current offset in payload decoding */
	size_t			offpayload;

	/** Length of payload to decode */
	size_t			lenpayload;

	/** Buffer for current payload */
	struct pomp_buffer	*payloadbuf;

	/** Channel of current frame NULL if not open, data will be trashed */
	struct mux_channel	*channel;

	/** List of opened channels */
	struct mux_channel	*channels;

	/** Pending host address resolutions */
	struct list_node	pending_resolves;

	/** Last channel id not opened on which we recv data **/
	uint32_t		last_rcv_chanid_closed;

	/** Ip proxys */
	struct list_node	proxys;

	/** Last proxy identifier. */
	uint32_t		last_proxy_id;

	struct {
		pthread_t		thread;
		int			thread_created;
		struct pomp_evt		*evt;
		struct pomp_buffer	*buf;
		struct mux_queue	*queue;
	} rx;

	struct {
		pthread_t		thread;
		int			thread_created;
		struct pomp_buffer	*buf;
		size_t			off;
		struct mux_queue	*queue;
	} tx;

	/** Protocol version of the remote mux; '0' for unknown version. */
	uint32_t remote_version;
};

/**
 */
static ssize_t xread(int fd, void *ptr, size_t count)
{
	ssize_t readlen = 0;
	do {
		readlen = read(fd, ptr, count);
	} while (readlen < 0 && errno == EINTR);
	return readlen;
}

/**
 */
static ssize_t xwrite(int fd, const void *ptr, size_t count)
{
	ssize_t writelen = 0;
	do {
		writelen = write(fd, ptr, count);
	} while (writelen < 0 && errno == EINTR);
	return writelen;
}

/**
 * Check that the magic bytes of the frame header are valid.
 * @param ctx : mux context.
 * @param idx : index of magic byte to check.
 * @param val : expected value of magic byte.
 * @param state : next state if check is ok.
 */
static void check_magic(struct mux_ctx *ctx, int idx, int val,
		enum mux_prot_state state)
{
	if (ctx->headerbuf[idx] != val) {
		MUX_LOGW("Bad header magic %d : 0x%02x(0x%02x)",
			idx, ctx->headerbuf[idx], val);
		ctx->state = MUX_PROT_STATE_HEADER_MAGIC_0;
	} else {
		ctx->state = state;
	}
}

/**
 * Decode the header of the message.
 * @param ctx : mux context.
 *
 * @remarks in case of error during header decoding, the state is reseted.
 */
static void decode_header(struct mux_ctx *ctx)
{
	uint32_t d = 0;
	uint32_t chanid = 0;

	/* Decode header inside structure */
	memcpy(&ctx->header.magic[0], ctx->headerbuf, 4);
	memcpy(&d, &ctx->headerbuf[4], 4);
	ctx->header.chanid = chanid = MUX_LE32TOH(d);
	memcpy(&d, &ctx->headerbuf[8], 4);
	ctx->header.size = MUX_LE32TOH(d);

	ctx->offpayload = 0;
	ctx->state = MUX_PROT_STATE_PAYLOAD;

	/* Check header and setup payload decoding */
	if (ctx->header.size < MUX_PROT_HEADER_SIZE) {
		MUX_LOGW("Bad header size : %d", ctx->header.size);
		ctx->state = MUX_PROT_STATE_HEADER_MAGIC_0;
	} else {
		/* Search for channel */
		if (chanid != 0) {
			if (IS_SLAVE_ID(chanid)) {
				ctx->channel = mux_find_channel(
						ctx, GET_MASTER_ID(chanid));
			} else if (IS_MASTER_ID(chanid)) {
				ctx->channel = mux_find_channel(
						ctx, GET_SLAVE_ID(chanid));
			} else {
				ctx->channel = mux_find_channel(ctx, chanid);
			}
		}

		/* Allocate buffer for payload, still decode payload in case
		 * of error, it will simply be trashed */
		ctx->lenpayload = ctx->header.size - MUX_PROT_HEADER_SIZE;
		if (chanid == 0 || ctx->channel != NULL) {
			ctx->payloadbuf = pomp_buffer_new(ctx->lenpayload);
			if (ctx->payloadbuf == NULL)
				ctx->channel = NULL;
		} else if (ctx->last_rcv_chanid_closed == chanid) {
			MUX_LOGW("Channel 0x%08x not opened", chanid);
			ctx->last_rcv_chanid_closed = chanid;
		}
	}
}

/**
 * Copy data. Up to lensrc - *offsrc bytes will be written.
 * @param basedst : base address of destination.
 * @param offdst : offset of destination, updated after the copy.
 * @param lendst : total size of destination.
 * @param basesrc : base address of source.
 * @param offsrc : offset of source, updated after the copy.
 * @param lensrc : total size of source.
 */
static void copy(void *basedst, size_t *offdst, size_t lendst,
		const void *basesrc, size_t *offsrc, size_t lensrc)
{
	/* Compute destination and source */
	void *dst = ((uint8_t *)(basedst)) + *offdst;
	const void *src = ((const uint8_t *)(basesrc)) + *offsrc;

	/* Determine copy length */
	size_t lencpy = lensrc - *offsrc;
	if (lencpy > lendst - *offdst)
		lencpy = lendst - *offdst;
	if (lencpy == 0)
		return;

	/* Do the copy and update offsets */
	memcpy(dst, src, lencpy);
	*offdst += lencpy;
	*offsrc += lencpy;
}

/**
 * Process magic byte in header. Only one byte will be written.
 * @param ctx : mux context.
 * @param basesrc : base address of source.
 * @param offsrc : offset of source, updated after the copy.
 * @param lensrc : total size of source.
 */
static void process_header_magic(struct mux_ctx *ctx,
		const void *basesrc, size_t *offsrc, size_t lensrc)
{
	copy(ctx->headerbuf, &ctx->offheader, MUX_PROT_HEADER_SIZE,
			basesrc, offsrc, *offsrc + 1);
}

/**
 * Process header bytes. Up to lensrc - *offsrc bytes will be written.
 * @param ctx : mux context.
 * @param basesrc : base address of source.
 * @param offsrc : offset of source, updated after the copy.
 * @param lensrc : total size of source.
 */
static void process_header(struct mux_ctx *ctx,
		const void *basesrc, size_t *offsrc, size_t lensrc)
{
	copy(ctx->headerbuf, &ctx->offheader, MUX_PROT_HEADER_SIZE,
			basesrc, offsrc, lensrc);
}

/**
 * Process payload bytes. Up to lensrc - *offsrc bytes will be copied.
 * @param ctx : mux context.
 * @param basesrc : base address of source.
 * @param offsrc : offset of source, updated after the copy.
 * @param lensrc : total size of source.
 */
static void process_payload(struct mux_ctx *ctx,
		const void *basesrc, size_t *offsrc, size_t lensrc)
{
	int res = 0;
	const void *src = ((const uint8_t *)(basesrc)) + *offsrc;
	void *dst = NULL;
	size_t lencpy = 0;

	/* Determine copy length */
	lencpy = lensrc - *offsrc;
	if (lencpy > ctx->lenpayload - ctx->offpayload)
		lencpy = ctx->lenpayload - ctx->offpayload;
	if (lencpy == 0)
		return;

	/* Copy data */
	if (ctx->payloadbuf != NULL) {
		/* Get data from buffer */
		res = pomp_buffer_get_data(ctx->payloadbuf, &dst, NULL, NULL);
		if (res < 0) {
			MUX_LOG_ERR("pomp_buffer_get_data", -res);
		} else {
			memcpy((uint8_t *)dst + ctx->offpayload, src, lencpy);
			pomp_buffer_set_len(ctx->payloadbuf,
					ctx->offpayload + lencpy);
		}
	}
	ctx->offpayload += lencpy;
	*offsrc += lencpy;
}

/**
 */
static void reset_decode(struct mux_ctx *ctx)
{
	ctx->state = MUX_PROT_STATE_IDLE;
	memset(&ctx->headerbuf, 0, sizeof(ctx->headerbuf));
	memset(&ctx->header, 0, sizeof(ctx->header));
	ctx->offheader = 0;
	ctx->offpayload = 0;
	ctx->lenpayload = 0;
	if (ctx->payloadbuf != NULL) {
		pomp_buffer_unref(ctx->payloadbuf);
		ctx->payloadbuf = NULL;
	}
}

/**
 */
static void fill_header(struct mux_prot_header *header,
		uint32_t chanid, uint32_t len)
{
	/* Setup header */
	memset(header, 0, sizeof(*header));
	header->magic[0] = MUX_PROT_HEADER_MAGIC_0;
	header->magic[1] = MUX_PROT_HEADER_MAGIC_1;
	header->magic[2] = MUX_PROT_HEADER_MAGIC_2;
	header->magic[3] = MUX_PROT_HEADER_MAGIC_3;
	header->chanid = MUX_HTOLE32(chanid);
	header->size = MUX_HTOLE32(len + MUX_PROT_HEADER_SIZE);
}

/**
 */
static struct pomp_buffer *create_header_buf(struct mux_ctx *ctx,
		uint32_t chanid, struct pomp_buffer *buf)
{
	int res = 0;
	size_t len = 0;
	struct mux_prot_header *header = NULL;
	struct pomp_buffer *headerbuf = NULL;
	void *headerdata = NULL;

	/* Determine size of data */
	res = pomp_buffer_get_cdata(buf, NULL, &len, NULL);
	if (res < 0)
		goto error;

	/* Create buffer for header
	 * TODO: recycle old one if possible */
	headerbuf = pomp_buffer_new(sizeof(*header));
	if (headerbuf == NULL)
		goto error;
	res = pomp_buffer_get_data(headerbuf, &headerdata, NULL, NULL);
	if (res < 0)
		goto error;
	header = headerdata;

	/* Fill header */
	fill_header(header, chanid, len);

	/* Set length of buffer */
	res = pomp_buffer_set_len(headerbuf, sizeof(*header));
	if (res < 0)
		goto error;
	return headerbuf;

	/* Cleanup in case of error */
error:
	if (headerbuf != NULL)
		pomp_buffer_unref(headerbuf);
	return NULL;
}

/**
 * Notify that payload is complete.
 * @param ctx : mux context.
 */
static void notify_payload(struct mux_ctx *ctx)
{
	int res = 0;
	const struct mux_ctrl_msg *msg = NULL;
	const void *data = NULL;
	const void *payload;
	size_t len = 0;

	/* Get data from buffer */
	res = pomp_buffer_get_cdata(ctx->payloadbuf, &data, &len, NULL);
	if (res < 0) {
		MUX_LOG_ERR("pomp_buffer_get_cdata", -res);
		return;
	}

	if (ctx->header.chanid == 0 && len >= sizeof(*msg)) {
		/* Message received on control channel */
		msg = data;
		payload = (const uint8_t *)data + sizeof(*msg);
		len -= sizeof(*msg);
		if (len == 0)
			payload = NULL;
		mux_channel_recv_ctrl_msg(ctx, msg, payload, len);
	} else if (ctx->channel != NULL) {
		/* Data for regular channel */
		if (len > 0)
			mux_channel_put_buf(ctx->channel, ctx->payloadbuf);
	} else {
		MUX_LOGW("Data lost chanid=0x%08x", ctx->header.chanid);
	}

	/* Unref payload buffer, reset partially state */
	pomp_buffer_unref(ctx->payloadbuf);
	ctx->payloadbuf = NULL;
	ctx->channel = NULL;
}

/**
 * Read data from fd to rx buffer.
 * Can be called from event loop or rx thread.
 * @return 1 if data was read, 0 in case of error or EOF was detected.
 */
static int do_fd_read(struct mux_ctx *ctx)
{
	int res = 0;
	void *data = NULL;
	size_t capacity = 0;
	ssize_t readlen = 0;

	/* Get data from buffer or allocate new one */
	if (ctx->rx.buf != NULL) {
		res = pomp_buffer_get_data(
				ctx->rx.buf, &data, NULL, &capacity);
		if (res < 0) {
			/* Buffer is shared */
			pomp_buffer_unref(ctx->rx.buf);
			ctx->rx.buf = NULL;
		}
	}

	/* Allocate new buffer */
	if (ctx->rx.buf == NULL) {
		ctx->rx.buf = pomp_buffer_new_get_data(
				MUX_RX_BUFFER_SIZE, &data);
		if (ctx->rx.buf == NULL)
			return 0;
		capacity = MUX_RX_BUFFER_SIZE;
	}

	/* Read data */
	readlen = xread(ctx->fd, data, capacity);
	if (readlen > 0) {
		pomp_buffer_set_len(ctx->rx.buf, (uint32_t)readlen);
	} else if (readlen == 0) {
		ctx->eof = 1;
	} else if (!MUX_WOULD_BLOCK(errno)) {
		MUX_LOG_FD_ERR("read", ctx->fd, errno);
		ctx->eof = 1;
	}

	return readlen > 0;
}

/**
 * Write a buffer to fd with offset.
 * Can be called from event loop or tx thread.
 * @return 1 if buffer was fully written 0, if partial or error. In case of
 * error, EOF flag is set in context.
 */
static int do_fd_write_buf(struct mux_ctx *ctx,
		struct pomp_buffer *buf, size_t *off)
{
	const void *cdata = NULL;
	size_t len = 0;
	ssize_t writelen = 0;
	int res;

	/* Get data from buffer */
	res = pomp_buffer_get_cdata(buf, &cdata, &len, NULL);
	if (res < 0)
		return 0;

	/* Write data */
	writelen = xwrite(ctx->fd, (const uint8_t *)cdata + *off, len - *off);
	if (writelen < 0) {
		if (MUX_WOULD_BLOCK(errno))
			return 0;

		if (errno != EPIPE)
			MUX_LOG_FD_ERR("write", ctx->fd, errno);

		ctx->eof = 1;
		return 0;
	} else if ((size_t)writelen == len - *off) {
		/* Fully written */
		return 1;
	} else {
		/* Partial write, update offset */
		*off += (size_t)writelen;
		return 0;
	}
}

/**
 * Write data from tx queue to fd.
 * Can be called from event loop or tx thread.
 * @return 1 if everything was written, 0 otherwise.
 */
static int do_fd_write(struct mux_ctx *ctx)
{
	/* Is there any data in current buffer */
	if (ctx->tx.buf != NULL) {
		if (!do_fd_write_buf(ctx, ctx->tx.buf, &ctx->tx.off))
			return 0;

		/* Release buffer */
		pomp_buffer_unref(ctx->tx.buf);
		ctx->tx.buf = NULL;
		ctx->tx.off = 0;
	}

	/* Dequeue buffers */
	while (mux_queue_try_get_buf(ctx->tx.queue, &ctx->tx.buf) == 0) {
		ctx->tx.off = 0;
		if (!do_fd_write_buf(ctx, ctx->tx.buf, &ctx->tx.off))
			return 0;

		/* Release buffer */
		pomp_buffer_unref(ctx->tx.buf);
		ctx->tx.buf = NULL;
		ctx->tx.off = 0;
	}

	/* Everything was written */
	return 1;
}

/**
 */
static int do_tx_fd_pollable(struct mux_ctx *ctx, struct pomp_buffer *buf)
{
	if (ctx->stopped || ctx->eof)
		return -EPIPE;

	/* Try to send now if possible */
	if (ctx->tx.buf == NULL) {
		pomp_buffer_ref(buf);
		ctx->tx.buf = buf;
		ctx->tx.off = 0;
		if (!do_fd_write(ctx)) {
			/* if write failed because of EOF: do not enter async */
			if (!ctx->eof) {
				MUX_LOGD("ctx=%p fd=%d enter async mode",
						ctx, ctx->fd);
				pomp_loop_update(ctx->loop, ctx->fd,
						POMP_FD_EVENT_IN |
						POMP_FD_EVENT_OUT);
			}
		}
		return !ctx->stopped && !ctx->eof ? 0 : -EPIPE;
	} else {
		return mux_queue_put_buf(ctx->tx.queue, buf);
	}
}

/**
 */
static int do_tx_fd_not_pollable(struct mux_ctx *ctx, struct pomp_buffer *buf)
{
	/* Simply put buffer in tx queue */
	return mux_queue_put_buf(ctx->tx.queue, buf);
}

/**
 */
static int do_tx(struct mux_ctx *ctx, struct pomp_buffer *buf)
{
	/* Call tx operation if fd is not managed internally */
	if (ctx->fd < 0)
		return (*ctx->ops.tx)(ctx, buf, ctx->ops.userdata);

	if ((ctx->flags & MUX_FLAG_FD_NOT_POLLABLE) != 0)
		return do_tx_fd_not_pollable(ctx, buf);
	else
		return do_tx_fd_pollable(ctx, buf);
}

/**
 * Notify EOF or error.
 */
static void do_fdeof(struct mux_ctx *ctx)
{
	/* Notify only once */
	if (ctx->eof_notified)
		return;
	ctx->eof_notified = 1;

	/* Stop monitoring IO on fd, then notify */
	if ((ctx->flags & MUX_FLAG_FD_NOT_POLLABLE) == 0)
		pomp_loop_remove(ctx->loop, ctx->fd);
	(*ctx->ops.fdeof)(ctx, ctx->ops.userdata);
}

/**
 * Function call when fd is ready for IN events.
 */
static void fd_read_cb(struct mux_ctx *ctx)
{
	/* Read and decode data */
	while (do_fd_read(ctx))
		mux_decode(ctx, ctx->rx.buf);
}

/**
 * Function call when fd is ready for OUT events.
 */
static void fd_write_cb(struct mux_ctx *ctx)
{
	/* Write data, stop monitoring OUT events if queue is empty */
	if (do_fd_write(ctx)) {
		MUX_LOGD("ctx=%p fd=%d exit async mode", ctx, ctx->fd);
		pomp_loop_update(ctx->loop, ctx->fd, POMP_FD_EVENT_IN);
	}
}

/**
 * Function call when fd is ready for IN/OUT events.
 */
static void fd_cb(int fd, uint32_t revents, void *userdata)
{
	struct mux_ctx *ctx = userdata;
	if (revents & POMP_FD_EVENT_IN)
		fd_read_cb(ctx);
	if (revents & POMP_FD_EVENT_OUT)
		fd_write_cb(ctx);
	if (ctx->eof)
		do_fdeof(ctx);
}

/**
 * Function called when the rx available event is signaled.
 */
static void rx_evt_cb(struct pomp_evt *evt, void *userdata)
{
	struct mux_ctx *ctx = userdata;
	struct pomp_buffer *buf;

	/* Get a new buffer, process it and release it */
	while (mux_queue_try_get_buf(ctx->rx.queue, &buf) == 0) {
		if (!ctx->stopped && !ctx->eof)
			mux_decode(ctx, buf);
		pomp_buffer_unref(buf);
	}

	if (ctx->eof)
		do_fdeof(ctx);
}

/**
 * Rx thread when fd is managed internally and not pollable.
 */
static void *rx_thread(void *userdata)
{
	struct mux_ctx *ctx = userdata;

	while (!ctx->stopped && !ctx->eof) {
		if (do_fd_read(ctx))
			mux_queue_put_buf(ctx->rx.queue, ctx->rx.buf);

		/* Always signal rx event for eof notification */
		pomp_evt_signal(ctx->rx.evt);
	}

	return NULL;
}

/**
 * Tx thread when fd is managed internally and not pollable.
 */
static void *tx_thread(void *userdata)
{
	struct mux_ctx *ctx = userdata;

	while (!ctx->stopped && !ctx->eof) {
		if (ctx->tx.buf == NULL)
			mux_queue_get_buf(ctx->tx.queue, &ctx->tx.buf);
		do_fd_write(ctx);
	}

	/* Always signal rx event for eof notification */
	if (ctx->eof)
		pomp_evt_signal(ctx->rx.evt);

	return NULL;
}

/**
 * Setup fd when pollable. It sets it as non blocking and register it for
 * IN events in the loop.
 */
static int setup_fd_pollable(struct mux_ctx *ctx)
{
#ifdef _WIN32
	return -ENOSYS;
#else /* !_WIN32 */
	int res = 0;

	/* Tx queue */
	ctx->tx.queue = mux_queue_new(0);
	if (ctx->tx.queue == NULL)
		return -ENOMEM;

	/* Set fd non-blocking */
	if (fcntl(ctx->fd, F_SETFL,
			fcntl(ctx->fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
		res = -errno;
		MUX_LOG_FD_ERR("fcntl.F_SETFL", ctx->fd, errno);
		return res;
	}

	/* Register in loop for input */
	res = pomp_loop_add(ctx->loop, ctx->fd,
			POMP_FD_EVENT_IN, &fd_cb, ctx);
	if (res < 0) {
		MUX_LOG_ERR("pomp_loop_add", -res);
		return res;
	}

	return 0;
#endif /* !_WIN32 */
}

/**
 * Setup fd when not pollable. It setups rx/tx queues and creates rx/tx threads.
 */
static int setup_fd_not_pollable(struct mux_ctx *ctx)
{
	int res = 0;

	/* Rx queue */
	ctx->rx.queue = mux_queue_new(0);
	if (ctx->rx.queue == NULL)
		return -ENOMEM;

	/* Rx available event */
	ctx->rx.evt = pomp_evt_new();
	if (ctx->rx.evt == NULL) {
		res = -ENOMEM;
		return res;
	}

	/* Attach rx available event in loop */
	res = pomp_evt_attach_to_loop(ctx->rx.evt, ctx->loop, &rx_evt_cb, ctx);
	if (res < 0) {
		MUX_LOG_ERR("pomp_evt_attach_to_loop", -res);
		return res;
	}

	/* Tx queue */
	ctx->tx.queue = mux_queue_new(0);
	if (ctx->tx.queue == NULL)
		return -ENOMEM;

	/* Rx thread */
	res = pthread_create(&ctx->rx.thread, NULL, &rx_thread, ctx);
	if (res != 0) {
		MUX_LOG_ERR("pthread_create", res);
		return -res;
	}
	ctx->rx.thread_created = 1;

	/* Tx thread */
	pthread_create(&ctx->tx.thread, NULL, &tx_thread, ctx);
	if (res != 0) {
		MUX_LOG_ERR("pthread_create", res);
		return -res;
	}
	ctx->tx.thread_created = 1;

	return 0;
}

/**
 * Destroy mux context. Automatically called when ref count is 0.
 */
static void mux_destroy(struct mux_ctx *ctx)
{
	MUX_LOGI("destroying mux");
	if (ctx->channels != NULL) {
		MUX_LOGW("mux %p: some channels are still opened", ctx);
		return;
	}

	/* Stop rx/tx queues (in case stop was not called when destroy is
	 * called during early failures) */
	if (!ctx->stopped) {
		ctx->stopped = 1;
		if (ctx->rx.queue != NULL)
			mux_queue_stop(ctx->rx.queue);
		if (ctx->tx.queue != NULL)
			mux_queue_stop(ctx->tx.queue);
	}

	/* Join rx/tx thread */
	if (ctx->rx.thread_created)
		pthread_join(ctx->rx.thread, NULL);
	if (ctx->tx.thread_created)
		pthread_join(ctx->tx.thread, NULL);

	if (ctx->rx.evt != NULL) {
		pomp_evt_detach_from_loop(ctx->rx.evt, ctx->loop);
		pomp_evt_destroy(ctx->rx.evt);
	}

	if (ctx->loop != NULL) {
		if (ctx->fd >= 0 && pomp_loop_has_fd(ctx->loop, ctx->fd))
			pomp_loop_remove(ctx->loop, ctx->fd);
		if (!ctx->extloop)
			pomp_loop_destroy(ctx->loop);
	}

	if (ctx->payloadbuf != NULL)
		pomp_buffer_unref(ctx->payloadbuf);

	/* Clear rx */
	if (ctx->rx.buf != NULL)
		pomp_buffer_unref(ctx->rx.buf);
	if (ctx->rx.queue != NULL)
		mux_queue_destroy(ctx->rx.queue);

	/* Clear tx */
	if (ctx->tx.buf != NULL)
		pomp_buffer_unref(ctx->tx.buf);
	if (ctx->tx.queue != NULL)
		mux_queue_destroy(ctx->tx.queue);

	if (!ctx->extloop) {
		pthread_mutex_destroy(&ctx->loop_sync.mutex);
		pthread_cond_destroy(&ctx->loop_sync.cond_count);
		pthread_cond_destroy(&ctx->loop_sync.cond_waiters);
	}
	pthread_mutex_destroy(&ctx->mutex);

	/* Call release callback */
	if (ctx->ops.release)
		(*ctx->ops.release)(ctx, ctx->ops.userdata);

	free(ctx);
	MUX_LOGI("mux destroyed");
}

/*
 * See documentation in public header.
 */
struct mux_ctx *mux_new(int fd,
		struct pomp_loop *loop,
		const struct mux_ops *ops,
		uint32_t flags)
{
	struct mux_ctx *ctx = NULL;
	int res;

	/* Optional operations */
	if (fd >= 0 && (ops == NULL || ops->fdeof == NULL))
		return NULL;
	if (fd < 0 && (ops == NULL || ops->tx == NULL))
		return NULL;

	/* Allocate context structure */
	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return NULL;

	/* Initialize parameters */
	ctx->refcount = 1;
	ctx->fd = fd;
	ctx->flags = flags;
	list_init(&ctx->proxys);
	list_init(&ctx->pending_resolves);
	if (ops != NULL)
		ctx->ops = *ops;
	pthread_mutex_init(&ctx->mutex, NULL);

	if (loop != NULL) {
		ctx->loop = loop;
		ctx->extloop = 1;
	} else {
		pthread_mutex_init(&ctx->loop_sync.mutex, NULL);
		pthread_cond_init(&ctx->loop_sync.cond_count, NULL);
		pthread_cond_init(&ctx->loop_sync.cond_waiters, NULL);

		/* Create event loop */
		ctx->loop = pomp_loop_new();
		if (ctx->loop == NULL)
			goto error;
	}

	/* Reset decoder parameters */
	reset_decode(ctx);

	/* Setup fd */
	if (ctx->fd >= 0) {
		if ((ctx->flags & MUX_FLAG_FD_NOT_POLLABLE) != 0) {
			if (setup_fd_not_pollable(ctx) < 0)
				goto error;
		} else {
			if (setup_fd_pollable(ctx) < 0)
				goto error;
		}
	}

	/* Send handshake message */
	res = mux_send_handshake(ctx, 0);
	if (res < 0)
		MUX_LOG_ERR("mux_send_handshake", -res);

	return ctx;

	/* Cleanup in case of error */
error:
	mux_destroy(ctx);
	return NULL;
}

/*
 * See documentation in public header.
 */
void mux_ref(struct mux_ctx *ctx)
{
	int res;
	if (ctx == NULL)
		return;

#if defined(__GNUC__)
	res = __sync_add_and_fetch(&ctx->refcount, 1);
	MUX_LOGI("mux ref: %d", res);
#elif defined(_WIN32)
	/* codecheck_ignore[SPACING,VOLATILE] */
	InterlockedIncrement((long volatile *)&buf->refcount);
#else
#error No atomic increment function found on this platform
#endif
}

/*
 * See documentation in public header.
 */
void mux_unref(struct mux_ctx *ctx)
{
	uint32_t res = 0;
	if (ctx == NULL)
		return;

#if defined(__GNUC__)
	res = __sync_sub_and_fetch(&ctx->refcount, 1);
	MUX_LOGI("mux unref: %d", res);
#elif defined(_WIN32)
	/* codecheck_ignore[SPACING,VOLATILE] */
	res = (uint32_t)InterlockedDecrement((long volatile *)&ctx->refcount);
#else
#error No atomic decrement function found on this platform
#endif

	/* Free resource when ref count reaches 0 */
	if (res == 0)
		mux_destroy(ctx);
}

/*
 * See documentation in public header.
 */
struct pomp_loop *mux_get_loop(struct mux_ctx *ctx)
{
	return ctx == NULL ? NULL : ctx->loop;
}

/*
 * See documentation in public header.
 */
uint32_t mux_get_remote_version(struct mux_ctx *ctx)
{
	return ctx == NULL ? 0 : ctx->remote_version;
}

/*
 * See documentation in public header.
 */
int mux_stop(struct mux_ctx *ctx)
{
	struct mux_channel *channel = NULL;
	struct mux_channel *next = NULL;
	if (ctx == NULL)
		return -EINVAL;

	MUX_LOGI("stopping mux");

	mux_loop_acquire(ctx, 0);

	/* Nothing to do if already stopped */
	if (ctx->stopped) {
		MUX_LOGI("mux already stopped");
		goto out;
	}

	ctx->stopped = 1;

	/* Stop rx/tx queues */
	if (ctx->rx.queue != NULL)
		mux_queue_stop(ctx->rx.queue);
	if (ctx->tx.queue != NULL)
		mux_queue_stop(ctx->tx.queue);

	if (ctx->rx.evt != NULL)
		pomp_evt_detach_from_loop(ctx->rx.evt, ctx->loop);

	/* Stop all channels */
	channel = ctx->channels;
	while (channel != NULL) {
		mux_channel_stop(channel);
		channel = channel->next;
	}

	/* Automatically close ip slave channels (save next first because
	 * channel might be destroyed in the loop) */
	channel = ctx->channels;
	while (channel != NULL) {
		next = channel->next;
		if (channel->type == MUX_CHANNEL_TYPE_IP_SLAVE)
			mux_channel_close(ctx, channel->chanid);
		channel = next;
	}

out:
	mux_loop_release(ctx);
	MUX_LOGI("mux stopped");
	return 0;
}

/*
 * See documentation in public header.
 */
int mux_run(struct mux_ctx *ctx)
{
	if (ctx == NULL)
		return -EINVAL;
	if (ctx->extloop)
		return -EPERM;

	mux_ref(ctx);
	while (!ctx->stopped) {
		mux_loop_acquire(ctx, 1);
		if (!ctx->stopped)
			pomp_loop_wait_and_process(ctx->loop, -1);
		mux_loop_release(ctx);
	}
	mux_unref(ctx);

	return 0;
}

/*
 * See documentation in public header.
 */
int mux_encode(struct mux_ctx *ctx, uint32_t chanid, struct pomp_buffer *buf)
{
	int res = 0;
	struct pomp_buffer *headerbuf = NULL;
	struct mux_channel *channel = NULL;

	if (ctx == NULL || buf == NULL)
		return -EINVAL;

	if (ctx->stopped)
		return -EPIPE;

	/* Make sure channel is opened */
	if (chanid != 0) {
		channel = mux_find_channel(ctx, chanid);
		if (channel == NULL)
			return -EPIPE;
	}

	/* Create buffer for header */
	headerbuf = create_header_buf(ctx, chanid, buf);
	if (headerbuf == NULL)
		return -ENOMEM;

	mux_loop_acquire(ctx, 0);

	/* Send buffers */
	res = do_tx(ctx, headerbuf);
	if (res < 0)
		goto out;
	res = do_tx(ctx, buf);
	if (res < 0)
		goto out;

out:
	if (headerbuf != NULL)
		pomp_buffer_unref(headerbuf);

	mux_loop_release(ctx);
	return res;
}

/*
 * See documentation in public header.
 */
int mux_decode(struct mux_ctx *ctx, struct pomp_buffer *buf)
{
	int res = 0;
	const void *cdata = NULL;
	size_t len = 0, off = 0;
	if (ctx == NULL || buf == NULL)
		return -EINVAL;

	/* Get data from buffer */
	res = pomp_buffer_get_cdata(buf, &cdata, &len, NULL);
	if (res < 0)
		return res;

	mux_loop_acquire(ctx, 0);

	/* Processing loop */
	while (off < len) {
		switch (ctx->state) {
		case MUX_PROT_STATE_IDLE: /* NO BREAK */
		case MUX_PROT_STATE_HEADER_MAGIC_0:
			reset_decode(ctx);
			ctx->state = MUX_PROT_STATE_HEADER_MAGIC_0;
			process_header_magic(ctx, cdata, &off, len);
			check_magic(ctx, 0, MUX_PROT_HEADER_MAGIC_0,
					MUX_PROT_STATE_HEADER_MAGIC_1);
			break;

		case MUX_PROT_STATE_HEADER_MAGIC_1:
			process_header_magic(ctx, cdata, &off, len);
			check_magic(ctx, 1, MUX_PROT_HEADER_MAGIC_1,
					MUX_PROT_STATE_HEADER_MAGIC_2);
			break;

		case MUX_PROT_STATE_HEADER_MAGIC_2:
			process_header_magic(ctx, cdata, &off, len);
			check_magic(ctx, 2, MUX_PROT_HEADER_MAGIC_2,
					MUX_PROT_STATE_HEADER_MAGIC_3);
			break;

		case MUX_PROT_STATE_HEADER_MAGIC_3:
			process_header_magic(ctx, cdata, &off, len);
			check_magic(ctx, 3, MUX_PROT_HEADER_MAGIC_3,
					MUX_PROT_STATE_HEADER);
			break;

		case MUX_PROT_STATE_HEADER:
			process_header(ctx, cdata, &off, len);
			if (ctx->offheader == MUX_PROT_HEADER_SIZE)
				decode_header(ctx);
			break;

		case MUX_PROT_STATE_PAYLOAD:
			process_payload(ctx, cdata, &off, len);
			break;

		default:
			MUX_LOGE("Invalid state %d", ctx->state);
			break;
		}

		/* Check end of payload */
		if (ctx->state == MUX_PROT_STATE_PAYLOAD &&
				ctx->offpayload == ctx->lenpayload) {
			if (ctx->payloadbuf != NULL)
				notify_payload(ctx);
			ctx->state = MUX_PROT_STATE_IDLE;
		}
	}

	mux_loop_release(ctx);

	return 0;
}

/**
 */
int mux_get_host_address(struct mux_ctx *ctx, const char *hostname,
		uint32_t *addr)
{
	int ret;

	if (!ctx || !hostname || !addr)
		return -EINVAL;

	pthread_mutex_lock(&ctx->mutex);

	if (ctx->ops.resolve != NULL) {
		ret = (*ctx->ops.resolve)(ctx, hostname, addr,
				ctx->ops.userdata);
	} else {
		ret = -ENOENT;
	}

	pthread_mutex_unlock(&ctx->mutex);
	return ret;
}

static int mux_resolve_req_new(struct mux_ctx *ctx, uint32_t proxy_id,
		struct mux_ip_proxy_protocol *protocol,
		const char *hostname, uint16_t port,
		struct mux_resolve_request **ret_req)
{
	struct mux_resolve_request *req = NULL;

	if (ctx == NULL ||
	    hostname == NULL)
		return -EINVAL;

	req = calloc(1, sizeof(*req));
	if (req == NULL)
		return -ENOMEM;

	req->hostname = strdup(hostname);
	if (req->hostname  == NULL) {
		free(req);
		return -ENOMEM;
	}
	req->proxy_id = proxy_id;
	req->protocol = *protocol;
	req->hostport = port;

	*ret_req = req;
	return 0;
}

static int mux_resolve_req_destroy(struct mux_ctx *ctx,
		struct mux_resolve_request *req)
{
	if (ctx == NULL ||
	    req == NULL)
		return -EINVAL;

	free(req->hostname);
	free(req);
	return 0;
}

int mux_add_pending_resolve(struct mux_ctx *ctx, uint32_t proxy_id,
		struct mux_ip_proxy_protocol *protocol,
		const char *hostname, uint16_t port) {
	int res = 0;
	struct mux_resolve_request *req = NULL;

	if (ctx == NULL ||
	    protocol == NULL ||
	    hostname == NULL)
		return -EINVAL;

	res = mux_resolve_req_new(ctx, proxy_id, protocol, hostname, port,
			&req);
	if (res < 0)
		return res;

	mux_loop_acquire(ctx, 0);

	/* Add request to the list */
	list_add_before(&ctx->pending_resolves, &req->node);

	mux_loop_release(ctx);

	return 0;
}

/**
 */
int mux_resolve(struct mux_ctx *ctx, const char *hostname,
		uint32_t hostaddr)
{
	int res = 0;
	struct mux_resolve_request *req = NULL;
	struct mux_resolve_request *req_tmp = NULL;

	if (ctx == NULL || hostname == NULL)
		return -EINVAL;

	mux_loop_acquire(ctx, 0);

	/* Search hostname in pending resolutions. */
	list_walk_entry_forward_safe(&ctx->pending_resolves,
			req, req_tmp, node) {
		if (strcmp(hostname, req->hostname))
			continue;

		/* Send resolve ack */
		res = mux_send_proxy_ip_resolve_ack(ctx, req->proxy_id,
				&req->protocol,
				hostname, hostaddr, req->hostport);
		if (res < 0)
			MUX_LOG_ERR("mux_send_proxy_ip_resolve_ack", -res);

		/* remove request from list */
		list_del(&req->node);
		mux_resolve_req_destroy(ctx, req);
	}

	mux_loop_release(ctx);

	return 0;
}

/**
 */
struct mux_channel *mux_find_channel(struct mux_ctx *ctx, uint32_t chanid)
{
	struct mux_channel *channel = NULL;
	if (ctx == NULL)
		return NULL;

	pthread_mutex_lock(&ctx->mutex);

	/* Search in list */
	channel = ctx->channels;
	while (channel != NULL) {
		if (channel->chanid == chanid)
			break;
		channel = channel->next;
	}

	pthread_mutex_unlock(&ctx->mutex);

	return channel;
}

/**
 */
int mux_add_channel(struct mux_ctx *ctx, struct mux_channel *channel)
{
	struct mux_channel *tmp;
	int ret;

	if (ctx == NULL || channel == NULL)
		return -EINVAL;

	pthread_mutex_lock(&ctx->mutex);

	/* Check if channel already exists */
	tmp = ctx->channels;
	while (tmp != NULL) {
		if (tmp->chanid == channel->chanid) {
			ret = -EEXIST;
			goto error;
		}
		tmp = tmp->next;
	}

	/* Add at start of list */
	channel->next = ctx->channels;
	ctx->channels = channel;
	ret = 0;

	/* reset last recv chanid closed */
	if (ctx->last_rcv_chanid_closed == channel->chanid)
		ctx->last_rcv_chanid_closed = 0;

error:
	pthread_mutex_unlock(&ctx->mutex);
	return ret;
}

/**
 */
int mux_remove_channel(struct mux_ctx *ctx, struct mux_channel *channel)
{
	int res = 0;
	struct mux_channel *prev = NULL;

	if (ctx == NULL || channel == NULL)
		return -EINVAL;

	pthread_mutex_lock(&ctx->mutex);

	/* reset current channel */
	if (ctx->channel == channel)
		ctx->channel = NULL;

	if (ctx->channels == channel) {
		/* This was the first in the list */
		ctx->channels = channel->next;
		goto out;
	} else {
		/* Search in list */
		prev = ctx->channels;
		while (prev != NULL) {
			if (prev->next != channel) {
				prev = prev->next;
				continue;
			}

			/* Remove from list */
			prev->next = channel->next;
			goto out;
		}
	}

	/* Not found */
	res = -ENOENT;

out:
	pthread_mutex_unlock(&ctx->mutex);
	return res;
}

/**
 */
int mux_reset(struct mux_ctx *ctx)
{
	int res;
	struct mux_ctrl_msg msg;

	MUX_LOGI("Reset mux");

	if (ctx == NULL)
		return -EINVAL;

	mux_loop_acquire(ctx, 0);

	if (ctx->stopped) {
		res = -EBUSY;
		goto out;
	}

	/* Send reset message on control channel */
	memset(&msg, 0, sizeof(msg));
	msg.id = MUX_CTRL_MSG_ID_RESET;
	res = mux_send_ctrl_msg(ctx, &msg);

out:
	mux_loop_release(ctx);
	return res;
}

/**
 */
struct mux_channel *mux_remove_channels(struct mux_ctx *ctx)
{
	struct mux_channel *channels;

	if (ctx == NULL)
		return NULL;

	pthread_mutex_lock(&ctx->mutex);

	channels = ctx->channels;
	ctx->channels = NULL;
	ctx->channel = NULL;

	pthread_mutex_unlock(&ctx->mutex);
	return channels;
}

/**
 */
int mux_loop_acquire(struct mux_ctx *ctx, int willblock)
{
	if (ctx == NULL)
		return -EINVAL;

	/* Nothing to do for external loop */
	if (ctx->extloop)
		return 0;

	pthread_mutex_lock(&ctx->loop_sync.mutex);

	/* If current thread is not the owner, wait */
	if (!pthread_equal(ctx->loop_sync.owner, pthread_self())) {
		ctx->loop_sync.waiters++;

		/* If the acquire is for the blocking processing loop,
		 * do not acquire it now if there is other waiters */
		if (willblock) {
			while (ctx->loop_sync.waiters > 1) {
				pthread_cond_wait(&ctx->loop_sync.cond_waiters,
						&ctx->loop_sync.mutex);
			}
		}

		/* Wait until loop can be acquired */
		while (ctx->loop_sync.count != 0) {
			pomp_loop_wakeup(ctx->loop);
			pthread_cond_wait(&ctx->loop_sync.cond_count,
					&ctx->loop_sync.mutex);
		}

		ctx->loop_sync.waiters--;
		if (ctx->loop_sync.waiters <= 1)
			pthread_cond_signal(&ctx->loop_sync.cond_waiters);
	}

	/* OK, we are owner of loop */
	ctx->loop_sync.owner = pthread_self();
	ctx->loop_sync.count++;
	pthread_mutex_unlock(&ctx->loop_sync.mutex);
	return 0;
}

/**
 */
int mux_loop_release(struct mux_ctx *ctx)
{
	int res = 0;
	if (ctx == NULL)
		return -EINVAL;

	/* Nothing to do for external loop */
	if (ctx->extloop)
		return 0;

	pthread_mutex_lock(&ctx->loop_sync.mutex);

	if (!pthread_equal(ctx->loop_sync.owner, pthread_self())) {
		res = -EPERM;
		MUX_LOGE("Thread does not own the loop");
	} else if (--ctx->loop_sync.count == 0) {
		memset(&ctx->loop_sync.owner, 0, sizeof(pthread_t));
		pthread_cond_signal(&ctx->loop_sync.cond_count);
	}

	pthread_mutex_unlock(&ctx->loop_sync.mutex);
	return res;
}

/**
 */
int mux_send_ctrl_msg(struct mux_ctx *ctx, const struct mux_ctrl_msg *msg)
{
	return mux_send_ctrl_msg_with_payload(ctx, msg, NULL, 0);
}

/**
 */
int mux_send_ctrl_msg_with_payload(struct mux_ctx *ctx,
				   const struct mux_ctrl_msg *msg,
				   const void *payload,
				   size_t payload_size)
{
	int res = 0;
	struct pomp_buffer *buf = NULL;
	void *data = NULL;

	if (ctx == NULL || msg == NULL)
		return -EINVAL;

	if (payload_size > 0 && !payload)
		return -EINVAL;

	if (ctx->stopped)
		return -EPIPE;

	/* silently ignore send msg if eof raised */
	if (ctx->eof)
		return 0;

	/* Create buffer */
	buf = pomp_buffer_new(MUX_PROT_HEADER_SIZE + sizeof(*msg) +
			payload_size);
	if (buf == NULL) {
		res = -ENOMEM;
		goto out;
	}

	res = pomp_buffer_get_data(buf, &data, NULL, NULL);
	if (res < 0)
		goto out;

	/* Fill header, then data */
	fill_header(data, 0, sizeof(*msg) + payload_size);
	memcpy((uint8_t *)data + MUX_PROT_HEADER_SIZE, msg, sizeof(*msg));
	if (payload_size > 0)
		memcpy((uint8_t *)data + MUX_PROT_HEADER_SIZE +
			sizeof(*msg), payload, payload_size);
#ifndef MUX_LITTLE_ENDIAN
#error Big endian machines not yet supported
#endif

	/* Set length of buffer */
	res = pomp_buffer_set_len(buf, MUX_PROT_HEADER_SIZE + sizeof(*msg) +
			payload_size);
	if (res < 0)
		goto out;

	/* Directly send it */
	res = do_tx(ctx, buf);

out:
	if (buf != NULL)
		pomp_buffer_unref(buf);
	return res;
}

/**
 */
int mux_send_handshake(struct mux_ctx *ctx, int is_ack)
{
	struct mux_ctrl_msg version_msg = {
		.id = MUX_CTRL_MSG_ID_HANDSHAKE,
	};
	version_msg.args[0] = is_ack;
	version_msg.args[1] = MUX_PROTOCOL_VERSION;
	return mux_send_ctrl_msg_with_payload(ctx, &version_msg, NULL, 0);
}

/**
 */
int mux_notify_buf(struct mux_ctx *ctx, uint32_t chanid,
		struct pomp_buffer *buf)
{
	if (ctx == NULL || buf == NULL)
		return -EINVAL;
	if (ctx->ops.chan_cb == NULL)
		MUX_LOGW("Buffer lost chanid=0x%08x", chanid);
	else
		(*ctx->ops.chan_cb)(ctx, chanid, MUX_CHANNEL_DATA, buf,
				    ctx->ops.userdata);
	return 0;
}

int mux_ip_proxy_new(struct mux_ctx *ctx, struct mux_ip_proxy_info *info,
		struct mux_ip_proxy_cbs *cbs, int timeout,
		struct mux_ip_proxy **ret_obj)
{
	int res = 0;
	struct mux_ip_proxy *ip_proxy;
	size_t remotehost_len = 0;
	struct mux_ctrl_msg msg = {
		.id = MUX_CTRL_MSG_ID_PROXY_RESOLVE_REQ,
	};

	if (ctx == NULL || ret_obj == NULL ||
	    info == NULL || info->remote_host == NULL ||
	    cbs == NULL || cbs->open == NULL || cbs->close == NULL)
		return -EINVAL;

	if (info->protocol.application == MUX_IP_PROXY_APPLICATION_FTP &&
	    info->protocol.transport != MUX_IP_PROXY_TRANSPORT_TCP)
		return -EINVAL;

	ip_proxy = calloc(1, sizeof(*ip_proxy));
	if (ip_proxy == NULL)
		return -ENOMEM;

	list_add_before(&ctx->proxys, &ip_proxy->node);

	mux_loop_acquire(ctx, 0);

	ip_proxy->mux_ctx = ctx;
	mux_ref(ctx);

	ip_proxy->ploop = mux_get_loop(ctx);
	ip_proxy->protocol = info->protocol;
	ip_proxy->cbs = *cbs;
	ip_proxy->id = ctx->last_proxy_id++;
	ip_proxy->req.id = MUX_CTRL_MSG_ID_UNKNOWN;
	ip_proxy->remote.port = info->remote_port;
	ip_proxy->remote.host = strdup(info->remote_host);
	if (ip_proxy->remote.host == NULL) {
		res = -ENOMEM;
		goto error;
	}

	if (ip_proxy->protocol.transport == MUX_IP_PROXY_TRANSPORT_UDP) {
		res = mux_ip_proxy_set_udp_redirect_port(ip_proxy,
				info->udp_redirect_port);
		if (res < 0)
			goto error;
	}

	res = hash_init(&ip_proxy->tcp_conn_to_chann, 0);
	if (res < 0)
		goto error;

	/* Initilize pending request */
	res = mux_ip_init_pending_resolve_req(ip_proxy,
			ip_proxy->remote.host, timeout);
	if (res < 0)
		goto error;

	/* Ask address resolution by the mux peer. */
	msg.args[0] = ip_proxy->id;
	msg.args[1] = ip_proxy->protocol.transport;
	msg.args[2] = ip_proxy->protocol.application;
	msg.args[3] = ip_proxy->remote.port;
	remotehost_len = strlen(ip_proxy->remote.host) + 1;
	res = mux_send_ctrl_msg_with_payload(ctx, &msg, ip_proxy->remote.host,
			remotehost_len);
	if (res < 0)
		goto error;

	mux_loop_release(ctx);

	*ret_obj = ip_proxy;
	return 0;

	/* Cleanup in case of error */
error:
	mux_ip_proxy_destroy(ip_proxy);
	mux_loop_release(ctx);
	return res;
}

int mux_ip_proxy_destroy(struct mux_ip_proxy *ip_proxy)
{
	size_t len;

	if (ip_proxy == NULL)
		return -EINVAL;

	mux_loop_acquire(ip_proxy->mux_ctx, 0);

	mux_ip_proxy_close(ip_proxy);

	len = list_length(&ip_proxy->tcp_conn_to_chann.entries);
	if (len != 0)
		MUX_LOGW("connection to channel hash table not empty");

	hash_destroy(&ip_proxy->tcp_conn_to_chann);

	mux_ip_clear_pending_req(ip_proxy);

	mux_loop_release(ip_proxy->mux_ctx);
	list_del(&ip_proxy->node);

	mux_unref(ip_proxy->mux_ctx);
	free(ip_proxy->remote.host);
	free(ip_proxy);
	return 0;
}

struct mux_ip_proxy *mux_ip_proxy_from_id(struct mux_ctx *self, uint32_t id)
{
	struct mux_ip_proxy *proxy = NULL;

	if (self == NULL)
		return NULL;

	list_walk_entry_forward(&self->proxys, proxy, node) {
		if (proxy->id == id)
			return proxy;
	}

	return NULL;
}

int mux_ip_proxy_get_local_info(struct mux_ip_proxy *self,
		struct mux_ip_proxy_protocol *protocol, uint16_t *localport)
{
	if (self == NULL)
		return -EINVAL;

	if (protocol != NULL)
		*protocol = self->protocol;

	if (localport != NULL)
		*localport = self->localport;

	return 0;
}

uint16_t mux_ip_proxy_get_peerport(struct mux_ip_proxy *self)
{
	return (self != NULL) ? self->peerport : 0;
}

int mux_ip_proxy_set_udp_remote(struct mux_ip_proxy *self,
		const char *remote_host, uint16_t remote_port, int timeout)
{
	struct mux_ctrl_msg msg = {
		.id = MUX_CTRL_MSG_ID_PROXY_RESOLVE_REQ,
	};
	int res;
	size_t remotehost_len;
	char *old_host = NULL;

	if (self == NULL || remote_host == NULL ||
	    self->protocol.transport != MUX_IP_PROXY_TRANSPORT_UDP)
		return -EINVAL;

	mux_loop_acquire(self->mux_ctx, 0);

	if (self->udp.channel == NULL) {
		res = -EINVAL;
		goto end;
	}

	if (self->req.id != MUX_CTRL_MSG_ID_UNKNOWN) {
		/* Busy. */
		res = -EBUSY;
		goto end;
	}

	if (strcmp(remote_host, self->remote.host) == 0 &&
	    remote_port == self->remote.port) {
		/* Already connected to this remote. */
		res = -EALREADY;
		goto end;
	}

	/* Update remote addresse */
	old_host = self->remote.host;
	self->remote.host = strdup(remote_host);
	if (self->remote.host == NULL) {
		self->remote.host = old_host;
		res = -ENOMEM;
		goto end;
	}
	free(old_host);
	self->remote.addr = 0;
	self->remote.port = remote_port;

	/* Initilize pending request */
	res = mux_ip_init_pending_resolve_req(self,
			self->remote.host, timeout);
	if (res < 0)
		goto end;

	/* Ask the mux peer to resolve the address. */
	msg.chanid = self->udp.channel->chanid;
	msg.args[0] = self->id;
	msg.args[1] = self->protocol.transport;
	msg.args[2] = self->protocol.application;
	msg.args[3] = remote_port;
	remotehost_len = strlen(self->remote.host) + 1;
	res = mux_send_ctrl_msg_with_payload(self->mux_ctx, &msg,
			self->remote.host, remotehost_len);

end:
	mux_loop_release(self->mux_ctx);
	return res;
}

int mux_ip_proxy_set_udp_redirect_port(struct mux_ip_proxy *self,
		uint16_t redirect_port)
{
	struct sockaddr_in *addr;

	if (self == NULL ||
	    self->protocol.transport != MUX_IP_PROXY_TRANSPORT_UDP)
		return -EINVAL;

	mux_loop_acquire(self->mux_ctx, 0);

	self->udp.redirect_port = redirect_port;

	/* Setup address */
	addr = (struct sockaddr_in *)&self->udp.addr;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr->sin_port = htons(redirect_port);
	self->udp.addrlen = sizeof(*addr);

	mux_loop_release(self->mux_ctx);

	return 0;
}

int mux_set_remote_version(struct mux_ctx *ctx, uint32_t version)
{
	if (ctx == NULL)
		return -EINVAL;

	ctx->remote_version = version;
	return 0;
}
