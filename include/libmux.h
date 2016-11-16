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
 * @file libmux.h
 *
 */

#ifndef _LIBMUX_H_
#define _LIBMUX_H_

#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** To be used for all public API */
#ifdef MUX_API_EXPORTS
#  ifdef _WIN32
#    define MUX_API	__declspec(dllexport)
#  else /* !_WIN32 */
#    define MUX_API	__attribute__((visibility("default")))
#  endif /* !_WIN32 */
#else /* !MUX_API_EXPORTS */
#  define MUX_API
#endif /* !MUX_API_EXPORTS */

/* Forward declarations */
struct mux_ctx;
struct mux_queue;
struct pomp_loop;
struct pomp_buffer;

/** The given fd is not pollable and read/write must be done in threads */
#define MUX_FLAG_FD_NOT_POLLABLE	(1 << 0)

enum mux_channel_event {
	/* channel reset by peer */
	MUX_CHANNEL_RESET,
	/* channel data received */
	MUX_CHANNEL_DATA,
};

/**
 * Function called by mux_decode with demuxed data (unless a queue has
 * been allocated for the channel in which case mux_queue_get_buf
 * shall be called by another thread to get next buffer).
 * @param ctx : mux  context.
 * @param chanid : channel Id associated with data.
 * @param event : channel event.
 * @param buf : buffer with data (NULL if event is not MUX_CHANNEL_DATA).
 * @param userdata : user data.
 */
typedef void (*mux_channel_cb_t)(struct mux_ctx *ctx,
		uint32_t chanid,
		enum mux_channel_event event,
		struct pomp_buffer *buf,
		void *userdata);

/** */
struct mux_ops {
	/**
	 * Function called by mux_encode with muxed data
	 * @param ctx : mux  context.
	 * @param buf : buffer to write.
	 * @param userdata : user data.
	 * @return 0 in case of success, negative errno value in case of error.
	 *
	 * @remarks: the value returned by this function will be returned back
	 * by mux_encode.
	 */
	int (*tx)(struct mux_ctx *ctx, struct pomp_buffer *buf,
			void *userdata);

	/**
	 * Default channel function called by mux_decode with demuxed data
	 * if no callback was given during channel opening or a queue has been
	 * allocated for the channel.
	 */
	mux_channel_cb_t chan_cb;

	/**
	 * Function called when a valid fd was given during creation and
	 * an EOF condition or an error has been detected on the fd. The
	 * mux context should be stopped and destroyed (by another thread).
	 * @param ctx : mux  context.
	 * @param userdata : user data.
	 */
	void (*fdeof)(struct mux_ctx *ctx, void *userdata);

	/** Userdata to pass to operations */
	void *userdata;
};

/**
 * Create a new mux context.
 * @param fd : file descriptor to use for rx/tx operations. If valid, the mux
 * context will automatically read from it and decode data as well as write to
 * it encoded data. Set to -1 to handle rx/tx externally.
 * @param loop : event loop to use. If NULL the mux context will create its own
 * loop and a dedicated thread must created and call mux_run.
 * @param ops: callback operations. Can be NULL if a valid fd is given and the
 * rx operation is not used because all channels use a callback or queue.
 * @param flags : a combination of MUX_FLAG_XXX.
 * @return context structure or NULL in case of error.
 *
 * @remarks if a valid loop context is given, all calls to API must be done
 * in the thread running the loop. If the internal loop is used, the API can
 * be safely used by several threads.
 */
MUX_API struct mux_ctx *mux_new(int fd,
		struct pomp_loop *loop,
		const struct mux_ops *ops,
		uint32_t flags);

/**
 * Increase reference count of mux context.
 * @param ctx : mux context.
 */
MUX_API void mux_ref(struct mux_ctx *ctx);

/**
 * Decrease reference count of mux context. Object will be destroyed when it
 * reaches 0.
 * @param ctx : mux context.
 */
MUX_API void mux_unref(struct mux_ctx *ctx);

/**
 * Get the loop associated with the mux context.
 * @param ctx : mux context.
 * @param associated loop.
 */
MUX_API struct pomp_loop *mux_get_loop(struct mux_ctx *ctx);

/**
 * Stop a mux context. Shall be called prior to destroy the context. After this
 * call, the thread that called mux_run can be safely joined.
 * @param ctx : mux context.
 * @return 0 in case of success, negative errno value in case of error.
 */
MUX_API int mux_stop(struct mux_ctx *ctx);

/**
 * Run the internal event loop until mux_stop is called. Shall be called by
 * a dedicated thread.
 * @param ctx : mux context.
 * @return 0 in case of success, negative errno value in case of error.
 */
MUX_API int mux_run(struct mux_ctx *ctx);

/**
 * Reset mux.
 * @param ctx : mux context.
 * @return 0 in case of success, negative errno value in case of error.
 */
MUX_API int mux_reset(struct mux_ctx *ctx);

/**
 * Mux data. This will call the ops.tx operation with muxed data
 * (header + original data).
 * @param ctx : mux context.
 * @param chanid : channel Id associated with data.
 * @param buf : data to mux.
 * @return 0 in case of success, negative errno value in case of error.
 *
 * @remarks safe to call from any thread if the internal loop is used.
 */
MUX_API int mux_encode(struct mux_ctx *ctx, uint32_t chanid,
		struct pomp_buffer *buf);

/**
 * Demux read data. This will parse buffer, search for frames and call ops.rx
 * operation for any data belonging to a channel. No internal buffering is done
 * do_read may be called multiple times for a single frame.
 * @param ctx : mux context.
 * @param buf : data to demux.
 * @return 0 in case of success, negative errno value in case of error.
 *
 * @remarks safe to call from any thread if the internal loop is used.
 */
MUX_API int mux_decode(struct mux_ctx *ctx, struct pomp_buffer *buf);

/**
 * add host to be resolved by libmux tcp connection
 *
 * @param ctx : mux context.
 * @param hostname : hostname to be resolved.
 * @param addr : hostname ipv4 address.
 * @return 0 in case of success, negative errno value in case of error.
 */
MUX_API int mux_add_host(struct mux_ctx *ctx, const char *hostname,
		uint32_t addr);

/**
 * remove host to be resolved by libmux tcp connection
 *
 * @param ctx : mux context.
 * @param hostname : hostname to be resolved.
 * @return 0 in case of success, negative errno value in case of error.
 */
MUX_API int mux_remove_host(struct mux_ctx *ctx, const char *hostname);

/**
 * Open a channel.
 * @param ctx : mux context.
 * @param chanid : id of channel to open.
 * @param cb : function to call when data are received for the given channel.
 * Can be NULL in which case the generic rx operation of the mux context will
 * be used.
 * @param userdata : userd data given to callback.
 * @return 0 in case of success, negative errno value in case of error.
 *
 * @remarks safe to call from any thread if the internal loop is used.
 */
MUX_API int mux_channel_open(struct mux_ctx *ctx, uint32_t chanid,
		mux_channel_cb_t cb, void *userdata);

/**
 * Close a channel.
 * @param ctx : mux context.
 * @param chanid : id of channel to close.
 * @return 0 in case of success, negative errno value in case of error.
 *
 * @remarks safe to call from any thread if the internal loop is used.
 */
MUX_API int mux_channel_close(struct mux_ctx *ctx, uint32_t chanid);

/**
 * Open a channel for a remote tcp connection.
 * @param ctx : mux context.
 * @param remoteaddr : remote host to connect to (IPv4 quad-dotted format or
 * hostname).
 * @param remoteport : remote port to connect to.
 * @param localport : allocated local port for the connection.
 * @param localport : allocated channel id for the connection.
 * @return 0 in case of success, negative errno value in case of error.
 *
 * @remarks safe to call from any thread if the internal loop is used.
 */
MUX_API int mux_channel_open_tcp(struct mux_ctx *ctx,
		const char *remotehost, uint16_t remoteport,
		uint16_t *localport, uint32_t *chanid);

/**
 * Open a channel for a remote ftp connection.
 * @param ctx : mux context.
 * @param remoteaddr : remote host to connect to (IPv4 quad-dotted format or
 * hostname).
 * @param remoteport : remote port to connect to.
 * @param localport : allocated local port for the connection.
 * @param chanid : allocated channel id for the connection.
 * @return 0 in case of success, negative errno value in case of error.
 *
 * @remarks safe to call from any thread if the internal loop is used.
 */
MUX_API int mux_channel_open_ftp(struct mux_ctx *ctx,
		const char *remotehost, uint16_t remoteport,
		uint16_t *localport, uint32_t *chanid);

/**
 * Allocate a queue for a channel.
 * @param ctx : mux context.
 * @param chanid : id of channel.
 * @param depth : depth of queue. 0 for growable queue.
 * @param queue : allocated queue.
 * @return 0 in case of success, negative errno value in case of error.
 *
 * @remarks safe to call from any thread if the internal loop is used. However,
 * only one thread should dot it (the one that called mux_channel_open).
 */
MUX_API int mux_channel_alloc_queue(struct mux_ctx *ctx, uint32_t chanid,
		uint32_t depth, struct mux_queue **queue);

/**
 * Get a buffer from a queue. Blocking call until a buffer is available or the
 * queue is stopped (when channel is closed).
 * @param queue : queue.
 * @param buf : return buffer. Caller gets a new ref on it, please call
 * pomp_buffer_unref when done.
 * @return 0 in case of success, negative errno value in case of error.
 *
 * @remarks: when -EPIPE is returned, the queue object shall not be used
 * anymore by the caller.
 */
MUX_API int mux_queue_get_buf(struct mux_queue *queue,
		struct pomp_buffer **buf);

/**
 * Get a buffer from a queue. Non blocking version of mux_queue_get_buf.
 * @param queue : queue.
 * @param buf : return buffer. Caller gets a new ref on it, please call
 * pomp_buffer_unref when done.
 * @return 0 in case of success, negative errno value in case of error.
 *
 * @remarks: when -EPIPE is returned, the queue object shall not be used
 * anymore by the caller.
 */
MUX_API int mux_queue_try_get_buf(struct mux_queue *queue,
		struct pomp_buffer **buf);

/**
 * Get a buffer from a queue. Timed version of mux_queue_get_buf.
 * @param queue : queue.
 * @param buf : return buffer. Caller gets a new ref on it, please call
 * pomp_buffer_unref when done.
 * @param timeout : maximum wait time.
 * @return 0 in case of success, negative errno value in case of error.
 * -ETIMEDOUT is returned in case of timeout.
 *
 * @remarks: when -EPIPE is returned, the queue object shall not be used
 * anymore by the caller.
 */
MUX_API int mux_queue_timed_get_buf(struct mux_queue *queue,
				    struct pomp_buffer **buf,
				    struct timespec *timeout);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_LIBMUX_H_ */
