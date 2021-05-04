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
 * @file mux_priv.h
 *
 */

#ifndef _MUX_PRIV_H_
#define _MUX_PRIV_H_

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_ENDIAN_H
#  include <endian.h>
#endif
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef _WIN32
# include <winsock2.h>
#else /* !_WIN32 */
#  include <sys/ioctl.h>
#  include <sys/socket.h>
#  include <arpa/inet.h>
#  include <netinet/in.h>
#endif /* !_WIN32 */

#define POMP_ENABLE_ADVANCED_API
#if defined(ALCHEMY_BUILD) || defined(ANDROID)
#  include <libpomp.h>
#  include "libmux.h"
#else
#  include <libpomp/libpomp.h>
#  include "libARNetworkALMux/libmux.h"
#endif

#include <futils/hash.h>
#include <futils/list.h>
#include <futils/random.h>

/* Forward declarations */
struct mux_ctrl_msg;

#include "mux_log.h"
#include "mux_channel.h"
#include "mux_ip_proxy_priv.h"

/** Endianess detection */
#if !defined(MUX_LITTLE_ENDIAN) && !defined(MUX_BIG_ENDIAN)
#  if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
#    define MUX_LITTLE_ENDIAN
#  elif defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
#    define MUX_BIG_ENDIAN
#  elif defined(_WIN32)
#    define MUX_LITTLE_ENDIAN
#  else
#    error Unable to determine endianess of machine
#  endif
#endif

#ifdef MUX_LITTLE_ENDIAN

/** Convert 32-bit integer from host ordering to little endian */
#define MUX_HTOLE32(_x)	((uint32_t)(_x))

/** Convert 32-bit integer from little endian to host ordering */
#define MUX_LE32TOH(_x)	((uint32_t)(_x))

#else

#error Big endian machines not yet supported

#endif

/**
 * Mux messages.
 *
 * To ensure retrocompatibility:
 * - Old messages should never be removed, changed or reused.
 * - Core messages should always be functional and retrocompatible.
 * - New messages should use a new identifier.
 * - MUX_PROTOCOL_VERSION should be incremented each time a message is added or
 *   modified.
 */
enum mux_ctrl_msg_id {
	MUX_CTRL_MSG_ID_UNKNOWN = UINT32_MAX,
	/** Core message. */
	MUX_CTRL_MSG_ID_CHANNEL_OPEN = 0,
	/** Core message. */
	MUX_CTRL_MSG_ID_CHANNEL_CLOSE = 1,
	MUX_CTRL_MSG_ID_CHANNEL_TCP_CONNECT, /**< Deprecated */
	MUX_CTRL_MSG_ID_CHANNEL_TCP_DISCONNECT, /**< Deprecated */
	MUX_CTRL_MSG_ID_CHANNEL_TCP_CONNECTED, /**< Deprecated */
	MUX_CTRL_MSG_ID_CHANNEL_TCP_DISCONNECTED, /**< Deprecated */
	/** Core message. */
	MUX_CTRL_MSG_ID_RESET = 6,
	MUX_CTRL_MSG_ID_CHANNEL_TCP_REQ_ACK, /**< Deprecated */
	MUX_CTRL_MSG_ID_CHANNEL_TCP_ACK, /**< Deprecated */

	MUX_CTRL_MSG_ID_PROXY_RESOLVE_REQ,
	MUX_CTRL_MSG_ID_PROXY_RESOLVE_REQ_ACK,
	MUX_CTRL_MSG_ID_PROXY_REMOTE_UPDATE_REQ,
	MUX_CTRL_MSG_ID_PROXY_REMOTE_UPDATE_REQ_ACK,
	MUX_CTRL_MSG_ID_CHANNEL_IP_CONNECT,
	MUX_CTRL_MSG_ID_CHANNEL_IP_DISCONNECT,
	MUX_CTRL_MSG_ID_CHANNEL_IP_CONNECTED,
	MUX_CTRL_MSG_ID_CHANNEL_IP_DISCONNECTED,
	MUX_CTRL_MSG_ID_CHANNEL_IP_REQ_ACK,
	MUX_CTRL_MSG_ID_CHANNEL_IP_ACK,

	/** Core message. */
	MUX_CTRL_MSG_ID_HANDSHAKE = 127,
};

#define MUX_CTRL_MSG_MAX_ARG_COUNT	6

struct mux_ctrl_msg {
	uint32_t	id;
	uint32_t	chanid;
	uint32_t	args[MUX_CTRL_MSG_MAX_ARG_COUNT];
};

struct mux_channel;

/* Internal version API */

/**
 * Sets the remote protocol mux version.
 *
 * @param ctx : mux context.
 * @param version : remote protocol version number.
 *
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_set_remote_version(struct mux_ctx *ctx, uint32_t version);

/* Internal context API */

int mux_loop_acquire(struct mux_ctx *ctx, int willblock);

int mux_loop_release(struct mux_ctx *ctx);

/**
 * Send a handshake.
 *
 * @param ctx : mux context.
 * @param is_ack : '1' if it is an acknowledgement of a handshake received,
 *                 otherwise '0'.
 *
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_send_handshake(struct mux_ctx *ctx, int is_ack);

int mux_send_ctrl_msg(struct mux_ctx *ctx, const struct mux_ctrl_msg *msg);

int mux_send_ctrl_msg_with_payload(struct mux_ctx *ctx,
		const struct mux_ctrl_msg *msg, const void *payload,
		size_t payload_size);

int mux_notify_buf(struct mux_ctx *ctx, uint32_t chanid,
		struct pomp_buffer *buf);

struct mux_channel *mux_find_channel(struct mux_ctx *ctx, uint32_t chanid);

int mux_add_channel(struct mux_ctx *ctx, struct mux_channel *channel);

int mux_remove_channel(struct mux_ctx *ctx, struct mux_channel *channel);

struct mux_channel *mux_remove_channels(struct mux_ctx *ctx);

int mux_get_host_address(struct mux_ctx *ctx, const char *hostname,
		uint32_t *addr);
int mux_resolve_addr(struct mux_ctx *ctx, char *hostname, char **hostip);

struct mux_ip_proxy *mux_ip_proxy_from_id(struct mux_ctx *ctx, uint32_t id);

int mux_add_pending_resolve(struct mux_ctx *ctx, uint32_t proxy_id,
		struct mux_ip_proxy_protocol *protocol,
		const char *hostname, uint16_t port);

/* Internal queue API */

struct mux_queue *mux_queue_new(uint32_t depth);
int mux_queue_destroy(struct mux_queue *queue);
int mux_queue_stop(struct mux_queue *queue);
int mux_queue_put_buf(struct mux_queue *queue, struct pomp_buffer *buf);

#endif /* !_MUX_PRIV_H_ */
