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
 * @file mux_channel.h
 *
 */

#ifndef _MUX_CHANNEL_H_
#define _MUX_CHANNEL_H_

/** Minimum master channel id. */
#define IS_MASTER_ID_MIN 1024

/** Get the master channel id of a slave channel */
#define GET_MASTER_ID(slaveid) ((slaveid) & 0x7fffffff)

/** Get the slave channel id of a master channel */
#define GET_SLAVE_ID(masterid) ((masterid) | 0x80000000)

/** Check if a channel id is a master one */
#define IS_MASTER_ID(channid) ({ __typeof__(channid) _cid = (channid); \
				((_cid & 0x80000000) == 0) && \
				_cid >= IS_MASTER_ID_MIN; })

/** Check if a channel id is a slave one */
#define IS_SLAVE_ID(channid) (((channid) & 0x80000000) != 0)

/** Type of channel */
enum mux_channel_type {
	MUX_CHANNEL_TYPE_NORMAL,
	MUX_CHANNEL_TYPE_IP_MASTER,
	MUX_CHANNEL_TYPE_IP_SLAVE,
};

/** State of ip channel */
enum mux_ip_state {
	MUX_IP_STATE_IDLE,
	MUX_IP_STATE_CONNECTING,
	MUX_IP_STATE_CONNECTED,
};

/** Channel structure */
struct mux_channel {
	enum mux_channel_type	type;
	struct mux_ctx		*ctx;
	struct pomp_loop	*loop;
	uint32_t		chanid;
	struct mux_channel	*next;
	struct mux_queue	*queue;
	int			stopped;

	mux_channel_cb_t	cb;
	void			*userdata;

	union {
		/* Link between the mux and local. */
		struct {
			enum mux_ip_state	state;
			uint32_t		remoteaddr;
			uint16_t		remoteport;
			int			waiting_ack;
			uint32_t		tx_ack_bytes;

			uint32_t		peerport;
			struct mux_ip_proxy	*ip_proxy;
			/** Proxy protocol. */
			struct mux_ip_proxy_protocol	protocol;
			struct pomp_conn	*conn;
			struct {
				struct mux_ip_proxy	*proxy;
				struct pomp_buffer	*buf;
				struct pomp_buffer	*buf_postport;
				int			remoteport;
			} ftp_data;
		} ipmaster;

		/* Link between the mux and the remote. */
		struct {
			struct pomp_ctx		*ctx;
			struct pomp_conn	*conn;
			int			fd;
			struct pomp_timer	*queue_timer;
			enum mux_ip_state	state;
			int			flushing;
			int			send_queue_empty;
			int			ack_req;

			/* Remote address. */
			struct sockaddr			remoteaddr;
			/* Remote address length. */
			size_t				remoteaddrlen;
			/** Proxy protocol. */
			struct mux_ip_proxy_protocol	protocol;
		} ipslave;
	};
};

/* Internal channel API */

/**
 * Open a channel for a remote ip connection.
 * @param ctx : mux context.
 * @param protocol : proxy protocol.
 * @param remoteaddr : remote address to connect to (IPv4).
 * @param remoteport : remote port to connect to.
 * @return 0 in case of success, negative errno value in case of error.
 *
 * @remarks safe to call from any thread if the internal loop is used.
 */
int mux_channel_open_ip(struct mux_ctx *ctx,
		struct mux_ip_proxy_protocol *protocol,
		uint32_t remoteaddr, uint16_t remoteport, uint32_t *chanid);

int mux_channel_recv_ctrl_msg(struct mux_ctx *ctx,
		const struct mux_ctrl_msg *msg,
		const void *payload,
		size_t size);

int mux_channel_stop(struct mux_channel *channel);

int mux_channel_put_buf(struct mux_channel *channel, struct pomp_buffer *buf);

/**
 * Notify a mux ip master channel of a pomp connection event.
 * @param channel: the channel to notify.
 * @param event: the pomp event.
 * @param conn: the pomp connection.
 */
void mux_channel_ipmaster_event(struct mux_channel *channel,
		enum pomp_event event,
		struct pomp_conn *conn);

/**
 * Notify a mux ip master channel that the pomp connection received data.
 * @param channel: the channel to notify.
 * @param conn: the pomp connection.
 * @param buf: the buffer data received.
 */
void mux_channel_ipmaster_raw(struct mux_channel *channel,
		struct pomp_conn *conn,
		struct pomp_buffer *buf);

int mux_channel_send_msg_ip_connect(struct mux_channel *channel);

/**
 * Send message ip resolve acknowledgement.
 *
 * @param ctx : mux context.
 * @param proxy_id : proxy identifier.
 * @param protocol : proxy protocol.
 * @param hostname : host name.
 * @param hostaddr : host address in network byte order.
 * @param port : host port.
 */
int mux_send_proxy_ip_resolve_ack(struct mux_ctx *ctx, uint32_t proxy_id,
		struct mux_ip_proxy_protocol *protocol, const char *hostname,
		uint32_t hostaddr, uint16_t port);

#endif /* _MUX_CHANNEL_H_ */
