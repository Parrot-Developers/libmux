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

/** Get the master channel id of a slave channel */
#define GET_MASTER_ID(slaveid) ((slaveid) & 0x7fffffff)

/** Get the slave channel id of a master channel */
#define GET_SLAVE_ID(masterid) ((masterid) | 0x80000000)

/** Check if a channel id is a master one */
#define IS_MASTER_ID(channid) ((channid) >= 1024)

/** Check if a channel id is a slave one */
#define IS_SLAVE_ID(channid) (((channid) & 0x80000000) != 0)

/** Type of channel */
enum mux_channel_type {
	MUX_CHANNEL_TYPE_NORMAL,
	MUX_CHANNEL_TYPE_TCP_MASTER,
	MUX_CHANNEL_TYPE_TCP_SLAVE,
};

/** State of tcp channel */
enum mux_tcp_state {
	MUX_TCP_STATE_IDLE,
	MUX_TCP_STATE_CONNECTING,
	MUX_TCP_STATE_CONNECTED,
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
		struct {
			struct pomp_ctx		*ctx;
			struct pomp_conn	*conn;
			enum mux_tcp_state	state;
			char			*remotehost;
			uint16_t		remoteport;
			int			isftpctrl;
			struct mux_channel	*ftpdatachan;
			int			waiting_ack;
			uint32_t		tx_ack_bytes;
		} tcpmaster;

		struct {
			struct pomp_ctx		*ctx;
			struct pomp_conn	*conn;
			int			fd;
			struct pomp_timer	*queue_timer;
			enum mux_tcp_state	state;
			int			flushing;
			int			send_queue_empty;
			int			ack_req;
		} tcpslave;
	};
};

/* Internal channel API */

int mux_channel_recv_ctrl_msg(struct mux_ctx *ctx,
		const struct mux_ctrl_msg *msg,
		const void *payload,
		size_t size);

int mux_channel_stop(struct mux_channel *channel);

int mux_channel_put_buf(struct mux_channel *channel, struct pomp_buffer *buf);

#endif /* _MUX_CHANNEL_H_ */
