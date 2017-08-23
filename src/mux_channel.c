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
 */

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include "mux_priv.h"

#define MUX_CHANNEL_TCP_ACK_BYTES_INTL (64 * 1024) /* 64 KB */
#define MUX_CHANNEL_TCP_SLAVE_FIFO_TIMEOUT 100 /* 100 ms */

static int mux_channel_disconnect_tcp_slave(struct mux_ctx *ctx,
		uint32_t masterid);
/**
 */
#include <ctype.h>
static inline void log_buf(const char *prefix, struct pomp_buffer *buf)
{
/*	char log[256] = "";
	const void *cdata = NULL;
	size_t len = 0;
	size_t off = 0, i = 0;
	uint8_t b = 0;

	pomp_buffer_get_cdata(buf, &cdata, &len, NULL);

	off += snprintf(log + off, sizeof(log) - off, "%s %zu: ", prefix, len);

	for (i = 0; i < len && off < sizeof(log); i++) {
		b = ((const uint8_t *)cdata)[i];
		if (isprint(b)) {
			off += snprintf(log + off, sizeof(log) - off,
					"%c", b);
		} else {
			off += snprintf(log + off, sizeof(log) - off,
					"<%02x>", b);
		}
	}

	log[sizeof(log) - 1] = '\0';
	MUX_LOGD("%s", log);*/
}

/**
 * Get the string description of a channel type.
 * @param type : channel type.
 * @return description of channel type.
 */
static const char *get_type_str(enum mux_channel_type type)
{
	switch (type) {
	case MUX_CHANNEL_TYPE_NORMAL: return "NORMAL";
	case MUX_CHANNEL_TYPE_TCP_MASTER: return "TCP_MASTER";
	case MUX_CHANNEL_TYPE_TCP_SLAVE: return "TCP_SLAVE";
	default: return "UNKNOWN";
	}
}

static void tcp_slave_queue_timer_cb(struct pomp_timer *timer, void *userdata)
{
	struct mux_channel *channel = userdata;
	struct mux_ctrl_msg ctrl_msg;
	int ret, pending;

	if (!channel->tcpslave.ack_req) {
		pomp_timer_clear(channel->tcpslave.queue_timer);
		return;
	}

	ret = ioctl(channel->tcpslave.fd, TIOCOUTQ, &pending);
	if (ret < 0) {
		MUX_LOGE("ioctl(TIOCOUTQ) error: %s", strerror(errno));
		return;
	}

	/* check if no bytes pending */
	if (pending != 0)
		return;

	/* stop timer */
	pomp_timer_clear(channel->tcpslave.queue_timer);
	channel->tcpslave.ack_req = 0;

	/* send ack */
	MUX_LOGD("slave 0x%08x: send ack", channel->chanid);
	memset(&ctrl_msg, 0, sizeof(ctrl_msg));
	ctrl_msg.id = MUX_CTRL_MSG_ID_CHANNEL_TCP_ACK;
	ctrl_msg.chanid = channel->chanid;
	mux_send_ctrl_msg(channel->ctx, &ctrl_msg);
}

/**
 * Create a new channel structure.
 * @param ctx : context to associate with channel.
 * @param type : type of channel.
 * @param chanid : channel id.
 * @param cb : function to call when data are received for the given channel.
 * @param userdata : userd data given to callback.
 * @return created channel or NULL in case of error.
 */
static struct mux_channel *mux_channel_new(struct mux_ctx *ctx,
		enum mux_channel_type type, uint32_t chanid,
		mux_channel_cb_t cb, void *userdata)
{
	struct mux_channel *channel = NULL;

	/* Allocate channel structure */
	channel = calloc(1, sizeof(*channel));
	if (channel == NULL)
		return NULL;

	/* Initialize channel structure */
	channel->type = type;
	channel->ctx = ctx;
	channel->loop = mux_get_loop(ctx);
	channel->chanid = chanid;
	channel->cb = cb;
	channel->userdata = userdata;

	switch (channel->type) {
	case MUX_CHANNEL_TYPE_NORMAL:
		break;
	case MUX_CHANNEL_TYPE_TCP_MASTER:
		channel->tcpmaster.ctx = NULL;
		channel->tcpmaster.conn = NULL;
		channel->tcpmaster.state = MUX_TCP_STATE_IDLE;
		channel->tcpmaster.remoteport = 0;
		channel->tcpmaster.remotehost = NULL;
		channel->tcpmaster.isftpctrl = 0;
		channel->tcpmaster.ftpdatachan = NULL;
		channel->tcpmaster.tx_ack_bytes = 0;
		channel->tcpmaster.waiting_ack = 0;
		break;
	case MUX_CHANNEL_TYPE_TCP_SLAVE:
		channel->tcpslave.ctx = NULL;
		channel->tcpslave.conn = NULL;
		channel->tcpslave.state = MUX_TCP_STATE_IDLE;
		channel->tcpslave.flushing = 0;
		channel->tcpslave.send_queue_empty = 1;
		channel->tcpslave.ack_req = 0;
		channel->tcpslave.queue_timer = pomp_timer_new(
				mux_get_loop(ctx),
				&tcp_slave_queue_timer_cb, channel);
		if (!channel->tcpslave.queue_timer) {
			free(channel);
			return NULL;
		}
		break;
	}

	return channel;
}

/**
 * Destroy a channel structure.
 * @param channel : channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_destroy(struct mux_channel *channel)
{
	if (channel == NULL)
		return -EINVAL;

	if (!channel->stopped)
		return -EBUSY;

	/* Free resources */
	if (channel->queue != NULL)
		mux_queue_destroy(channel->queue);

	if (channel->type == MUX_CHANNEL_TYPE_TCP_MASTER)
		free(channel->tcpmaster.remotehost);

	if (channel->type == MUX_CHANNEL_TYPE_TCP_SLAVE)
		pomp_timer_destroy(channel->tcpslave.queue_timer);

	free(channel);
	return 0;
}

/**
 * Open a channel.
 * @param ctx : mux context.
 * @param type : type of channel.
 * @param chanid : channel id.
 * @param cb : function to call when data are received for the given channel.
 * @param userdata : userd data given to callback.
 * @param channel : created channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_open_internal(struct mux_ctx *ctx,
		enum mux_channel_type type, uint32_t chanid,
		mux_channel_cb_t cb, void *userdata,
		struct mux_channel **channel)
{
	int res = 0;
	struct mux_ctrl_msg ctrl_msg;
	MUX_LOGI("Opening channel 0x%08x", chanid);

	if (ctx == NULL || channel == NULL)
		return -EINVAL;

	/* Allocate a new channel object */
	*channel = mux_channel_new(ctx, type, chanid, cb, userdata);
	if (*channel == NULL)
		return -ENOMEM;

	/* Add it in context */
	res = mux_add_channel(ctx, *channel);
	if (res < 0)
		goto error;

	/* Send message on control channel */
	memset(&ctrl_msg, 0, sizeof(ctrl_msg));
	ctrl_msg.id = MUX_CTRL_MSG_ID_CHANNEL_OPEN;
	ctrl_msg.chanid = chanid;
	ctrl_msg.args[0] = type;
	res = mux_send_ctrl_msg(ctx, &ctrl_msg);
	if (res < 0)
		goto error;

	return 0;

	/* Cleanup in case of error */
error:
	if (*channel != NULL) {
		mux_channel_stop(*channel);
		mux_remove_channel(ctx, *channel);
		mux_channel_destroy(*channel);
	}
	*channel = NULL;
	return res;
}

/**
 * Close a channel.
 * @param channel : channel.
 * @param do_destroy  : notify peer on channel close, remove and destroy it
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_close_internal(struct mux_channel *channel,
			int do_destroy)
{
	struct mux_ctrl_msg ctrl_msg;
	MUX_LOGD("Closing channel 0x%08x", channel->chanid);

	/* Stop it if needed */
	if (!channel->stopped)
		mux_channel_stop(channel);

	/* Close data channel of ftp master */
	if (channel->type == MUX_CHANNEL_TYPE_TCP_MASTER
			&& channel->tcpmaster.isftpctrl
			&& channel->tcpmaster.ftpdatachan != NULL) {
		mux_channel_close_internal(channel->tcpmaster.ftpdatachan,
				do_destroy);
		channel->tcpmaster.ftpdatachan = NULL;
	}

	if (channel->type == MUX_CHANNEL_TYPE_TCP_SLAVE)
		pomp_timer_clear(channel->tcpslave.queue_timer);

	if (do_destroy) {
		/* Send message on control channel (ignore errors) */
		memset(&ctrl_msg, 0, sizeof(ctrl_msg));
		ctrl_msg.id = MUX_CTRL_MSG_ID_CHANNEL_CLOSE;
		ctrl_msg.chanid = channel->chanid;
		ctrl_msg.args[0] = channel->type;
		mux_send_ctrl_msg(channel->ctx, &ctrl_msg);

		/* Remove it from context and free resources */
		mux_remove_channel(channel->ctx, channel);
		mux_channel_destroy(channel);
	}

	return 0;
}

/**
 * Open a slave tcp channel associated with a master one.
 * @param ctx : mux context.
 * @param masterid : id of master channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_open_tcp_slave(struct mux_ctx *ctx, uint32_t masterid)
{
	struct mux_channel *channel = NULL;
	return mux_channel_open_internal(ctx, MUX_CHANNEL_TYPE_TCP_SLAVE,
			GET_SLAVE_ID(masterid), NULL, NULL, &channel);
}

/**
 * Close a slave tcp channel associated with a master one.
 * @param ctx : mux context.
 * @param masterid : id of master channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_close_tcp_slave(struct mux_ctx *ctx, uint32_t masterid)
{
	struct mux_channel *channel = NULL;
	channel = mux_find_channel(ctx, GET_SLAVE_ID(masterid));
	if (channel == NULL)
		return -ENOENT;
	return mux_channel_close(ctx, GET_SLAVE_ID(masterid));
}

/**
 * Called when the slave tcp channel is connected to the remote address.
 * @param ctx : mux context.
 * @param slaveid : id of slave channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_tcp_connected(struct mux_ctx *ctx, uint32_t slaveid)
{
	struct mux_channel *channel = NULL;

	/* Search channel, must exist and be a tcp master */
	channel = mux_find_channel(ctx, GET_MASTER_ID(slaveid));
	if (channel == NULL)
		return -ENOENT;
	if (channel->type != MUX_CHANNEL_TYPE_TCP_MASTER)
		return -EINVAL;

	if (channel->tcpmaster.state != MUX_TCP_STATE_IDLE) {
		MUX_LOGI("master 0x%08x: slave connected", channel->chanid);
		channel->tcpmaster.state = MUX_TCP_STATE_CONNECTED;
	}
	return 0;
}

/**
 * Called when the slave tcp channel is disconnected from the remote address.
 * @param ctx : mux context.
 * @param slaveid : id of slave channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_tcp_disconnected(struct mux_ctx *ctx, uint32_t slaveid)
{
	struct mux_channel *channel = NULL;

	/* Search channel, must exist and be a tcp master */
	channel = mux_find_channel(ctx, GET_MASTER_ID(slaveid));
	if (channel == NULL)
		return -ENOENT;
	if (channel->type != MUX_CHANNEL_TYPE_TCP_MASTER)
		return -EINVAL;

	if (channel->tcpmaster.state != MUX_TCP_STATE_IDLE) {
		MUX_LOGI("master 0x%08x: slave disconnected", channel->chanid);
		channel->tcpmaster.state = MUX_TCP_STATE_CONNECTING;
		channel->tcpmaster.waiting_ack = 0;
		channel->tcpmaster.tx_ack_bytes = 0;
		if (channel->tcpmaster.conn != NULL)
			pomp_conn_disconnect(channel->tcpmaster.conn);
	}
	return 0;
}

/**
 * Called when the master tcp channel request an ack.
 * slave channel must send all pending data before sending the ack.
 * @param ctx : mux context.
 * @param id : id of remote channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_tcp_request_ack(struct mux_ctx *ctx, uint32_t masterid)
{
	struct mux_channel *channel = NULL;

	/* Search channel, must exist and be a tcp slave */
	channel = mux_find_channel(ctx, GET_SLAVE_ID(masterid));
	if (channel == NULL)
		return -ENOENT;
	if (channel->type != MUX_CHANNEL_TYPE_TCP_SLAVE)
		return -EINVAL;

	channel->tcpslave.ack_req = 1;
	MUX_LOGD("slave 0x%08x: delay ack", channel->chanid);
	if (channel->tcpslave.send_queue_empty) {
		/* pomp has written all data, wait kernel socket send them */
		pomp_timer_set_periodic(channel->tcpslave.queue_timer,
				MUX_CHANNEL_TCP_SLAVE_FIFO_TIMEOUT,
				MUX_CHANNEL_TCP_SLAVE_FIFO_TIMEOUT);
	}

	return 0;
}

/**
 * Called when the slave tcp channel has sent a tcp ack.
 * master channel can now resume tx operation.
 * @param ctx : mux context.
 * @param id : id of remote channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_tcp_ack(struct mux_ctx *ctx, uint32_t slaveid)
{
	struct mux_channel *channel = NULL;

	/* Search channel, must exist and be a tcp master */
	channel = mux_find_channel(ctx, GET_MASTER_ID(slaveid));
	if (channel == NULL)
		return -ENOENT;
	if (channel->type != MUX_CHANNEL_TYPE_TCP_MASTER)
		return -EINVAL;

	if (channel->tcpmaster.waiting_ack) {
		channel->tcpmaster.tx_ack_bytes = 0;
		channel->tcpmaster.waiting_ack = 0;
		pomp_conn_resume_read(channel->tcpmaster.conn);
	}

	return 0;
}


/**
 * Check if a received buffer from a ftp control connection contains an
 * EPSV (extended passive mode) response. If yes, extract port information,
 * create a new tcp connection and modify the response to give the local port.
 * @param channel : channel.
 * @param buf : buffer to check.
 * @return a modified version of the buffer or NULL if no EPSV response was
 * found. Caller shall unref the buffer when done.
 */
static struct pomp_buffer *master_check_ftp_epsv(struct mux_channel *channel,
		struct pomp_buffer *buf)
{
	int res = 0;
	const void *data = NULL;
	const char *datastr = NULL;
	size_t len = 0, i = 0, j = 0, portlen = 0;
	int remoteport = -1;
	uint16_t localport = 0;
	uint32_t ftpdatachanid = 0;
	struct pomp_buffer *newbuf = NULL;
	void *newdata = NULL;
	char *newdatastr = NULL;
	size_t newlen = 0, newcapacity;

	static const char prefix[] = "EPSV ok (|||";
	static const char suffix[] = "|)\r\n";
	static const size_t prefixlen = sizeof(prefix) - 1;
	static const size_t suffixlen = sizeof(suffix) - 1;

	/* Get data from buffer */
	res = pomp_buffer_get_cdata(buf, &data, &len, NULL);
	if (res < 0)
		return NULL;
	datastr = data;

	/* TODO: check for response code 229, the 'EPSV ok' string is
	 * specific to busybox ftpd
	 * The '|' separator is not mandatory but recommended by RFC2428 */

	/* Check for 'EPSV ok (|||%u|)\r\n' string
	 * It assume that the buffer contains a full line (no fragmentation)
	 * The loop is also not optimal but datastr is not null terminated
	 * and there is no 'strnstr' function available... */
	for (i = 0; i + suffixlen + prefixlen <= len; i++) {
		if (strncmp(datastr + i, prefix, prefixlen) != 0)
			continue;
		i += prefixlen;
		for (j = i; j + suffixlen <= len; j++) {
			if (strncmp(datastr + j, suffix, suffixlen) != 0)
				continue;
			remoteport = atoi(datastr + i);
			break;
		}
		break;
	}

	/* No match found or invalid port */
	if (remoteport <= 0 || remoteport >= 65536)
		return NULL;

	/* If there is already a data channel for this ftp connection,
	 * close it */
	if (channel->tcpmaster.ftpdatachan != NULL)
		mux_channel_close_internal(channel->tcpmaster.ftpdatachan, 1);

	channel->tcpmaster.ftpdatachan = NULL;

	/* Open a new channel for data connection */
	if (mux_channel_open_tcp(channel->ctx,
			channel->tcpmaster.remotehost, remoteport,
			&localport, &ftpdatachanid) < 0) {
		goto error;
	}
	channel->tcpmaster.ftpdatachan = mux_find_channel(
			channel->ctx, ftpdatachanid);

	/* At this stage, i points to start of port num and j after port num
	 * Allocate a new buffer to patch response (+5 is to ensure room
	 * for new local port) */
	newbuf = pomp_buffer_new(len + 5);
	if (newbuf == NULL)
		goto error;
	if (pomp_buffer_get_data(newbuf, &newdata, &newlen, &newcapacity))
		goto error;
	newdatastr = newdata;

	/* Patch buffer */
	MUX_LOGI("master 0x%08x: replace %u by %u in EPSV response",
			channel->chanid, remoteport, localport);
	memcpy(newdatastr, datastr, i);
	portlen = snprintf(newdatastr + i, newcapacity - i, "%u", localport);
	memcpy(newdatastr + i + portlen, datastr + j, len - j);

	/* Set new data len */
	newlen = i + portlen + len - j;
	if (pomp_buffer_set_len(newbuf, newlen) < 0)
		goto error;
	log_buf("master mux->client (patched)", newbuf);
	return newbuf;

	/* Cleanup in case of error */
error:
	if (newbuf != NULL)
		pomp_buffer_unref(newbuf);
	return NULL;
}

/**
 * Tcp master channel event callback.
 */
static void master_event_cb(struct pomp_ctx *ctx,
		enum pomp_event event,
		struct pomp_conn *conn,
		const struct pomp_msg *msg,
		void *userdata)
{
	int res = 0;
	struct mux_channel *channel = userdata;
	struct mux_ctrl_msg ctrl_msg;
	struct pomp_buffer *buf = NULL;

	switch (event) {
	case POMP_EVENT_CONNECTED:
		/* Only accept one client at a time */
		if (channel->tcpmaster.conn != NULL) {
			MUX_LOGI("master 0x%08x: reject conn", channel->chanid);
			pomp_conn_disconnect(conn);
			return;
		}

		MUX_LOGI("master 0x%08x: client connected", channel->chanid);

		/* Send message on control channel */
		memset(&ctrl_msg, 0, sizeof(ctrl_msg));
		ctrl_msg.id = MUX_CTRL_MSG_ID_CHANNEL_TCP_CONNECT;
		ctrl_msg.chanid = channel->chanid;
		ctrl_msg.args[0] = INADDR_ANY;
		ctrl_msg.args[1] = channel->tcpmaster.remoteport;
		res = mux_send_ctrl_msg_with_payload(channel->ctx, &ctrl_msg,
				channel->tcpmaster.remotehost,
				strlen(channel->tcpmaster.remotehost) + 1);
		if (res < 0) {
			MUX_LOG_ERR("mux_send_ctrl_msg", -res);
			MUX_LOGI("master 0x%08x: reject conn", channel->chanid);
			pomp_conn_disconnect(conn);
			return;
		}

		channel->tcpmaster.conn = conn;
		channel->tcpmaster.waiting_ack = 0;
		channel->tcpmaster.tx_ack_bytes = 0;

		/* Write data received on mux while connecting */
		while (mux_queue_try_get_buf(channel->queue, &buf) == 0) {
			pomp_conn_send_raw_buf(conn, buf);
			pomp_buffer_unref(buf);
			buf = NULL;
		}

		break;

	case POMP_EVENT_DISCONNECTED:
		if (channel->tcpmaster.conn != conn)
			return;

		MUX_LOGI("master 0x%08x: client disconnected", channel->chanid);
		channel->tcpmaster.conn = NULL;

		/* Stop associated data channel for ftp ctrl */
		if (channel->tcpmaster.isftpctrl &&
				channel->tcpmaster.ftpdatachan != NULL) {
			mux_channel_stop(channel->tcpmaster.ftpdatachan);
		}

		/* Send message on control channel (ignore errors) */
		if (channel->tcpmaster.state == MUX_TCP_STATE_CONNECTED) {
			memset(&ctrl_msg, 0, sizeof(ctrl_msg));
			ctrl_msg.id = MUX_CTRL_MSG_ID_CHANNEL_TCP_DISCONNECT;
			ctrl_msg.chanid = channel->chanid;
			mux_send_ctrl_msg(channel->ctx, &ctrl_msg);
			channel->tcpmaster.state = MUX_TCP_STATE_CONNECTING;
			channel->tcpmaster.waiting_ack = 0;
			channel->tcpmaster.tx_ack_bytes = 0;
		}
		break;

	case POMP_EVENT_MSG:
		/* Never received for raw context */
		break;
	}
}

/**
 * Tcp master channel data callback.
 */
static void master_raw_cb(struct pomp_ctx *ctx,
		struct pomp_conn *conn,
		struct pomp_buffer *buf,
		void *userdata)
{
	int res = 0;
	size_t len;
	struct mux_ctrl_msg ctrl_msg;
	struct mux_channel *channel = userdata;

	/* Get data len */
	res = pomp_buffer_get_cdata(buf, NULL, &len, NULL);
	if (res < 0)
		return;

	if (channel->tcpmaster.waiting_ack)
		MUX_LOGW("encode while waiting ack: %zu", len);

	/* Send data */
	log_buf("master client->mux", buf);
	res = mux_encode(channel->ctx, channel->chanid, buf);
	if (res < 0) {
		MUX_LOG_ERR("mux_encode", -res);
		return;
	}

	/* update number of tx bytes sent */
	channel->tcpmaster.tx_ack_bytes += len;
	if (channel->tcpmaster.tx_ack_bytes < MUX_CHANNEL_TCP_ACK_BYTES_INTL)
		return;

	/* if channel already waiting ack do nothing */
	if (channel->tcpmaster.waiting_ack)
		return;

	/* request ACK on control channel */
	memset(&ctrl_msg, 0, sizeof(ctrl_msg));
	ctrl_msg.id = MUX_CTRL_MSG_ID_CHANNEL_TCP_REQ_ACK;
	ctrl_msg.chanid = channel->chanid;
	res = mux_send_ctrl_msg(channel->ctx, &ctrl_msg);
	if (res < 0) {
		MUX_LOG_ERR("ctrl_msg.CHANNEL_TCP_REQ_ACK", -res);
		return;
	}

	/* switch to ack wait state & suspend read */
	channel->tcpmaster.waiting_ack = 1;
	pomp_conn_suspend_read(conn);
	MUX_LOGD("master 0x%08x: waiting ack %d bytes", channel->chanid,
			channel->tcpmaster.tx_ack_bytes);
}

/**
 * Tcp slave channel event callback.
 */
static void slave_event_cb(struct pomp_ctx *ctx,
		enum pomp_event event,
		struct pomp_conn *conn,
		const struct pomp_msg *msg,
		void *userdata)
{
	int res = 0;
	struct mux_channel *channel = userdata;
	struct mux_ctrl_msg ctrl_msg;
	struct pomp_buffer *buf = NULL;

	switch (event) {
	case POMP_EVENT_CONNECTED:
		MUX_LOGI("slave 0x%08x: server connected",
				GET_MASTER_ID(channel->chanid));

		/* Send message on control channel */
		memset(&ctrl_msg, 0, sizeof(ctrl_msg));
		ctrl_msg.id = MUX_CTRL_MSG_ID_CHANNEL_TCP_CONNECTED;
		ctrl_msg.chanid = channel->chanid;
		res = mux_send_ctrl_msg(channel->ctx, &ctrl_msg);
		if (res < 0) {
			MUX_LOG_ERR("ctrl_msg.CHANNEL_TCP_CONNECTED", -res);
			pomp_conn_disconnect(conn);
			return;
		}

		/* We are now fully connected */
		channel->tcpslave.conn = conn;
		channel->tcpslave.state = MUX_TCP_STATE_CONNECTED;
		channel->tcpslave.send_queue_empty = 1;
		channel->tcpslave.ack_req = 0;

		/* Write data received on while connecting */
		while (mux_queue_try_get_buf(channel->queue, &buf) == 0) {
			pomp_conn_send_raw_buf(conn, buf);
			pomp_buffer_unref(buf);
			buf = NULL;
		}

		break;

	case POMP_EVENT_DISCONNECTED:
		MUX_LOGI("slave 0x%08x: server disconnected",
				GET_MASTER_ID(channel->chanid));

		/* Send message on control channel (ignore errors) */
		if (channel->tcpslave.state == MUX_TCP_STATE_CONNECTED) {
			memset(&ctrl_msg, 0, sizeof(ctrl_msg));
			ctrl_msg.id = MUX_CTRL_MSG_ID_CHANNEL_TCP_DISCONNECTED;
			ctrl_msg.chanid = channel->chanid;
			mux_send_ctrl_msg(channel->ctx, &ctrl_msg);
			channel->tcpslave.ack_req = 0;
		}
		if (channel->tcpslave.flushing) {
			/* This will trigger the abort of pending buffer, then
			 * slave_send_cb will finish the disconnection */
			channel->tcpslave.conn = NULL;
			pomp_ctx_stop(ctx);
			channel->tcpslave.state = MUX_TCP_STATE_IDLE;
			channel->tcpslave.ack_req = 0;
		} else {
			/* Context will handle reconnection */
			channel->tcpslave.conn = NULL;
			channel->tcpslave.state = MUX_TCP_STATE_CONNECTING;
			channel->tcpslave.send_queue_empty = 1;
			channel->tcpslave.ack_req = 0;
		}
		break;

	case POMP_EVENT_MSG:
		/* Never received for raw context */
		break;
	}
}

/**
 * Tcp slave channel data callback.
 */
static void slave_raw_cb(struct pomp_ctx *ctx,
		struct pomp_conn *conn,
		struct pomp_buffer *buf,
		void *userdata)
{
	int res = 0;
	struct mux_channel *channel = userdata;

	/* Send data */
	log_buf("slave server->mux", buf);
	res = mux_encode(channel->ctx, channel->chanid, buf);
	if (res < 0)
		MUX_LOG_ERR("mux_encode", -res);
}

/**
 * Tcp slave disconnect in idle callback.
 */
static void slave_disconnect_idle_cb(void *userdata)
{
	struct mux_channel *channel = userdata;

	MUX_LOGI("chanid=0x%08x: queue empty, disconnect", channel->chanid);
	channel->tcpslave.flushing = 0;

	mux_channel_disconnect_tcp_slave(channel->ctx,
			GET_MASTER_ID(channel->chanid));
}

/**
 * Tcp slave channel send callback.
 */
static void slave_send_cb(struct pomp_ctx *ctx,
		struct pomp_conn *conn,
		struct pomp_buffer *buf,
		uint32_t status,
		void *cookie,
		void *userdata)
{
	struct mux_channel *channel = userdata;

	if ((status & POMP_SEND_STATUS_QUEUE_EMPTY) != 0) {
		/* Queue is empty */
		channel->tcpslave.send_queue_empty = 1;

		/* if flushing was in progress, register a
		 * function to do the disconnection */
		if (channel->tcpslave.flushing) {
			MUX_LOGI("slave 0x%08x: flushing %s",
				channel->chanid,
				(status & POMP_SEND_STATUS_ABORTED) ?
				"aborted" : "completed");
			pomp_loop_idle_add(channel->loop,
					&slave_disconnect_idle_cb, channel);
		} else if (channel->tcpslave.ack_req &&
			  (status & POMP_SEND_STATUS_ABORTED) == 0) {
			/* start polling kernel socket buffer */
			pomp_timer_set_periodic(channel->tcpslave.queue_timer,
				MUX_CHANNEL_TCP_SLAVE_FIFO_TIMEOUT,
				MUX_CHANNEL_TCP_SLAVE_FIFO_TIMEOUT);
		}
	} else {
		/* Queue not empty */
		channel->tcpslave.send_queue_empty = 0;
	}
}

static void slave_tcp_socket_cb(struct pomp_ctx *ctx,
		int fd, enum pomp_socket_kind kind,
		void *userdata)
{
	struct mux_channel *channel = userdata;
	channel->tcpslave.fd = fd;
}

/**
 * Connect slave tcp channel to remote address.
 * @param ctx : mux context.
 * @param masterid : id of master channel.
 * @param remoteaddr : remote address to connect to (IPv4, host byte order).
 * @param remoteport : remote port to connect to.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_connect_tcp_slave(struct mux_ctx *ctx,
		uint32_t masterid,
		uint32_t remoteaddr, uint16_t remoteport)
{
	int res = 0;
	struct mux_channel *channel = NULL;
	struct sockaddr_in addr;

	/* Search slave channel associated with master channel */
	channel = mux_find_channel(ctx, GET_SLAVE_ID(masterid));
	if (channel == NULL)
		return -ENOENT;

	/* Are we idle ? */
	if (channel->tcpslave.ctx != NULL)
		return -EBUSY;

	/* Create queue used to save received data on mux while waiting for
	 * connection to server */
	channel->queue = mux_queue_new(0);
	if (channel->queue == NULL) {
		res = -ENOMEM;
		goto error;
	}

	/* Create context and make it raw */
	channel->tcpslave.ctx = pomp_ctx_new_with_loop(&slave_event_cb,
			channel, channel->loop);
	if (channel->tcpslave.ctx == NULL)
		return -ENOMEM;
	res = pomp_ctx_set_raw(channel->tcpslave.ctx, &slave_raw_cb);
	if (res < 0)
		goto error;
	res = pomp_ctx_set_send_cb(channel->tcpslave.ctx, &slave_send_cb);
	if (res < 0)
		goto error;

	/* Disable keepalive */
	res = pomp_ctx_setup_keepalive(channel->tcpslave.ctx, 0, 0, 0, 0);
	if (res < 0)
		goto error;

	/* Setup address */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(remoteaddr);
	addr.sin_port = htons(remoteport);

	/* Add socket cb to retrieve socket fd */
	channel->tcpslave.fd = -1;
	pomp_ctx_set_socket_cb(channel->tcpslave.ctx, &slave_tcp_socket_cb);

	/* Start connecting
	 * set state BEFORE call, connection can succeed now */
	channel->tcpslave.state = MUX_TCP_STATE_CONNECTING;
	channel->tcpslave.send_queue_empty = 1;
	res = pomp_ctx_connect(channel->tcpslave.ctx,
			(const struct sockaddr *)&addr, sizeof(addr));
	if (res < 0) {
		MUX_LOG_ERR("pomp_ctx_connect", -res);
		goto error;
	}

	return 0;

	/* Cleanup in case of error */
error:
	if (channel->tcpslave.ctx != NULL) {
		pomp_ctx_destroy(channel->tcpslave.ctx);
		channel->tcpslave.ctx = NULL;
	}
	channel->tcpslave.state = MUX_TCP_STATE_IDLE;
	return res;
}

/**
 * Disonnect slave tcp channel from remote address.
 * @param ctx : mux context.
 * @param masterid : id of master channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_disconnect_tcp_slave(struct mux_ctx *ctx,
		uint32_t masterid)
{
	struct mux_channel *channel = NULL;

	/* Search slave channel associated with master channel */
	channel = mux_find_channel(ctx, GET_SLAVE_ID(masterid));
	if (channel == NULL)
		return -ENOENT;

	/* if slave is connected and send queue is not empty, do nothing, just
	 * wait for queue to become empty */
	if (channel->tcpslave.state == MUX_TCP_STATE_CONNECTED &&
			!channel->tcpslave.send_queue_empty) {
		MUX_LOGI("chanid=0x%08x: queue not empty, flush",
				channel->chanid);
		channel->tcpslave.flushing = 1;
		channel->tcpslave.ack_req = 0;
		pomp_timer_clear(channel->tcpslave.queue_timer);
		return 0;
	} else if (channel->tcpslave.flushing) {
		return 0;
	}

	if (channel->queue != NULL) {
		mux_queue_stop(channel->queue);
		mux_queue_destroy(channel->queue);
		channel->queue = NULL;
	}

	if (channel->tcpslave.ctx != NULL) {
		pomp_ctx_stop(channel->tcpslave.ctx);
		pomp_ctx_destroy(channel->tcpslave.ctx);
		channel->tcpslave.ctx = NULL;
	}
	channel->tcpslave.state = MUX_TCP_STATE_IDLE;
	channel->tcpslave.ack_req = 0;
	pomp_timer_clear(channel->tcpslave.queue_timer);

	return 0;
}

/*
 * See documentation in public header.
 */
int mux_channel_open(struct mux_ctx *ctx, uint32_t chanid,
		mux_channel_cb_t cb, void *userdata)
{
	int res = 0;
	struct mux_channel *channel = NULL;

	mux_loop_acquire(ctx, 0);
	res = mux_channel_open_internal(ctx, MUX_CHANNEL_TYPE_NORMAL,
			chanid, cb, userdata, &channel);
	mux_loop_release(ctx);

	return res;
}

/*
 * See documentation in public header.
 */
int mux_channel_close(struct mux_ctx *ctx, uint32_t chanid)
{
	int res = 0;
	struct mux_channel *channel = NULL;

	if (ctx == NULL || chanid == 0)
		return -EINVAL;

	mux_loop_acquire(ctx, 0);

	/* Search channel, must exist */
	channel = mux_find_channel(ctx, chanid);
	if (channel != NULL)
		res = mux_channel_close_internal(channel, 1);
	else
		res = -ENOENT;

	mux_loop_release(ctx);
	return res;
}

/*
 * See documentation in public header.
 */
int mux_channel_open_tcp(struct mux_ctx *ctx,
		const char *remotehost, uint16_t remoteport,
		uint16_t *localport, uint32_t *chanid)
{
	int res = 0;
	struct mux_channel *channel = NULL;
	struct sockaddr_in addr;
	const struct sockaddr *local_addr = NULL;
	uint32_t addrlen = 0;

	if (ctx == NULL || localport == NULL || chanid == NULL ||
		remotehost == NULL)
		return -EINVAL;

	mux_loop_acquire(ctx, 0);

	/* Search a free channel */
	*chanid = 1023 + random() % 65535;
	do {
		(*chanid)++;
		channel = mux_find_channel(ctx, *chanid);
	} while (channel != NULL);

	/* Open it */
	res = mux_channel_open_internal(ctx, MUX_CHANNEL_TYPE_TCP_MASTER,
			*chanid, NULL, NULL, &channel);
	if (res < 0)
		goto error;

	/* Create queue used to save received data on mux while waiting for
	 * connection to slave */
	channel->queue = mux_queue_new(0);
	if (channel->queue == NULL) {
		res = -ENOMEM;
		goto error;
	}

	/* Create context and make it raw */
	channel->tcpmaster.ctx = pomp_ctx_new_with_loop(&master_event_cb,
			channel, channel->loop);
	if (channel->tcpmaster.ctx == NULL)
		return -ENOMEM;
	res = pomp_ctx_set_raw(channel->tcpmaster.ctx, &master_raw_cb);
	if (res < 0)
		goto error;

	/* Disable keepalive */
	res = pomp_ctx_setup_keepalive(channel->tcpmaster.ctx, 0, 0, 0, 0);
	if (res < 0)
		goto error;

	/* Setup address (bind to a random port) */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	addrlen = sizeof(addr);

	/* set state BEFORE listen call, connection can succeed now
	 * but without knowing the port it might be a bit difficult ;) */
	channel->tcpmaster.state = MUX_TCP_STATE_CONNECTING;
	channel->tcpmaster.remoteport = remoteport;
	channel->tcpmaster.remotehost = strdup(remotehost);
	if (!channel->tcpmaster.remotehost) {
		res = -ENOMEM;
		goto error;
	}

	/* Start listening */
	res = pomp_ctx_listen(channel->tcpmaster.ctx,
			(const struct sockaddr *)&addr, addrlen);
	if (res < 0) {
		MUX_LOG_ERR("pomp_ctx_listen", -res);
		goto error;
	}

	/* Retrieve bound local port */
	local_addr = pomp_ctx_get_local_addr(channel->tcpmaster.ctx, &addrlen);
	if (local_addr == NULL || addrlen < sizeof(struct sockaddr_in)) {
		MUX_LOGE("Invalid bound local address");
		goto error;
	}
	if (local_addr->sa_family != AF_INET) {
		MUX_LOGE("Invalid bound local address family");
		goto error;
	}
	*localport = ntohs(((const struct sockaddr_in *)local_addr)->sin_port);

	mux_loop_release(ctx);
	return 0;

	/* Cleanup in case of error */
error:
	if (channel != NULL)
		mux_channel_close(ctx, *chanid);
	*localport = 0;
	*chanid = 0;
	mux_loop_release(ctx);
	return res;
}

/*
 * See documentation in public header.
 */
int mux_channel_open_ftp(struct mux_ctx *ctx,
		const char *remotehost, uint16_t remoteport,
		uint16_t *localport, uint32_t *chanid)
{
	int res = 0;
	struct mux_channel *channel = NULL;

	mux_loop_acquire(ctx, 0);

	/* Open the tcp connection for control */
	res = mux_channel_open_tcp(ctx, remotehost, remoteport,
			localport, chanid);
	if (res < 0)
		goto out;

	/* Find back the channel structure */
	channel = mux_find_channel(ctx, *chanid);
	if (channel == NULL) {
		mux_channel_close(ctx, *chanid);
		res = -ENOENT;
		goto out;
	}

	/* Remember it is a ftp control connection */
	channel->tcpmaster.isftpctrl = 1;

out:
	mux_loop_release(ctx);
	return res;
}

/*
 * See documentation in public header.
 */
int mux_channel_alloc_queue(struct mux_ctx *ctx, uint32_t chanid,
		uint32_t depth, struct mux_queue **queue)
{
	struct mux_channel *channel = NULL;
	if (ctx == NULL || chanid == 0 || queue == NULL)
		return -EINVAL;

	/* Search channel, must exist */
	channel = mux_find_channel(ctx, chanid);
	if (channel == NULL)
		return -ENOENT;

	/* Make sure a queue is not already present */
	if (channel->queue != NULL)
		return -EPERM;

	/* Allocate queue */
	channel->queue = mux_queue_new(depth);
	if (channel->queue == NULL)
		return -ENOMEM;

	*queue = channel->queue;
	return 0;
}

/**
 * Stop a channel.
 * @param channel : channel
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_channel_stop(struct mux_channel *channel)
{
	if (channel == NULL)
		return -EINVAL;

	channel->stopped = 1;

	if (channel->queue != NULL)
		mux_queue_stop(channel->queue);

	switch (channel->type) {
	case MUX_CHANNEL_TYPE_NORMAL:
		break;

	case MUX_CHANNEL_TYPE_TCP_MASTER:
		if (channel->tcpmaster.ctx != NULL) {
			pomp_ctx_stop(channel->tcpmaster.ctx);
			pomp_ctx_destroy(channel->tcpmaster.ctx);
			channel->tcpmaster.ctx = NULL;
			channel->tcpmaster.conn = NULL;
		}
		channel->tcpmaster.state = MUX_TCP_STATE_IDLE;
		break;

	case MUX_CHANNEL_TYPE_TCP_SLAVE:
		if (channel->tcpslave.ctx != NULL) {
			pomp_ctx_stop(channel->tcpslave.ctx);
			pomp_ctx_destroy(channel->tcpslave.ctx);
			channel->tcpslave.ctx = NULL;
			channel->tcpslave.conn = NULL;
		}
		channel->tcpslave.state = MUX_TCP_STATE_IDLE;
		pomp_loop_idle_remove(channel->loop, &slave_disconnect_idle_cb,
				channel);

		break;
	}

	return 0;
}

/**
 * Put a recived buffer on a channel.
 * @param channel : channel
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_channel_put_buf(struct mux_channel *channel, struct pomp_buffer *buf)
{
	int res = 0;
	struct pomp_conn *conn = NULL;
	struct pomp_buffer *newbuf = NULL;

	if (channel == NULL || buf == NULL)
		return -EINVAL;

	/* Is it data for a slave tcp connection ? */
	if (channel->type == MUX_CHANNEL_TYPE_TCP_SLAVE) {
		log_buf("slave mux->server", buf);
		conn = channel->tcpslave.conn;
		if (conn == NULL)
			return mux_queue_put_buf(channel->queue, buf);
		return pomp_conn_send_raw_buf(conn, buf);
	}

	/* Is it data for a master tcp connection ? */
	if (channel->type == MUX_CHANNEL_TYPE_TCP_MASTER) {
		log_buf("master mux->client", buf);
		conn = channel->tcpslave.conn;
		if (conn == NULL)
			return mux_queue_put_buf(channel->queue, buf);
		if (channel->tcpmaster.isftpctrl) {
			newbuf = master_check_ftp_epsv(channel, buf);
			if (newbuf != NULL) {
				res = pomp_conn_send_raw_buf(conn, newbuf);
				pomp_buffer_unref(newbuf);
				return res;
			}
		}
		return pomp_conn_send_raw_buf(conn, buf);
	}

	/* If a queue is associated, put buffer in it */
	if (channel->queue != NULL)
		return mux_queue_put_buf(channel->queue, buf);

	/* Is there a callback associated with channel ? */
	if (channel->cb != NULL) {
		(*channel->cb) (channel->ctx, channel->chanid,
				MUX_CHANNEL_DATA, buf, channel->userdata);
		return 0;
	}

	/* Finally, notify buffer to context */
	return mux_notify_buf(channel->ctx, channel->chanid, buf);
}


/**
 * Reset channels
 * @param ctx : mux context.
 */
static void mux_channel_ctrl_reset(struct mux_ctx *ctx)
{
	struct mux_channel *channels = NULL;
	struct mux_channel *channel, *next = NULL;

	/* get all channels */
	channels = mux_remove_channels(ctx);

	/* close all channels */
	channel = channels;
	while (channel) {
		mux_channel_close_internal(channel, 0);
		channel = channel->next;
	}

	/* notify channel reset by peer */
	channel = channels;
	while (channel) {
		if (channel->cb)
			(*channel->cb) (channel->ctx, channel->chanid,
					MUX_CHANNEL_RESET, NULL,
					channel->userdata);
		next = channel->next;
		/* destroy channel */
		mux_channel_destroy(channel);
		channel = next;
	}
}


/**
 * Notify reception of a message on control channel.
 * @param ctx : mux context.
 * @param msg : received message.
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_channel_recv_ctrl_msg(struct mux_ctx *ctx,
		const struct mux_ctrl_msg *msg,
		const void *payload,
		size_t size)
{
	const char *hostname;
	uint32_t hostaddr;
	int ret;
	struct mux_channel *channel;

	switch (msg->id) {
	case MUX_CTRL_MSG_ID_CHANNEL_OPEN:
		MUX_LOGI("CHANNEL_OPEN chanid=0x%08x type=%s",
				msg->chanid, get_type_str(msg->args[0]));
		if (msg->args[0] == MUX_CHANNEL_TYPE_TCP_MASTER)
			mux_channel_open_tcp_slave(ctx, msg->chanid);
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_CLOSE:
		MUX_LOGI("CHANNEL_CLOSE chanid=0x%08x type=%s",
				msg->chanid, get_type_str(msg->args[0]));
		if (msg->args[0] == MUX_CHANNEL_TYPE_TCP_MASTER)
			mux_channel_close_tcp_slave(ctx, msg->chanid);
		/* Send a reset callback to the channel */
		channel = mux_find_channel(ctx, msg->chanid);
		if (channel && channel->cb)
			(*channel->cb) (channel->ctx, channel->chanid,
					MUX_CHANNEL_RESET, NULL,
					channel->userdata);
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_TCP_CONNECT:

		MUX_LOGI("CHANNEL_TCP_CONNECT chanid=0x%08x addr=%08x:%u",
				msg->chanid, msg->args[0], msg->args[1]);

		/* get hostname if any address is given as remote address */
		if (msg->args[0] == INADDR_ANY) {
			hostname = payload;
			/* ensure hostname is a valid string null terminated */
			if (!hostname || size == 0 ||
			    hostname[size - 1] != '\0') {
				MUX_LOGE("malformated host (%zd bytes)", size);
				return 0;
			}

			/* first try to convert hostname as
			 * IPv4 quad-dotted format */
			hostaddr = inet_addr(hostname);
			if (hostaddr == INADDR_NONE) {
				/* not a valid IPv4 quad-dotted format
				 * convert hostname to host address */
				ret = mux_get_host_address(ctx, hostname,
						&hostaddr);
				if (ret < 0) {
					MUX_LOGE("can't found '%s' host "
						 "address", hostname);
					return 0;
				} else {
					MUX_LOGI("host '%s' -> %08x",
						hostname, hostaddr);
				}
			}
		} else {
			hostaddr = msg->args[0];
		}

		mux_channel_connect_tcp_slave(ctx, msg->chanid,
				hostaddr, msg->args[1]);
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_TCP_DISCONNECT:
		MUX_LOGI("CHANNEL_TCP_DISCONNECT chanid=0x%08x", msg->chanid);
		mux_channel_disconnect_tcp_slave(ctx, msg->chanid);
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_TCP_CONNECTED:
		MUX_LOGI("CHANNEL_TCP_CONNECTED chanid=0x%08x", msg->chanid);
		mux_channel_tcp_connected(ctx, msg->chanid);
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_TCP_DISCONNECTED:
		MUX_LOGI("CHANNEL_TCP_DISCONNECTED chanid=0x%08x", msg->chanid);
		mux_channel_tcp_disconnected(ctx, msg->chanid);
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_TCP_REQ_ACK:
		MUX_LOGI("CHANNEL_TCP_REQ_ACK chanid=0x%08x", msg->chanid);
		mux_channel_tcp_request_ack(ctx, msg->chanid);
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_TCP_ACK:
		MUX_LOGI("CHANNEL_TCP_ACK chanid=0x%08x", msg->chanid);
		mux_channel_tcp_ack(ctx, msg->chanid);
		break;

	case MUX_CTRL_MSG_ID_RESET:
		MUX_LOGI("RESET");
		mux_channel_ctrl_reset(ctx);
		break;

	default:
		MUX_LOGW("Unknown ctrl msg id %u", msg->id);
		break;
	}

	return 0;
}
