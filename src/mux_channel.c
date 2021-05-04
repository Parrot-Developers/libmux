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

#include "mux_priv.h"

#define MUX_CHANNEL_IP_ACK_BYTES_INTL (1024 * 1024) /* 1 MB */
#define MUX_CHANNEL_IP_SLAVE_FIFO_TIMEOUT 50 /* 50 ms */

static int mux_channel_disconnect_ip_slave(struct mux_ctx *ctx,
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
	case MUX_CHANNEL_TYPE_IP_MASTER: return "IP_MASTER";
	case MUX_CHANNEL_TYPE_IP_SLAVE: return "IP_SLAVE";
	default: return "UNKNOWN";
	}
}

/**
 * Retrieves socket pending data length.
 *
 * @param fd : socket file descriptor.
 * @return socket pending data length, negative errno value in case of error.
 */
static int socket_pending_data(int fd)
{
#ifdef __APPLE__
	uint32_t len;
	socklen_t max = sizeof(len);
	return getsockopt(fd, SOL_SOCKET, SO_NWRITE, &len, &max) < 0 ?
			-errno : (int)len;
#elif defined _WIN32
	return -ENOSYS;
#else /* !_WIN32 !__APPLE__ */
	uint32_t len;
	return ioctl(fd, TIOCOUTQ, &len) < 0 ? -errno : (int)len;
#endif /* !_WIN32 !__APPLE__ */
}

static void ip_slave_queue_timer_cb(struct pomp_timer *timer, void *userdata)
{
	struct mux_channel *channel = userdata;
	struct mux_ctrl_msg ctrl_msg;

	if (!channel->ipslave.ack_req) {
		pomp_timer_clear(channel->ipslave.queue_timer);
		return;
	}

	int pending = socket_pending_data(channel->ipslave.fd);
	if (pending < 0 && pending != -ENOSYS)
		MUX_LOG_ERR("socket_pending_data", pending);

	/* check if no bytes pending */
	/* In error case, assume there is no pending data. */
	if (pending > 0)
		return;

	/* stop timer */
	pomp_timer_clear(channel->ipslave.queue_timer);
	channel->ipslave.ack_req = 0;

	/* send ack */
	MUX_LOGD("slave 0x%08x: send ack", channel->chanid);
	memset(&ctrl_msg, 0, sizeof(ctrl_msg));
	ctrl_msg.id = MUX_CTRL_MSG_ID_CHANNEL_IP_ACK;
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
	case MUX_CHANNEL_TYPE_IP_MASTER:
		channel->ipmaster.conn = NULL;
		channel->ipmaster.state = MUX_IP_STATE_IDLE;
		channel->ipmaster.remoteport = 0;
		channel->ipmaster.remoteaddr = 0;
		channel->ipmaster.ftp_data.proxy = NULL;
		channel->ipmaster.tx_ack_bytes = 0;
		channel->ipmaster.waiting_ack = 0;
		break;
	case MUX_CHANNEL_TYPE_IP_SLAVE:
		channel->ipslave.ctx = NULL;
		channel->ipslave.conn = NULL;
		channel->ipslave.state = MUX_IP_STATE_IDLE;
		channel->ipslave.flushing = 0;
		channel->ipslave.send_queue_empty = 1;
		channel->ipslave.ack_req = 0;
		channel->ipslave.queue_timer = pomp_timer_new(
				mux_get_loop(ctx),
				&ip_slave_queue_timer_cb, channel);
		if (!channel->ipslave.queue_timer) {
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

	if (channel->type == MUX_CHANNEL_TYPE_IP_SLAVE)
		pomp_timer_destroy(channel->ipslave.queue_timer);

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
	if (type == MUX_CHANNEL_TYPE_NORMAL &&
	    (IS_MASTER_ID(chanid) || IS_SLAVE_ID(chanid)))
		return -EINVAL;
	if (type == MUX_CHANNEL_TYPE_IP_MASTER && !IS_MASTER_ID(chanid))
		return -EINVAL;
	if (type == MUX_CHANNEL_TYPE_IP_SLAVE && !IS_SLAVE_ID(chanid))
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
	struct mux_ip_proxy_protocol *protocol = &channel->ipmaster.protocol;
	if (channel->type == MUX_CHANNEL_TYPE_IP_MASTER &&
	    protocol->application == MUX_IP_PROXY_APPLICATION_FTP &&
	    channel->ipmaster.ftp_data.proxy != NULL) {
		mux_ip_proxy_destroy(channel->ipmaster.ftp_data.proxy);
		channel->ipmaster.ftp_data.proxy = NULL;
	}

	if (channel->type == MUX_CHANNEL_TYPE_IP_SLAVE)
		pomp_timer_clear(channel->ipslave.queue_timer);

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
 * Open a slave ip channel associated with a master one.
 * @param ctx : mux context.
 * @param masterid : id of master channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_open_ip_slave(struct mux_ctx *ctx, uint32_t masterid)
{
	struct mux_channel *channel = NULL;
	return mux_channel_open_internal(ctx, MUX_CHANNEL_TYPE_IP_SLAVE,
			GET_SLAVE_ID(masterid), NULL, NULL, &channel);
}

/**
 * Close a slave ip channel associated with a master one.
 * @param ctx : mux context.
 * @param masterid : id of master channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_close_ip_slave(struct mux_ctx *ctx, uint32_t masterid)
{
	struct mux_channel *channel = NULL;
	channel = mux_find_channel(ctx, GET_SLAVE_ID(masterid));
	if (channel == NULL)
		return -ENOENT;
	return mux_channel_close(ctx, GET_SLAVE_ID(masterid));
}

/**
 * Called when the slave ip channel is connected to the remote address.
 * @param ctx : mux context.
 * @param slaveid : id of slave channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_ip_connected(struct mux_ctx *ctx, uint32_t slaveid,
		uint16_t peerport)
{
	struct mux_channel *channel = NULL;

	/* Search channel, must exist and be a ip master */
	channel = mux_find_channel(ctx, GET_MASTER_ID(slaveid));
	if (channel == NULL)
		return -ENOENT;
	if (channel->type != MUX_CHANNEL_TYPE_IP_MASTER)
		return -EINVAL;

	if (channel->ipmaster.state != MUX_IP_STATE_IDLE) {
		MUX_LOGI("master 0x%08x: slave connected", channel->chanid);
		channel->ipmaster.peerport = peerport;
		channel->ipmaster.state = MUX_IP_STATE_CONNECTED;

		mux_ip_proxy_channel_connected(channel->ipmaster.ip_proxy,
				peerport);
	}
	return 0;
}

/**
 * Called when the slave ip channel is disconnected from the remote address.
 * @param ctx : mux context.
 * @param slaveid : id of slave channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_ip_disconnected(struct mux_ctx *ctx, uint32_t slaveid)
{
	struct mux_channel *channel = NULL;

	/* Search channel, must exist and be a ip master */
	channel = mux_find_channel(ctx, GET_MASTER_ID(slaveid));
	if (channel == NULL)
		return -ENOENT;
	if (channel->type != MUX_CHANNEL_TYPE_IP_MASTER)
		return -EINVAL;

	if (channel->ipmaster.state != MUX_IP_STATE_IDLE) {
		MUX_LOGI("master 0x%08x: slave disconnected", channel->chanid);
		channel->ipmaster.state = MUX_IP_STATE_CONNECTING;
		channel->ipmaster.waiting_ack = 0;
		channel->ipmaster.tx_ack_bytes = 0;
		if (channel->ipmaster.conn != NULL)
			pomp_conn_disconnect(channel->ipmaster.conn);
	}
	return 0;
}

/**
 * Called when the master ip channel request an ack.
 * slave channel must send all pending data before sending the ack.
 * @param ctx : mux context.
 * @param id : id of remote channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_ip_request_ack(struct mux_ctx *ctx, uint32_t masterid)
{
	struct mux_channel *channel = NULL;

	/* Search channel, must exist and be a ip slave */
	channel = mux_find_channel(ctx, GET_SLAVE_ID(masterid));
	if (channel == NULL)
		return -ENOENT;
	if (channel->type != MUX_CHANNEL_TYPE_IP_SLAVE)
		return -EINVAL;

	channel->ipslave.ack_req = 1;
	MUX_LOGD("slave 0x%08x: delay ack", channel->chanid);
	if (channel->ipslave.send_queue_empty) {
		/* pomp has written all data, wait kernel socket send them */
		pomp_timer_set_periodic(channel->ipslave.queue_timer,
				1,
				MUX_CHANNEL_IP_SLAVE_FIFO_TIMEOUT);
	}

	return 0;
}

/**
 * Called when the slave ip channel has sent a ip ack.
 * master channel can now resume tx operation.
 * @param ctx : mux context.
 * @param id : id of remote channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_ip_ack(struct mux_ctx *ctx, uint32_t slaveid)
{
	struct mux_channel *channel = NULL;

	/* Search channel, must exist and be a ip master */
	channel = mux_find_channel(ctx, GET_MASTER_ID(slaveid));
	if (channel == NULL)
		return -ENOENT;
	if (channel->type != MUX_CHANNEL_TYPE_IP_MASTER)
		return -EINVAL;

	/* No acknowledgement in waiting. */
	if (!channel->ipmaster.waiting_ack)
		return 0;

	/* Resume the connection. */
	channel->ipmaster.tx_ack_bytes = 0;
	channel->ipmaster.waiting_ack = 0;
	int res = pomp_conn_resume_read(channel->ipmaster.conn);
	if (res < 0) {
		MUX_LOG_ERR("pomp_conn_resume_read", -res);
		return res;
	}

	if (channel->ipmaster.protocol.transport == MUX_IP_PROXY_TRANSPORT_UDP)
		channel->ipmaster.conn = NULL;

	return 0;
}

/** */
static void ftp_data_proxy_open(struct mux_ip_proxy *self, uint16_t localport,
			void *userdata)
{
	int res;
	void *newdata = NULL;
	size_t newLen = 0;
	size_t newcapacity = 0;
	char *newdatastr = NULL;
	int portlen = 0;

	struct mux_channel *channel = userdata;

	res = pomp_buffer_get_data(channel->ipmaster.ftp_data.buf,
			&newdata, &newLen, &newcapacity);
	if (res < 0)
		goto error;

	newdatastr = newdata;

	/* Patch buffer */
	MUX_LOGI("master 0x%08x: replace %u by %u in EPSV response",
			channel->chanid, channel->ipmaster.ftp_data.remoteport,
			localport);
	portlen = snprintf(newdatastr + newLen, newcapacity - newLen, "%u",
			localport);
	res = pomp_buffer_set_len(channel->ipmaster.ftp_data.buf,
			newLen + portlen);
	if (res < 0)
		goto error;

	res = pomp_buffer_append_buffer(channel->ipmaster.ftp_data.buf,
			channel->ipmaster.ftp_data.buf_postport);
	if (res < 0)
		goto error;

	log_buf("master mux->client (patched)", channel->ipmaster.ftp_data.buf);
	res = pomp_conn_send_raw_buf(channel->ipmaster.conn,
			channel->ipmaster.ftp_data.buf);
	if (res < 0)
		goto error;

	pomp_buffer_unref(channel->ipmaster.ftp_data.buf);
	channel->ipmaster.ftp_data.buf = NULL;

	pomp_buffer_unref(channel->ipmaster.ftp_data.buf_postport);
	channel->ipmaster.ftp_data.buf_postport = NULL;
	return;

error:
	MUX_LOG_ERR("failed to send modified ftp EPSV", -res);

	mux_ip_proxy_destroy(channel->ipmaster.ftp_data.proxy);
	channel->ipmaster.ftp_data.proxy = NULL;

	pomp_buffer_unref(channel->ipmaster.ftp_data.buf);
	channel->ipmaster.ftp_data.buf = NULL;

	pomp_buffer_unref(channel->ipmaster.ftp_data.buf_postport);
	channel->ipmaster.ftp_data.buf_postport = NULL;
}

static void ftp_data_proxy_close(struct mux_ip_proxy *self, void *userdata)
{
}

/**
 * Check if a received buffer from a ftp control connection contains an
 * EPSV (extended passive mode) response. If yes, extract port information,
 * create a new ip connection and modify the response to give the local port.
 * @param channel : channel.
 * @param buf : buffer to check.
 * @return '1' if data contains an EPSV else '0' or negative errno value
 *         in case of error.
 */
static int master_check_ftp_epsv(struct mux_channel *channel,
		struct pomp_buffer *buf)
{
	int res = 0;
	const void *data = NULL;
	const char *datastr = NULL;
	size_t len = 0, i = 0, j = 0;
	int remoteport = -1;
	const char *remotehost = NULL;

	static const char prefix[] = "EPSV ok (|||";
	static const char suffix[] = "|)\r\n";
	static const size_t prefixlen = sizeof(prefix) - 1;
	static const size_t suffixlen = sizeof(suffix) - 1;

	/* Get data from buffer */
	res = pomp_buffer_get_cdata(buf, &data, &len, NULL);
	if (res < 0)
		return 0;
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
		return 0;

	/* If there is already a data channel for this ftp connection,
	 * close it */
	if (channel->ipmaster.ftp_data.proxy != NULL)
		mux_ip_proxy_destroy(channel->ipmaster.ftp_data.proxy);

	channel->ipmaster.ftp_data.proxy = NULL;

	remotehost = mux_ip_proxy_get_remote_host(channel->ipmaster.ip_proxy);

	struct mux_ip_proxy_info info = {
		.protocol.transport = MUX_IP_PROXY_TRANSPORT_TCP,
		.remote_host = remotehost,
		.remote_port = remoteport,
	};

	struct mux_ip_proxy_cbs cbs = {
		.open = &ftp_data_proxy_open,
		.close = &ftp_data_proxy_close,
		.userdata = channel,
	};

	/* Open a new channel for data connection */
	res = mux_ip_proxy_new(channel->ctx, &info, &cbs, -1,
			&channel->ipmaster.ftp_data.proxy);
	if (res < 0)
		goto error;

	/*  */
	channel->ipmaster.ftp_data.buf = pomp_buffer_new(len + 5);
	if (channel->ipmaster.ftp_data.buf == NULL) {
		res = -ENOMEM;
		goto error;
	}

	res = pomp_buffer_append_data(channel->ipmaster.ftp_data.buf,
			datastr, i);
	if (res < 0)
		goto error;

	/* Copy post port */
	channel->ipmaster.ftp_data.buf_postport =
			pomp_buffer_new_with_data(datastr + j, len - j);
	if (channel->ipmaster.ftp_data.buf_postport == NULL) {
		res = -ENOMEM;
		goto error;
	}

	channel->ipmaster.ftp_data.remoteport = remoteport;
	return 1;

	/* Cleanup in case of error */
error:

	if (channel->ipmaster.ftp_data.proxy != NULL) {
		mux_ip_proxy_destroy(channel->ipmaster.ftp_data.proxy);
		channel->ipmaster.ftp_data.proxy = NULL;
	}

	if (channel->ipmaster.ftp_data.buf != NULL) {
		pomp_buffer_unref(channel->ipmaster.ftp_data.buf);
		channel->ipmaster.ftp_data.buf = NULL;
	}

	if (channel->ipmaster.ftp_data.buf_postport != NULL) {
		pomp_buffer_unref(channel->ipmaster.ftp_data.buf_postport);
		channel->ipmaster.ftp_data.buf_postport = NULL;
	}
	return res;
}

int mux_channel_send_msg_ip_connect(struct mux_channel *channel)
{
	int res;

	/* Send message on control channel */
	struct mux_ctrl_msg ctrl_msg = {
		.id = MUX_CTRL_MSG_ID_CHANNEL_IP_CONNECT,
		.chanid = channel->chanid,
		.args = {
			channel->ipmaster.protocol.transport,
			channel->ipmaster.protocol.application,
			channel->ipmaster.remoteaddr,
			channel->ipmaster.remoteport,
		},
	};

	res = mux_send_ctrl_msg(channel->ctx, &ctrl_msg);
	if (res < 0) {
		MUX_LOG_ERR("mux_send_ctrl_msg", -res);
		return res;
	}

	return 0;
}

/**
 * See documentation in header.
 */
void mux_channel_ipmaster_event(struct mux_channel *channel,
		enum pomp_event event,
		struct pomp_conn *conn)
{
	int res = 0;
	struct mux_ctrl_msg ctrl_msg;
	struct pomp_buffer *buf = NULL;

	switch (event) {
	case POMP_EVENT_CONNECTED:
		/* Only accept one client at a time */
		if (channel->ipmaster.conn != NULL) {
			MUX_LOGI("master 0x%08x: reject conn", channel->chanid);
			pomp_conn_disconnect(conn);
			return;
		}

		MUX_LOGI("master 0x%08x: client connected", channel->chanid);

		/* Send message on control channel */
		res = mux_channel_send_msg_ip_connect(channel);
		if (res < 0) {
			MUX_LOGI("master 0x%08x: reject conn", channel->chanid);
			pomp_conn_disconnect(conn);
			return;
		}

		channel->ipmaster.conn = conn;
		channel->ipmaster.waiting_ack = 0;
		channel->ipmaster.tx_ack_bytes = 0;

		/* Write data received on mux while connecting */
		while (mux_queue_try_get_buf(channel->queue, &buf) == 0) {
			pomp_conn_send_raw_buf(conn, buf);
			pomp_buffer_unref(buf);
			buf = NULL;
		}

		break;

	case POMP_EVENT_DISCONNECTED:
		if (channel->ipmaster.conn != conn)
			return;

		MUX_LOGI("master 0x%08x: client disconnected", channel->chanid);
		channel->ipmaster.conn = NULL;

		/* Stop associated data channel for ftp ctrl */
		if (channel->ipmaster.protocol.application ==
				MUX_IP_PROXY_APPLICATION_FTP &&
		    channel->ipmaster.ftp_data.proxy != NULL) {
			mux_ip_proxy_destroy(
					channel->ipmaster.ftp_data.proxy);
			channel->ipmaster.ftp_data.proxy = NULL;
		}

		/* Send message on control channel (ignore errors) */
		if (channel->ipmaster.state == MUX_IP_STATE_CONNECTED) {
			memset(&ctrl_msg, 0, sizeof(ctrl_msg));
			ctrl_msg.id = MUX_CTRL_MSG_ID_CHANNEL_IP_DISCONNECT;
			ctrl_msg.chanid = channel->chanid;
			mux_send_ctrl_msg(channel->ctx, &ctrl_msg);
			channel->ipmaster.state = MUX_IP_STATE_CONNECTING;
			channel->ipmaster.waiting_ack = 0;
			channel->ipmaster.tx_ack_bytes = 0;
		}
		break;

	case POMP_EVENT_MSG:
		/* Never received for raw context */
		break;
	}
}

/**
 * See documentation in header.
 */
void mux_channel_ipmaster_raw(struct mux_channel *channel,
		struct pomp_conn *conn,
		struct pomp_buffer *buf)
{
	int res = 0;
	size_t len;
	struct mux_ctrl_msg ctrl_msg;

	/* Get data len */
	res = pomp_buffer_get_cdata(buf, NULL, &len, NULL);
	if (res < 0)
		return;

	if (channel->ipmaster.waiting_ack)
		MUX_LOGW("encode while waiting ack: %zu", len);

	/* Send data */
	log_buf("master client->mux", buf);
	res = mux_encode(channel->ctx, channel->chanid, buf);
	if (res < 0) {
		MUX_LOG_ERR("mux_encode", -res);
		return;
	}

	/* update number of tx bytes sent */
	channel->ipmaster.tx_ack_bytes += len;
	if (channel->ipmaster.tx_ack_bytes < MUX_CHANNEL_IP_ACK_BYTES_INTL)
		return;

	/* if channel already waiting ack do nothing */
	if (channel->ipmaster.waiting_ack)
		return;

	/* request ACK on control channel */
	memset(&ctrl_msg, 0, sizeof(ctrl_msg));
	ctrl_msg.id = MUX_CTRL_MSG_ID_CHANNEL_IP_REQ_ACK;
	ctrl_msg.chanid = channel->chanid;
	res = mux_send_ctrl_msg(channel->ctx, &ctrl_msg);
	if (res < 0) {
		MUX_LOG_ERR("ctrl_msg.CHANNEL_IP_REQ_ACK", -res);
		return;
	}

	/* Check and save the connection to suspend */
	switch (channel->ipmaster.protocol.transport) {
	case MUX_IP_PROXY_TRANSPORT_TCP:
		if (conn != channel->ipmaster.conn) {
			MUX_LOGE("Bad connection to suspend.");
			return;
		}
		break;

	case MUX_IP_PROXY_TRANSPORT_UDP:
		if (channel->ipmaster.conn != NULL) {
			MUX_LOGE("Connection already suspended.");
			return;
		}
		channel->ipmaster.conn = conn;
		break;
	default:
		MUX_LOGE("Unknown protocol.transport %d",
				channel->ipmaster.protocol.transport);
		return;
	}

	/* switch to ack wait state & suspend read */
	channel->ipmaster.waiting_ack = 1;
	pomp_conn_suspend_read(conn);
	MUX_LOGD("master 0x%08x: waiting ack %d bytes", channel->chanid,
			channel->ipmaster.tx_ack_bytes);
}

static int mux_channel_send_msg_ip_connected(struct mux_channel *channel,
		uint16_t localport)
{
	int res;

	/* Send message on control channel */
	struct mux_ctrl_msg ctrl_msg = {
		.id = MUX_CTRL_MSG_ID_CHANNEL_IP_CONNECTED,
		.chanid = channel->chanid,
		.args = {
			localport,
		},
	};
	res = mux_send_ctrl_msg(channel->ctx, &ctrl_msg);
	if (res < 0) {
		MUX_LOG_ERR("ctrl_msg.CHANNEL_IP_CONNECTED", -res);
		return res;
	}

	return 0;
}

/**
 * Ip slave channel event callback.
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
		res = mux_channel_send_msg_ip_connected(channel, 0);
		if (res < 0) {
			MUX_LOG_ERR("mux_channel_send_msg_ip_connected", -res);
			pomp_conn_disconnect(conn);
			return;
		}

		/* We are now fully connected */
		channel->ipslave.conn = conn;
		channel->ipslave.state = MUX_IP_STATE_CONNECTED;
		channel->ipslave.send_queue_empty = 1;

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
		if (channel->ipslave.state == MUX_IP_STATE_CONNECTED) {
			memset(&ctrl_msg, 0, sizeof(ctrl_msg));
			ctrl_msg.id = MUX_CTRL_MSG_ID_CHANNEL_IP_DISCONNECTED;
			ctrl_msg.chanid = channel->chanid;
			mux_send_ctrl_msg(channel->ctx, &ctrl_msg);
			channel->ipslave.ack_req = 0;
		}
		if (channel->ipslave.flushing) {
			/* This will trigger the abort of pending buffer, then
			 * slave_send_cb will finish the disconnection */
			channel->ipslave.conn = NULL;
			pomp_ctx_stop(ctx);
			channel->ipslave.state = MUX_IP_STATE_IDLE;
			channel->ipslave.ack_req = 0;
		} else {
			/* Context will handle reconnection */
			channel->ipslave.conn = NULL;
			channel->ipslave.state = MUX_IP_STATE_CONNECTING;
			channel->ipslave.send_queue_empty = 1;
			channel->ipslave.ack_req = 0;
		}
		break;

	case POMP_EVENT_MSG:
		/* Never received for raw context */
		break;
	}
}

/**
 * Ip slave channel data callback.
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
 * Ip slave disconnect in idle callback.
 */
static void slave_disconnect_idle_cb(void *userdata)
{
	struct mux_channel *channel = userdata;

	MUX_LOGI("chanid=0x%08x: queue empty, disconnect", channel->chanid);
	channel->ipslave.flushing = 0;

	mux_channel_disconnect_ip_slave(channel->ctx,
			GET_MASTER_ID(channel->chanid));
}

/**
 * Ip slave channel send callback.
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
		channel->ipslave.send_queue_empty = 1;

		/* if flushing was in progress, register a
		 * function to do the disconnection */
		if (channel->ipslave.flushing) {
			MUX_LOGI("slave 0x%08x: flushing %s",
				channel->chanid,
				(status & POMP_SEND_STATUS_ABORTED) ?
				"aborted" : "completed");
			pomp_loop_idle_add(channel->loop,
					&slave_disconnect_idle_cb, channel);
		} else if (channel->ipslave.ack_req &&
			  (status & POMP_SEND_STATUS_ABORTED) == 0) {
			/* start polling kernel socket buffer */
			pomp_timer_set_periodic(channel->ipslave.queue_timer,
				1,
				MUX_CHANNEL_IP_SLAVE_FIFO_TIMEOUT);
		}
	} else {
		/* Queue not empty */
		channel->ipslave.send_queue_empty = 0;
	}
}

static void slave_ip_socket_cb(struct pomp_ctx *ctx,
		int fd, enum pomp_socket_kind kind,
		void *userdata)
{
	struct mux_channel *channel = userdata;
	channel->ipslave.fd = fd;
}

/**
 * Connects ip slave on UDP transport protocol.
 *
 * @param channel : slave channel to connect.
 *
 * @return 0 in case of success, negative errno value in case of error.
 */
static int ip_slave_connect_udp(struct mux_channel *channel)
{
	int res;
	const struct sockaddr *local_addr;
	uint32_t local_addrlen = 0;
	uint16_t localport = 0;
	struct sockaddr_in bind_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = 0,
	};

	res = pomp_ctx_bind(channel->ipslave.ctx,
		(const struct sockaddr *)&bind_addr, sizeof(bind_addr));
	if (res < 0) {
		MUX_LOG_ERR("pomp_ctx_bind", -res);
		return res;
	}

	/* Retrieve bound local port */
	local_addr = pomp_ctx_get_local_addr(channel->ipslave.ctx,
			&local_addrlen);
	if (local_addr == NULL ||
		local_addrlen < sizeof(struct sockaddr_in)) {
		MUX_LOGE("Invalid bound local address");
		return res;
	}
	if (local_addr->sa_family != AF_INET) {
		MUX_LOGE("Invalid bound local address family");
		return res;
	}
	localport = ntohs(((const struct sockaddr_in *)
			local_addr)->sin_port);

	/* Send message on control channel */
	res = mux_channel_send_msg_ip_connected(channel, localport);
	if (res < 0) {
		MUX_LOG_ERR("mux_channel_send_msg_ip_connected", -res);
		return res;
	}

	/* We are now fully connected */
	channel->ipslave.state = MUX_IP_STATE_CONNECTED;
	channel->ipslave.send_queue_empty = 1;

	return 0;
}

/**
 * Connect slave ip channel to remote address.
 *
 * @param ctx : mux context.
 * @param masterid : id of master channel.
 * @param protocol : layers protocols.
 * @param remoteaddr : remote IPV4 address to connect to in network byte order.
 * @param remoteport : remote port to connect to in host byte order.
 *
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_connect_ip_slave(struct mux_ctx *ctx, uint32_t masterid,
		struct mux_ip_proxy_protocol *protocol,
		uint32_t remoteaddr, uint16_t remoteport)
{
	int res = 0;
	struct mux_channel *channel = NULL;
	struct sockaddr_in *addr = NULL;

	/* Search slave channel associated with master channel */
	channel = mux_find_channel(ctx, GET_SLAVE_ID(masterid));
	if (channel == NULL)
		return -ENOENT;

	/* Are we idle ? */
	if (channel->ipslave.ctx != NULL)
		return -EBUSY;

	/* Create queue used to save received data on mux while waiting for
	 * connection to server */
	channel->queue = mux_queue_new(0);
	if (channel->queue == NULL) {
		res = -ENOMEM;
		goto error;
	}

	/* Create context and make it raw */
	channel->ipslave.ctx = pomp_ctx_new_with_loop(&slave_event_cb,
			channel, channel->loop);
	if (channel->ipslave.ctx == NULL)
		return -ENOMEM;
	res = pomp_ctx_set_raw(channel->ipslave.ctx, &slave_raw_cb);
	if (res < 0)
		goto error;
	res = pomp_ctx_set_send_cb(channel->ipslave.ctx, &slave_send_cb);
	if (res < 0)
		goto error;

	/* Disable keepalive */
	res = pomp_ctx_setup_keepalive(channel->ipslave.ctx, 0, 0, 0, 0);
	if (res < 0)
		goto error;

	/* Add socket cb to retrieve socket fd */
	channel->ipslave.fd = -1;
	pomp_ctx_set_socket_cb(channel->ipslave.ctx, &slave_ip_socket_cb);

	/* Setup remote address */
	addr = (struct sockaddr_in *)&channel->ipslave.remoteaddr;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = remoteaddr;
	addr->sin_port = htons(remoteport);
	channel->ipslave.remoteaddrlen = sizeof(*addr);

	channel->ipslave.state = MUX_IP_STATE_CONNECTING;
	channel->ipslave.send_queue_empty = 1;
	channel->ipslave.protocol = *protocol;

	switch (protocol->transport) {
	case MUX_IP_PROXY_TRANSPORT_TCP:
		MUX_LOGI("proxy slave %s : connect",
			protocol->application == MUX_IP_PROXY_APPLICATION_FTP ?
					"FTP" : "TCP");
		res = pomp_ctx_connect(channel->ipslave.ctx,
				&channel->ipslave.remoteaddr,
				channel->ipslave.remoteaddrlen);
		if (res < 0) {
			MUX_LOG_ERR("pomp_ctx_connect", -res);
			goto error;
		}
		break;
	case MUX_IP_PROXY_TRANSPORT_UDP:
		res = ip_slave_connect_udp(channel);
		if (res < 0) {
			MUX_LOG_ERR("ip_slave_connect_udp", -res);
			goto error;
		}

		break;
	default:
		MUX_LOGE("proxy slave transport %d unknow",
				protocol->transport);
		goto error;
	}

	return 0;

	/* Cleanup in case of error */
error:
	if (channel->ipslave.ctx != NULL) {
		pomp_ctx_destroy(channel->ipslave.ctx);
		channel->ipslave.ctx = NULL;
	}
	channel->ipslave.state = MUX_IP_STATE_IDLE;
	return res;
}

/**
 * Disonnect slave ip channel from remote address.
 * @param ctx : mux context.
 * @param masterid : id of master channel.
 * @return 0 in case of success, negative errno value in case of error.
 */
static int mux_channel_disconnect_ip_slave(struct mux_ctx *ctx,
		uint32_t masterid)
{
	struct mux_channel *channel = NULL;

	/* Search slave channel associated with master channel */
	channel = mux_find_channel(ctx, GET_SLAVE_ID(masterid));
	if (channel == NULL)
		return -ENOENT;

	/* if slave is connected and send queue is not empty, do nothing, just
	 * wait for queue to become empty */
	if (channel->ipslave.state == MUX_IP_STATE_CONNECTED &&
			!channel->ipslave.send_queue_empty) {
		MUX_LOGI("chanid=0x%08x: queue not empty, flush",
				channel->chanid);
		channel->ipslave.flushing = 1;
		channel->ipslave.ack_req = 0;
		pomp_timer_clear(channel->ipslave.queue_timer);
		return 0;
	} else if (channel->ipslave.flushing) {
		return 0;
	}

	if (channel->queue != NULL) {
		mux_queue_stop(channel->queue);
		mux_queue_destroy(channel->queue);
		channel->queue = NULL;
	}

	if (channel->ipslave.ctx != NULL) {
		pomp_ctx_stop(channel->ipslave.ctx);
		pomp_ctx_destroy(channel->ipslave.ctx);
		channel->ipslave.ctx = NULL;
	}
	channel->ipslave.state = MUX_IP_STATE_IDLE;
	channel->ipslave.ack_req = 0;
	pomp_timer_clear(channel->ipslave.queue_timer);

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

	if (chanid == 0 || chanid >= IS_MASTER_ID_MIN)
		return -EINVAL;

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
int mux_channel_open_ip(struct mux_ctx *ctx,
		struct mux_ip_proxy_protocol *protcol,
		uint32_t remoteaddr, uint16_t remoteport, uint32_t *chanid)
{
	int res = 0;
	uint16_t rnd = 0;
	struct mux_channel *channel = NULL;

	if (ctx == NULL || chanid == NULL || remoteaddr == 0)
		return -EINVAL;

	mux_loop_acquire(ctx, 0);

	/* Search a free channel */
	res = futils_random16(&rnd);
	if (res < 0) {
		MUX_LOG_ERR("futils_random16", -res);
		goto error;
	}
	/* Start from a random valid id increased at the loop start. */
	*chanid = IS_MASTER_ID_MIN - 1 + rnd;
	do {
		(*chanid)++;
		channel = mux_find_channel(ctx, *chanid);
	} while (channel != NULL);

	/* Open it */
	res = mux_channel_open_internal(ctx, MUX_CHANNEL_TYPE_IP_MASTER,
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

	/* set state BEFORE listen call, connection can succeed now
	 * but without knowing the port it might be a bit difficult ;) */
	channel->ipmaster.state = MUX_IP_STATE_CONNECTING;
	channel->ipmaster.protocol = *protcol;
	channel->ipmaster.remoteport = remoteport;
	channel->ipmaster.remoteaddr = remoteaddr;

	mux_loop_release(ctx);
	return 0;

	/* Cleanup in case of error */
error:
	if (channel != NULL)
		mux_channel_close(ctx, *chanid);
	*chanid = 0;
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

	case MUX_CHANNEL_TYPE_IP_MASTER:
		MUX_LOGI("master 0x%08x: channel stopped",
			channel->chanid);
		channel->ipmaster.waiting_ack = 0;
		channel->ipmaster.tx_ack_bytes = 0;
		if (channel->ipmaster.conn != NULL)
			pomp_conn_disconnect(channel->ipmaster.conn);
		channel->ipmaster.state = MUX_IP_STATE_IDLE;
		break;

	case MUX_CHANNEL_TYPE_IP_SLAVE:
		if (channel->ipslave.ctx != NULL) {
			pomp_ctx_stop(channel->ipslave.ctx);
			pomp_ctx_destroy(channel->ipslave.ctx);
			channel->ipslave.ctx = NULL;
			channel->ipslave.conn = NULL;
		}
		channel->ipslave.state = MUX_IP_STATE_IDLE;
		pomp_loop_idle_remove(channel->loop, &slave_disconnect_idle_cb,
				channel);

		break;
	}

	return 0;
}

/**
 * Put a received buffer on a tcp master channel.
 */
static int ipmaster_tcp_put_buf(struct mux_channel *channel,
		struct pomp_buffer *buf)
{
	int res = 0;
	struct pomp_conn *conn = channel->ipmaster.conn;
	if (conn == NULL)
		return mux_queue_put_buf(channel->queue, buf);

	switch (channel->ipmaster.protocol.application) {
	case MUX_IP_PROXY_APPLICATION_FTP:
		/* Check if it is an epsv ftp command. */
		res = master_check_ftp_epsv(channel, buf);
		if (res < 0)
			MUX_LOG_ERR("master_check_ftp_epsv", -res);
		else if (res == 1) {
			/* Waiting ftp data proxy opening. */
			return 0;
		}
		/* It is not an epsv ftp command. */

		return pomp_conn_send_raw_buf(conn, buf);

	case MUX_IP_PROXY_APPLICATION_NONE:
		return pomp_conn_send_raw_buf(conn, buf);
	default:
		return -EPROTO;
	}
}

/**
 * Put a received buffer on a channel.
 * @param channel : channel
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_channel_put_buf(struct mux_channel *channel, struct pomp_buffer *buf)
{
	struct pomp_conn *conn = NULL;

	if (channel == NULL || buf == NULL)
		return -EINVAL;

	/* Is it data for a slave ip connection ? */
	if (channel->type == MUX_CHANNEL_TYPE_IP_SLAVE) {
		log_buf("slave mux->server", buf);

		switch (channel->ipslave.protocol.transport) {
		case MUX_IP_PROXY_TRANSPORT_TCP:
			conn = channel->ipslave.conn;
			if (conn == NULL)
				return mux_queue_put_buf(channel->queue, buf);

			return pomp_conn_send_raw_buf(conn, buf);
		case MUX_IP_PROXY_TRANSPORT_UDP:
			return pomp_ctx_send_raw_buf_to(channel->ipslave.ctx,
					buf, &channel->ipslave.remoteaddr,
					channel->ipslave.remoteaddrlen);
		default:
			MUX_LOGE("ip transport (%d) unknown",
					channel->ipslave.protocol.transport);
			return -EPROTO;
		}
	}

	/* Is it data for a master ip connection ? */
	if (channel->type == MUX_CHANNEL_TYPE_IP_MASTER) {
		log_buf("master mux->client", buf);

		switch (channel->ipmaster.protocol.transport) {
		case MUX_IP_PROXY_TRANSPORT_TCP:
			return ipmaster_tcp_put_buf(channel, buf);
		case MUX_IP_PROXY_TRANSPORT_UDP:
			return mux_ip_proxy_udp_local_send(
					channel->ipmaster.ip_proxy, buf);
		default:
			MUX_LOGE("ip transport (%d) unknown",
					channel->ipmaster.protocol.transport);
			return -EPROTO;
		}
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

int mux_send_proxy_ip_resolve_ack(struct mux_ctx *ctx, uint32_t proxy_id,
		struct mux_ip_proxy_protocol *protocol,
		const char *hostname, uint32_t hostaddr, uint16_t port)
{
	struct mux_ctrl_msg msg = {
		.id = MUX_CTRL_MSG_ID_PROXY_RESOLVE_REQ_ACK,
		.args = {proxy_id, protocol->transport, protocol->application,
				hostaddr, port},
	};
	size_t remotehost_len;
	int res;

	MUX_LOGI("%s proxyId: %u transport: %u application %u hostname: %s, "
		 "hostaddr: %u port: %u", __func__, proxy_id,
				protocol->transport, protocol->application,
				hostname, hostaddr, port);

	remotehost_len = strlen(hostname) + 1;
	res = mux_send_ctrl_msg_with_payload(ctx, &msg, hostname,
			remotehost_len);
	if (res < 0)
		return res;

	return 0;
}

static int ipslave_resolve(struct mux_ctx *ctx, uint32_t proxy_id,
		struct mux_ip_proxy_protocol *protocol,
		char *hostname, size_t size, uint16_t port)
{
	int res;
	uint32_t hostaddr;

	MUX_LOGI("%s proxyId: %u transport: %u application: %u "
		 "hostname: %s port: %u",
			__func__, proxy_id,
			protocol->transport, protocol->application,
			hostname, port);

	/* ensure hostname is a valid string null terminated */
	if (!hostname || size == 0 ||
		hostname[size - 1] != '\0') {
		MUX_LOGE("malformated host (%zd bytes)", size);
		return 0;
	}

	/* first try to convert hostname as IPv4 quad-dotted format */
	hostaddr = inet_addr(hostname);
	if (hostaddr == INADDR_NONE) {
		/* not a valid IPv4 quad-dotted format
		 * convert hostname to host address */
		res = mux_get_host_address(ctx, hostname, &hostaddr);
		if (res < 0 || hostaddr == INADDR_NONE) {
			MUX_LOGI("can't found '%s' host address", hostname);
			/* Force INADDR_NONE to notify a failure. */
			hostaddr = INADDR_NONE;
		}
	}

	if (hostaddr == INADDR_ANY) {
		/* Asynchronous resolution. */
		/* Add pending resolve, waiting host adding. */
		res = mux_add_pending_resolve(ctx, proxy_id, protocol,
				hostname, port);
		if (res < 0) {
			MUX_LOG_ERR("mux_add_pending_resolve", -res);
			return res;
		}

		MUX_LOGI("waitting adding of host address for '%s'", hostname);
	} else {
		MUX_LOGI("host '%s' -> %08x", hostname, hostaddr);

		res = mux_send_proxy_ip_resolve_ack(ctx, proxy_id, protocol,
				hostname, hostaddr, port);
		if (res < 0) {
			MUX_LOG_ERR("mux_send_proxy_ip_resolve_ack", -res);
			return res;
		}
	}

	return 0;
}

static int ipmaster_resolve_ack(struct mux_ctx *ctx, uint32_t proxy_id,
		struct mux_ip_proxy_protocol *protocol,
		char *hostname, uint32_t addr, uint16_t port)
{
	struct mux_ip_proxy *proxy;

	MUX_LOGI("%s proxyId: %u transport: %u application: %u "
		 "hostname: %s addr: %u port: %u",
			__func__, proxy_id,
			protocol->transport, protocol->application,
			hostname, addr, port);

	proxy = mux_ip_proxy_from_id(ctx, proxy_id);
	if (proxy == NULL) {
		MUX_LOGE("proxy id(%u) not found", proxy_id);
		return -ENODEV;
	}

	return mux_ip_proxy_resolution(proxy, hostname, addr);
}

static int ipslave_set_remote_update(struct mux_ctx *ctx,
		uint32_t masterid, uint32_t remotaddr, uint16_t remoteport)
{
	struct mux_ctrl_msg msg = {
		.id = MUX_CTRL_MSG_ID_PROXY_REMOTE_UPDATE_REQ_ACK,
		.args = {remotaddr, remoteport},
	};

	int res;
	struct sockaddr_in *addr = NULL;
	struct mux_channel *channel = NULL;
	MUX_LOGI("%s masterid: %u remoteport: %u",
			__func__, masterid, remoteport);

	/* Search channel, must exist and be a ip slave udp */
	channel = mux_find_channel(ctx, GET_SLAVE_ID(masterid));
	if (channel == NULL)
		return -ENOENT;

	if (channel->type != MUX_CHANNEL_TYPE_IP_SLAVE ||
	    channel->ipslave.protocol.transport != MUX_IP_PROXY_TRANSPORT_UDP)
		return -EINVAL;

	/* Update remote address */
	addr = ((struct sockaddr_in *) &channel->ipslave.remoteaddr);
	addr->sin_addr.s_addr = remotaddr;
	addr->sin_port = htons(remoteport);

	msg.chanid = channel->chanid;
	res = mux_send_ctrl_msg(ctx, &msg);
	if (res < 0)
		return res;

	return 0;
}

static int ipmaster_set_remote_update_ack(struct mux_ctx *ctx,
		uint32_t slaveid, uint32_t remotaddr, uint16_t remoteport)
{
	struct mux_channel *channel = NULL;
	MUX_LOGI("%s slaveid: %u remoteport: %u",
			__func__, slaveid, remoteport);

	/* Search channel, must exist and be a ip master */
	channel = mux_find_channel(ctx, GET_MASTER_ID(slaveid));
	if (channel == NULL)
		return -ENOENT;

	if (channel->type != MUX_CHANNEL_TYPE_IP_MASTER ||
	    channel->ipmaster.protocol.transport != MUX_IP_PROXY_TRANSPORT_UDP)
		return -EINVAL;

	return mux_ip_proxy_remote_update(channel->ipmaster.ip_proxy,
			remotaddr, remoteport);
}

static int mux_channel_send_tcp_disconnect(struct mux_ctx *ctx,
		uint32_t masterid)
{
	struct mux_ctrl_msg msg = {
		.id = MUX_CTRL_MSG_ID_CHANNEL_TCP_DISCONNECT,
	};
	int res;
	struct mux_channel *channel = NULL;

	/* Search channel, must exist and be a ip slave udp */
	channel = mux_find_channel(ctx, GET_SLAVE_ID(masterid));
	if (channel == NULL)
		return -ENOENT;

	msg.chanid = channel->chanid;
	res = mux_send_ctrl_msg(ctx, &msg);
	if (res < 0)
		return res;

	return 0;
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
	struct mux_channel *channel;
	struct mux_ip_proxy_protocol protocol = {0};
	int res = 0;

	switch (msg->id) {
	case MUX_CTRL_MSG_ID_HANDSHAKE:
		MUX_LOGI("MUX_CTRL_MSG_ID_HANDSHAKE "
			 "is an acknowledgement: %u version: %u",
				msg->args[0], msg->args[1]);
		res = mux_set_remote_version(ctx, msg->args[1]);
		if (res < 0)
			MUX_LOG_ERR("mux_set_remote_version", -res);

		if (!msg->args[0]) {
			/* Send handshake acknowledgment */
			res = mux_send_handshake(ctx, 1);
			if (res < 0)
				MUX_LOG_ERR("mux_send_handshake", -res);
		}
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_OPEN:
		MUX_LOGI("CHANNEL_OPEN chanid=0x%08x type=%s",
				msg->chanid, get_type_str(msg->args[0]));
		if (msg->args[0] == MUX_CHANNEL_TYPE_IP_MASTER) {
			res = mux_channel_open_ip_slave(ctx, msg->chanid);
			if (res < 0)
				MUX_LOG_ERR("mux_channel_open_ip_slave", -res);
		}
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_CLOSE:
		MUX_LOGI("CHANNEL_CLOSE chanid=0x%08x type=%s",
				msg->chanid, get_type_str(msg->args[0]));
		if (msg->args[0] == MUX_CHANNEL_TYPE_IP_MASTER)
			mux_channel_close_ip_slave(ctx, msg->chanid);
		/* Send a reset callback to the channel */
		channel = mux_find_channel(ctx, msg->chanid);
		if (channel && channel->cb)
			(*channel->cb) (channel->ctx, channel->chanid,
					MUX_CHANNEL_RESET, NULL,
					channel->userdata);
		break;

	case MUX_CTRL_MSG_ID_PROXY_RESOLVE_REQ:
		MUX_LOGI("MUX_CTRL_MSG_ID_PROXY_RESOLVE_REQ proxyId: %u "
			 "transport: %u application %u "
			 "hostname: %s remote port: %u",
					msg->args[0],
					msg->args[1], msg->args[2],
					(char *)payload, msg->args[3]);
		protocol.transport = msg->args[1];
		protocol.application = msg->args[2];
		res = ipslave_resolve(ctx, msg->args[0], &protocol,
				(char *)payload, size, msg->args[3]);
		if (res < 0)
			MUX_LOG_ERR("ipslave_resolve", -res);
		break;

	case MUX_CTRL_MSG_ID_PROXY_RESOLVE_REQ_ACK:
		MUX_LOGI("MUX_CTRL_MSG_ID_PROXY_RESOLVE_REQ_ACK "
			 "proxyId: %u transport: %u application %u "
			 "hostname: %s address: %u",
				msg->args[0], msg->args[1], msg->args[2],
				(char *)payload, msg->args[3]);
		protocol.transport = msg->args[1];
		protocol.application = msg->args[2];
		ipmaster_resolve_ack(ctx, msg->args[0], &protocol,
				(char *)payload, msg->args[3], msg->args[4]);
		break;

	case MUX_CTRL_MSG_ID_PROXY_REMOTE_UPDATE_REQ:
		MUX_LOGI("MUX_CTRL_MSG_ID_PROXY_REMOTE_UPDATE_REQ "
			 "chanid=0x%08x remote address: %u port: %u",
				msg->chanid, msg->args[0], msg->args[1]);
		res = ipslave_set_remote_update(ctx, msg->chanid, msg->args[0],
				msg->args[1]);
		if (res < 0)
			MUX_LOG_ERR("ipslave_set_remote_update", -res);
		break;

	case MUX_CTRL_MSG_ID_PROXY_REMOTE_UPDATE_REQ_ACK:
		MUX_LOGI("MUX_CTRL_MSG_ID_PROXY_REMOTE_UPDATE_REQ_ACK "
			 "chanid=0x%08x remote address: %u port: %u",
				msg->chanid, msg->args[0], msg->args[1]);
		res = ipmaster_set_remote_update_ack(ctx, msg->chanid,
				msg->args[0], msg->args[1]);
		if (res < 0)
			MUX_LOG_ERR("ipmaster_set_remote_update_ack", -res);
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_IP_CONNECT:
		MUX_LOGI("CHANNEL_IP_CONNECT chanid=0x%08x "
			 "transport: %u application %u addr=%08x:%u",
				msg->chanid, msg->args[0], msg->args[1],
				msg->args[2], msg->args[3]);
		protocol.transport = msg->args[0];
		protocol.application = msg->args[1];
		res = mux_channel_connect_ip_slave(ctx, msg->chanid,
				&protocol, msg->args[2],
				msg->args[3]);
		if (res < 0)
			MUX_LOG_ERR("mux_channel_connect_ip_slave", -res);
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_IP_DISCONNECT:
		MUX_LOGI("CHANNEL_IP_DISCONNECT chanid=0x%08x", msg->chanid);
		mux_channel_disconnect_ip_slave(ctx, msg->chanid);
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_IP_CONNECTED:
		MUX_LOGI("CHANNEL_IP_CONNECTED chanid=0x%08x "
			 "slave localport: %d", msg->chanid, msg->args[0]);
		res = mux_channel_ip_connected(ctx, msg->chanid, msg->args[0]);
		if (res < 0)
			MUX_LOG_ERR("mux_channel_ip_connected", -res);
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_IP_DISCONNECTED:
		MUX_LOGI("CHANNEL_IP_DISCONNECTED chanid=0x%08x", msg->chanid);
		res = mux_channel_ip_disconnected(ctx, msg->chanid);
		if (res < 0)
			MUX_LOG_ERR("mux_channel_ip_disconnected", -res);
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_IP_REQ_ACK:
		MUX_LOGI("CHANNEL_IP_REQ_ACK chanid=0x%08x", msg->chanid);
		res = mux_channel_ip_request_ack(ctx, msg->chanid);
		if (res < 0)
			MUX_LOG_ERR("mux_channel_ip_request_ack", -res);
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_IP_ACK:
		MUX_LOGI("CHANNEL_IP_ACK chanid=0x%08x", msg->chanid);
		res = mux_channel_ip_ack(ctx, msg->chanid);
		if (res < 0)
			MUX_LOG_ERR("mux_channel_ip_ack", -res);
		break;

	case MUX_CTRL_MSG_ID_RESET:
		MUX_LOGI("RESET");
		mux_channel_ctrl_reset(ctx);
		break;

	case MUX_CTRL_MSG_ID_CHANNEL_TCP_CONNECT:
		MUX_LOGI("MUX_CTRL_MSG_ID_CHANNEL_TCP_CONNECT - DEPRECATED -"
			 " chanid=0x%08x ", msg->chanid);
		res = mux_channel_send_tcp_disconnect(ctx, msg->chanid);
		if (res < 0)
			MUX_LOG_ERR("mux_channel_send_tcp_disconnect", -res);
		break;

	default:
		MUX_LOGW("Unknown ctrl msg id %u", msg->id);
		break;
	}

	return res;
}
