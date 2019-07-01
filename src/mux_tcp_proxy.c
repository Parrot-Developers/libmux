/**
 * Copyright (c) 2017 Parrot Drones SAS
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
#include <futils/hash.h>
#include "mux_priv.h"

/** Mux Tcp Proxy */
struct mux_tcp_proxy {
	/* mux context */
	struct mux_ctx          *mux_ctx;
	/* pomp loop */
	struct pomp_loop        *ploop;
	/* pomp context */
	struct pomp_ctx         *pctx;
	/* remote host */
	char                    *remotehost;
	/* remote port */
	uint16_t                remoteport;
	/* hash table of connection fd to channel. */
	struct hash             conn_to_chann;
	/* local port. */
	uint16_t                localport;
	/* 1 if the proxy will be used to ftp otherwise 0. */
	int                     isftpctrl;
};

static int conn_to_chann(struct mux_tcp_proxy *tcp_proxy,
		struct pomp_conn *conn, struct mux_channel **channel)
{
	int res;
	int fd;

	if (tcp_proxy == NULL || conn == NULL || channel == NULL)
		return -EINVAL;

	fd = pomp_conn_get_fd(conn);

	res = hash_lookup(&tcp_proxy->conn_to_chann, (uint32_t) fd,
			(void **)channel);
	if (res < 0)
		return -ENOENT;

	return 0;
}

static int close_channel(struct mux_tcp_proxy *tcp_proxy,
		struct pomp_conn *conn)
{
	int res;
	int fd;
	struct mux_channel *channel = NULL;

	if (tcp_proxy == NULL)
		return -EINVAL;

	res = conn_to_chann(tcp_proxy, conn, &channel);
	if (res < 0)
		return res;

	mux_channel_close(tcp_proxy->mux_ctx, channel->chanid);

	fd = pomp_conn_get_fd(conn);
	hash_remove(&tcp_proxy->conn_to_chann, fd);

	return 0;
}

static int open_channel(struct mux_tcp_proxy *tcp_proxy,
		struct pomp_conn *conn)
{
	int res = 0;
	uint32_t chanid;
	struct mux_channel *channel = NULL;
	int fd;

	if (tcp_proxy == NULL || conn == NULL)
		return -EINVAL;

	fd = pomp_conn_get_fd(conn);

	mux_loop_acquire(tcp_proxy->mux_ctx, 0);
	res = mux_channel_open_tcp(tcp_proxy->mux_ctx,
			tcp_proxy->remotehost,
			tcp_proxy->remoteport, &chanid);
	if (res < 0) {
		mux_loop_release(tcp_proxy->mux_ctx);
		return res;
	}

	/* Find back the channel structure */
	channel = mux_find_channel(tcp_proxy->mux_ctx, chanid);
	if (channel == NULL) {
		res = -ENOENT;
		goto error;
	}

	channel->tcpmaster.isftpctrl = tcp_proxy->isftpctrl;

	res = hash_insert(&tcp_proxy->conn_to_chann, (uint32_t) fd, channel);
	if (res < 0)
		goto error;

	mux_loop_release(tcp_proxy->mux_ctx);
	return 0;

	/* Cleanup in case of error */
error:
	mux_channel_close(tcp_proxy->mux_ctx, chanid);
	mux_loop_release(tcp_proxy->mux_ctx);
	return res;
}

/**
 * event callback.
 */
static void tcp_proxy_event_cb(struct pomp_ctx *ctx,
		enum pomp_event event,
		struct pomp_conn *conn,
		const struct pomp_msg *msg,
		void *userdata)
{
	int res = 0;
	struct mux_tcp_proxy *tcp_proxy = userdata;
	struct mux_channel *channel = NULL;

	switch (event) {
	case POMP_EVENT_CONNECTED:

		res = open_channel(tcp_proxy, conn);
		if (res < 0) {
			MUX_LOG_ERR("open_channel", -res);
			break;
		}

		res = conn_to_chann(tcp_proxy, conn, &channel);
		if (res < 0) {
			MUX_LOG_ERR("conn_to_chann", -res);
			break;
		}

		mux_channel_tcpmaster_event(channel, event, conn);
		break;

	case POMP_EVENT_DISCONNECTED:

		res = conn_to_chann(tcp_proxy, conn, &channel);
		if (res < 0) {
			MUX_LOG_ERR("conn_to_chann", -res);
			break;
		}

		mux_channel_tcpmaster_event(channel, event, conn);

		res = close_channel(tcp_proxy, conn);
		if (res < 0)
			MUX_LOG_ERR("close_channel", -res);
		break;

	case POMP_EVENT_MSG:
		/* Never received for raw context */
		break;
	}

	/* If we had an error during a connected event, disconnect the socket */
	if (res < 0 && event == POMP_EVENT_CONNECTED)
		pomp_conn_disconnect(conn);
}

/**
 * data callback.
 */
static void tcp_proxy_raw_cb(struct pomp_ctx *ctx,
		struct pomp_conn *conn,
		struct pomp_buffer *buf,
		void *userdata)
{
	int res;
	struct mux_tcp_proxy *tcp_proxy = userdata;
	struct mux_channel *channel = NULL;

	res = conn_to_chann(tcp_proxy, conn, &channel);
	if (res < 0) {
		MUX_LOG_ERR("conn_to_chann", -res);
		return;
	}

	mux_channel_tcpmaster_raw(channel, conn, buf);
}

/**
 * See documentation in public header.
 */
int mux_tcp_proxy_new(struct mux_ctx *ctx,
		const char *remotehost, uint16_t remoteport, int isftpctrl,
		struct mux_tcp_proxy **ret_obj)
{
	int res = 0;
	struct mux_tcp_proxy *tcp_proxy;
	struct sockaddr_in addr;
	const struct sockaddr *local_addr = NULL;
	uint32_t addrlen = 0;

	if (ctx == NULL || ret_obj == NULL || remotehost == NULL)
		return -EINVAL;

	tcp_proxy = calloc(1, sizeof(*tcp_proxy));
	if (tcp_proxy == NULL)
		return -ENOMEM;

	mux_loop_acquire(ctx, 0);

	tcp_proxy->mux_ctx = ctx;
	mux_ref(ctx);

	tcp_proxy->ploop = mux_get_loop(ctx);
	tcp_proxy->isftpctrl = isftpctrl;

	res = hash_init(&tcp_proxy->conn_to_chann, 0);
	if (res < 0)
		goto error;

	/* Create context and make it raw */
	tcp_proxy->pctx = pomp_ctx_new_with_loop(&tcp_proxy_event_cb,
			tcp_proxy, tcp_proxy->ploop);
	if (tcp_proxy->pctx == NULL) {
		res = -ENOMEM;
		goto error;
	}
	res = pomp_ctx_set_raw(tcp_proxy->pctx, &tcp_proxy_raw_cb);
	if (res < 0)
		goto error;

	/* Disable keepalive */
	res = pomp_ctx_setup_keepalive(tcp_proxy->pctx, 0, 0, 0, 0);
	if (res < 0)
		goto error;

	/* Setup address (bind to a random port) */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	addrlen = sizeof(addr);

	tcp_proxy->remoteport = remoteport;
	tcp_proxy->remotehost = strdup(remotehost);
	if (!tcp_proxy->remotehost) {
		res = -ENOMEM;
		goto error;
	}

	/* Start listening */
	res = pomp_ctx_listen(tcp_proxy->pctx,
			(const struct sockaddr *)&addr, addrlen);
	if (res < 0) {
		MUX_LOG_ERR("pomp_ctx_listen", -res);
		goto error;
	}

	/* Retrieve bound local port */
	local_addr = pomp_ctx_get_local_addr(tcp_proxy->pctx, &addrlen);
	if (local_addr == NULL || addrlen < sizeof(struct sockaddr_in)) {
		MUX_LOGE("Invalid bound local address");
		goto error;
	}
	if (local_addr->sa_family != AF_INET) {
		MUX_LOGE("Invalid bound local address family");
		goto error;
	}
	tcp_proxy->localport = ntohs(((const struct sockaddr_in *)
			local_addr)->sin_port);

	mux_loop_release(ctx);

	*ret_obj = tcp_proxy;
	return 0;

	/* Cleanup in case of error */
error:
	mux_tcp_proxy_destroy(tcp_proxy);
	mux_loop_release(ctx);
	return res;
}

/**
 * See documentation in public header.
 */
int mux_tcp_proxy_destroy(struct mux_tcp_proxy *tcp_proxy)
{
	size_t len;

	if (tcp_proxy == NULL)
		return -EINVAL;

	mux_loop_acquire(tcp_proxy->mux_ctx, 0);

	pomp_ctx_stop(tcp_proxy->pctx);
	pomp_ctx_destroy(tcp_proxy->pctx);

	len = list_length(&tcp_proxy->conn_to_chann.entries);
	if (len != 0)
		MUX_LOGW("connection to channel hash table not empty");

	hash_destroy(&tcp_proxy->conn_to_chann);

	mux_loop_release(tcp_proxy->mux_ctx);
	mux_unref(tcp_proxy->mux_ctx);

	free(tcp_proxy->remotehost);
	free(tcp_proxy);
	return 0;
}

/**
 * See documentation in public header.
 */
int mux_tcp_proxy_get_port(struct mux_tcp_proxy *tcp_proxy)
{
	if (tcp_proxy == NULL)
		return -EINVAL;

	return tcp_proxy->localport;
}
