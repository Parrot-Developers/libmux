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

#include "mux_priv.h"

static int get_chann(struct mux_ip_proxy *self,
		struct pomp_conn *conn, struct mux_channel **channel)
{
	int res;
	int fd;

	if (self == NULL || channel == NULL)
		return -EINVAL;

	switch (self->protocol.transport) {
	case MUX_IP_PROXY_TRANSPORT_UDP:
		*channel = self->udp.channel;
		return 0;
	case MUX_IP_PROXY_TRANSPORT_TCP:
		if (conn == NULL)
			return -EINVAL;

		fd = pomp_conn_get_fd(conn);

		res = hash_lookup(&self->tcp_conn_to_chann, (uint32_t) fd,
				(void **)channel);
		if (res < 0)
			return -ENOENT;

		return 0;
	default:
		MUX_LOGE("ip transport (%d) unknown",
				self->protocol.transport);
		return -EINVAL;
	}
}

static int remove_chann(struct mux_ip_proxy *self, struct pomp_conn *conn)
{
	int fd;

	if (self == NULL)
		return -EINVAL;

	switch (self->protocol.transport) {
	case MUX_IP_PROXY_TRANSPORT_UDP:
		self->udp.channel = NULL;
		return 0;
	case MUX_IP_PROXY_TRANSPORT_TCP:
		if (conn == NULL)
			return -EINVAL;

		fd = pomp_conn_get_fd(conn);
		hash_remove(&self->tcp_conn_to_chann, fd);

		return 0;
	default:
		MUX_LOGE("ip transport (%d) unknown", self->protocol.transport);
		return -EINVAL;
	}

	return 0;
}

static int add_chann(struct mux_ip_proxy *self,
		struct pomp_conn *conn, struct mux_channel *channel)
{
	int fd;

	if (self == NULL || channel == NULL)
		return -EINVAL;

	switch (self->protocol.transport) {
	case MUX_IP_PROXY_TRANSPORT_UDP:
		self->udp.channel = channel;
		return 0;
	case MUX_IP_PROXY_TRANSPORT_TCP:
		if (conn == NULL)
			return -EINVAL;

		fd = pomp_conn_get_fd(conn);
		return hash_insert(&self->tcp_conn_to_chann, (uint32_t) fd,
				channel);
	default:
		MUX_LOGE("ip transport (%d) unknown", self->protocol.transport);
		return -EINVAL;
	}

	return 0;
}

static int close_channel(struct mux_ip_proxy *self,
		struct pomp_conn *conn)
{
	int res;
	struct mux_channel *channel = NULL;

	if (self == NULL)
		return -EINVAL;

	res = get_chann(self, conn, &channel);
	if (res < 0)
		return res;

	mux_channel_close(self->mux_ctx, channel->chanid);

	remove_chann(self, conn);

	return 0;
}

static int open_channel(struct mux_ip_proxy *ip_proxy,
		struct pomp_conn *conn)
{
	int res = 0;
	uint32_t chanid = 0;
	struct mux_channel *channel = NULL;

	if (ip_proxy == NULL ||
		(ip_proxy->protocol.transport != MUX_IP_PROXY_TRANSPORT_UDP &&
		 conn == NULL))
		return -EINVAL;

	mux_loop_acquire(ip_proxy->mux_ctx, 0);
	res = mux_channel_open_ip(ip_proxy->mux_ctx, &ip_proxy->protocol,
			ip_proxy->remote.addr, ip_proxy->remote.port, &chanid);
	if (res < 0) {
		mux_loop_release(ip_proxy->mux_ctx);
		return res;
	}

	/* Find back the channel structure */
	channel = mux_find_channel(ip_proxy->mux_ctx, chanid);
	if (channel == NULL) {
		res = -ENOENT;
		goto error;
	}

	channel->ipmaster.ip_proxy = ip_proxy;

	res = add_chann(ip_proxy, conn, channel);
	if (res < 0)
		goto error;

	mux_loop_release(ip_proxy->mux_ctx);
	return 0;

	/* Cleanup in case of error */
error:
	if (channel != NULL)
		mux_channel_close(ip_proxy->mux_ctx, channel->chanid);
	mux_loop_release(ip_proxy->mux_ctx);
	return res;
}

/**
 * event callback.
 */
static void ip_proxy_event_cb(struct pomp_ctx *ctx,
		enum pomp_event event,
		struct pomp_conn *conn,
		const struct pomp_msg *msg,
		void *userdata)
{
	int res = 0;
	struct mux_ip_proxy *ip_proxy = userdata;
	struct mux_channel *channel = NULL;

	switch (event) {
	case POMP_EVENT_CONNECTED:

		res = open_channel(ip_proxy, conn);
		if (res < 0) {
			MUX_LOG_ERR("open_channel", -res);
			break;
		}

		res = get_chann(ip_proxy, conn, &channel);
		if (res < 0) {
			MUX_LOG_ERR("get_chann", -res);
			break;
		}

		mux_channel_ipmaster_event(channel, event, conn);
		break;

	case POMP_EVENT_DISCONNECTED:

		res = get_chann(ip_proxy, conn, &channel);
		if (res < 0) {
			MUX_LOG_ERR("get_chann", -res);
			break;
		}

		mux_channel_ipmaster_event(channel, event, conn);

		res = close_channel(ip_proxy, conn);
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
static void ip_proxy_raw_cb(struct pomp_ctx *ctx,
		struct pomp_conn *conn,
		struct pomp_buffer *buf,
		void *userdata)
{
	int res;
	struct mux_ip_proxy *self = userdata;
	struct mux_channel *channel = NULL;

	res = get_chann(self, conn, &channel);
	if (res < 0) {
		MUX_LOG_ERR("get_chann", -res);
		return;
	}

	if (self->udp.redirect_port == 0 &&
	    self->protocol.transport == MUX_IP_PROXY_TRANSPORT_UDP) {
		/* No redirect port ; Set it to the sender port. */
		uint32_t addrlen;
		uint16_t redirect_port;
		const struct sockaddr_in *peeraddr;
		const struct sockaddr *addr = pomp_conn_get_peer_addr(conn,
				&addrlen);
		peeraddr = (const struct sockaddr_in *)addr;
		if (peeraddr == NULL)
			goto end;

		redirect_port = ntohs(peeraddr->sin_port);
		res = mux_ip_proxy_set_udp_redirect_port(self, redirect_port);
		if (res < 0)
			MUX_LOG_ERR("mux_ip_proxy_set_udp_redirect_port", -res);
		else
			MUX_LOGI("Redirect port set to %u", redirect_port);
	}

end:
	mux_channel_ipmaster_raw(channel, conn, buf);
}

static int update_remote(struct mux_ip_proxy *self,
		uint32_t remote_addr, uint16_t remote_port)
{
	struct mux_ctrl_msg msg = {
		.id = MUX_CTRL_MSG_ID_PROXY_REMOTE_UPDATE_REQ,
		.args = {remote_addr, remote_port},
	};

	if (self == NULL ||
	    self->protocol.transport != MUX_IP_PROXY_TRANSPORT_UDP)
		return -EINVAL;

	/* Ask the mux peer to connect to the new remote. */
	msg.chanid = self->udp.channel->chanid;
	return mux_send_ctrl_msg(self->mux_ctx, &msg);
}

static int udp_connect(struct mux_ip_proxy *self)
{
	int res;

	if (self == NULL)
		return -EINVAL;

	res = open_channel(self, NULL);
	if (res < 0) {
		MUX_LOG_ERR("open_channel", -res);
		return res;
	}

	res = mux_channel_send_msg_ip_connect(self->udp.channel);
	if (res < 0) {
		MUX_LOG_ERR("mux_channel_send_msg_ip_connect", -res);
		return res;
	};

	return 0;
}

static int resolution_failed(struct mux_ip_proxy *self, uint32_t addr,
		int err)
{
	if (self == NULL)
		return -EINVAL;

	/* Remote address update */
	self->remote.addr = addr;

	/* Notify than the resolution failed. */
	if (self->cbs.resolution_failed != NULL)
		(*self->cbs.resolution_failed)(self, err, self->cbs.userdata);

	return 0;
}

static int resolution_succeed(struct mux_ip_proxy *self, uint32_t addr)
{
	int res;

	if (self == NULL)
		return -EINVAL;

	/* Remote address update */
	self->remote.addr = addr;

	switch (self->protocol.transport) {
	case MUX_IP_PROXY_TRANSPORT_TCP:
		mux_ip_proxy_open(self);

		return 0;
	case MUX_IP_PROXY_TRANSPORT_UDP:
		/* Check if mux channel exists. */
		if (self->udp.channel != NULL) {
			res = update_remote(self, self->remote.addr,
				self->remote.port);
			if (res < 0) {
				MUX_LOG_ERR("update_remote", -res);
				return res;
			}

		} else {
			/* Connect the mux peer to the remote. */
			res = udp_connect(self);
			if (res < 0) {
				MUX_LOG_ERR("udp_connect", -res);
				return res;
			}
		}

		return 0;
	default:
		MUX_LOGE("ip transport (%d) unknown", self->protocol.transport);
		return -EPROTO;
	}
}

int mux_ip_proxy_resolution(struct mux_ip_proxy *self, char *hostname,
		uint32_t addr)
{
	int res;
	if (self == NULL || hostname == NULL)
		return -EINVAL;

	if (self->req.id != MUX_CTRL_MSG_ID_PROXY_RESOLVE_REQ ||
		self->req.data.hostname == NULL ||
		strcmp(self->req.data.hostname, hostname) != 0)
		return 0;

	/* Clear pending request */
	mux_ip_clear_pending_req(self);

	if (addr == INADDR_NONE)
		res = resolution_failed(self, addr, -ENODEV);
	else
		res = resolution_succeed(self, addr);

	return res;
}

static int mux_ip_proxy_resolution_timeout(struct mux_ip_proxy *self)
{
	if (self == NULL)
		return -EINVAL;

	if (self->req.id != MUX_CTRL_MSG_ID_PROXY_RESOLVE_REQ)
		return -EPROTO;

	/* Clear pending request */
	mux_ip_clear_pending_req(self);

	return resolution_failed(self, INADDR_NONE, -ETIMEDOUT);
}

int mux_ip_proxy_remote_update(struct mux_ip_proxy *self,
		uint32_t remotaddr, uint16_t remoteport)
{
	if (self == NULL)
		return -EINVAL;

	self->remote.addr = remotaddr;
	self->remote.port = remoteport;

	/* Notify of the remote update. */
	if (*self->cbs.remote_update != NULL)
		(*self->cbs.remote_update)(self, self->cbs.userdata);

	return 0;
}

int mux_ip_proxy_channel_connected(struct mux_ip_proxy *self, uint16_t peerport)
{
	if (self == NULL)
		return -EINVAL;

	self->peerport = peerport;

	switch (self->protocol.transport) {
	case MUX_IP_PROXY_TRANSPORT_TCP:
		return 0;
	case MUX_IP_PROXY_TRANSPORT_UDP:
		mux_ip_proxy_open(self);
		return 0;
	default:
		MUX_LOGE("ip transport (%d) unknown", self->protocol.transport);
		return -EPROTO;
	}
}

int mux_ip_proxy_open(struct mux_ip_proxy *self)
{
	int res = 0;
	struct sockaddr_in addr;
	uint32_t addrlen = 0;
	const struct sockaddr *local_addr = NULL;

	if (self == NULL)
		return -EINVAL;

	/* Create context and make it raw */
	self->pctx = pomp_ctx_new_with_loop(&ip_proxy_event_cb,
			self, self->ploop);
	if (self->pctx == NULL) {
		res = -ENOMEM;
		goto error;
	}
	res = pomp_ctx_set_raw(self->pctx, &ip_proxy_raw_cb);
	if (res < 0)
		goto error;

	/* Disable keepalive */
	res = pomp_ctx_setup_keepalive(self->pctx, 0, 0, 0, 0);
	if (res < 0)
		goto error;

	/* Setup address (bind to a random port) */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	addrlen = sizeof(addr);

	switch (self->protocol.transport) {
	case MUX_IP_PROXY_TRANSPORT_TCP:
		/* Start listening */
		res = pomp_ctx_listen(self->pctx,
				(const struct sockaddr *)&addr, addrlen);
		if (res < 0) {
			MUX_LOG_ERR("pomp_ctx_listen", -res);
			goto error;
		}
		break;
	case MUX_IP_PROXY_TRANSPORT_UDP:
		/* Start listening */
		res = pomp_ctx_bind(self->pctx,
				(const struct sockaddr *)&addr, addrlen);
		if (res < 0) {
			MUX_LOG_ERR("pomp_ctx_bind", -res);
			goto error;
		}
		break;
	default:
		MUX_LOGE("ip transport (%d) unknown", self->protocol.transport);
		break;
	}

	/* Retrieve bound local port */
	local_addr = pomp_ctx_get_local_addr(self->pctx, &addrlen);
	if (local_addr == NULL || addrlen < sizeof(struct sockaddr_in)) {
		MUX_LOGE("Invalid bound local address");
		goto error;
	}
	if (local_addr->sa_family != AF_INET) {
		MUX_LOGE("Invalid bound local address family");
		goto error;
	}
	self->localport = ntohs(((const struct sockaddr_in *)
			local_addr)->sin_port);

	/* Notify of the local socket opening. */
	(*self->cbs.open)(self, self->localport, self->cbs.userdata);

	return 0;

	/* Cleanup in case of error */
error:
	mux_ip_proxy_close(self);
	return res;
}

int mux_ip_proxy_close(struct mux_ip_proxy *self)
{
	if (self == NULL)
		return -EINVAL;

	if (self->udp.channel != NULL)
		mux_channel_close(self->mux_ctx, self->udp.channel->chanid);

	pomp_ctx_stop(self->pctx);
	pomp_ctx_destroy(self->pctx);

	/* Notify of the local socket closing. */
	(*self->cbs.close)(self, self->cbs.userdata);

	return 0;
}

int mux_ip_proxy_udp_local_send(struct mux_ip_proxy *self,
		struct pomp_buffer *buf)
{
	if (self == NULL ||
	    self->protocol.transport != MUX_IP_PROXY_TRANSPORT_UDP ||
	    buf == NULL)
		return -EINVAL;

	if (self->udp.redirect_port == 0)
		return -ENOTCONN;

	return pomp_ctx_send_raw_buf_to(self->pctx, buf,
			&self->udp.addr, self->udp.addrlen);
}

const char *mux_ip_proxy_get_remote_host(struct mux_ip_proxy *self)
{
	return self == NULL ? NULL : self->remote.host;
}

uint16_t mux_ip_proxy_get_remote_port(struct mux_ip_proxy *self)
{
	return self == NULL ? 0 : self->remote.port;
}

uint32_t mux_ip_proxy_get_remote_addr(struct mux_ip_proxy *self)
{
	return self == NULL ? 0 : self->remote.addr;
}

static void mux_ip_proxy_open_timeout_cb(struct pomp_timer *timer,
		void *userdata)
{
	mux_ip_proxy_resolution_timeout(userdata);
}

int mux_ip_init_pending_resolve_req(struct mux_ip_proxy *self, char *hostname,
		int timeout)
{
	int res;

	if (self == NULL || hostname == NULL)
		return -EINVAL;

	if (self->req.id != MUX_CTRL_MSG_ID_UNKNOWN)
		return -EBUSY;

	self->req.data.hostname = strdup(hostname);
	if (self->req.data.hostname == NULL)
		return -ENOMEM;

	self->req.id = MUX_CTRL_MSG_ID_PROXY_RESOLVE_REQ;
	if (timeout >= 0) {
		/* Initilize request timeout timer */
		self->req.timeout = pomp_timer_new(self->ploop,
				&mux_ip_proxy_open_timeout_cb, self);
		if (self->req.timeout == NULL)
			return -ENOMEM;

		res = pomp_timer_set(self->req.timeout, timeout);
		if (res < 0)
			goto error;
	}

	return 0;
error:
	mux_ip_clear_pending_req(self);
	return res;
}

int mux_ip_clear_pending_req(struct mux_ip_proxy *self)
{
	if (self == NULL)
		return -EINVAL;

	if (self->req.timeout != NULL) {
		pomp_timer_clear(self->req.timeout);
		pomp_timer_destroy(self->req.timeout);
		self->req.timeout = NULL;
	}

	switch (self->req.id) {
	case MUX_CTRL_MSG_ID_PROXY_RESOLVE_REQ:
		free(self->req.data.hostname);
		self->req.data.hostname = NULL;
		break;
	case MUX_CTRL_MSG_ID_UNKNOWN:
	default:
		break;
	}

	self->req.id = MUX_CTRL_MSG_ID_UNKNOWN;

	return 0;
}
