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

#ifndef _MUX_IP_PROXY_PRIV_H_
#define _MUX_IP_PROXY_PRIV_H_

#include <futils/hash.h>

/** Mux Ip Proxy */
struct mux_ip_proxy {
	/** List node. */
	struct list_node        node;
	/** Identifier. */
	uint32_t                id;
	/** Mux context. */
	struct mux_ctx          *mux_ctx;
	/** Callbacks. */
	struct mux_ip_proxy_cbs cbs;
	/** Pomp loop. */
	struct pomp_loop        *ploop;
	/** Pomp contex. */
	struct pomp_ctx         *pctx;
	/** Proxy protocol. */
	struct mux_ip_proxy_protocol protocol;

	/* Remote info. */
	struct {
		/** Remote host name. */
		char                    *host;
		/** Remote address in network byte order. */
		uint32_t                addr;
		/** Remote port. */
		uint16_t                port;
	} remote;

	/**
	 * Hash table of connection fd to channel.
	 * Only used if 'protocol.transport' is 'MUX_IP_PROXY_TRANSPORT_TCP'.
	 */
	struct hash             tcp_conn_to_chann;

	/**
	 * UDP part.
	 * Only used if 'protocol.transport' is 'MUX_IP_PROXY_TRANSPORT_UDP'.
	 */
	struct {
		/**
		 * Mux channel used by the proxy.
		 * Only used if 'protocol.transport' is
		 * 'MUX_IP_PROXY_TRANSPORT_UDP'.
		 */
		struct mux_channel      *channel;

		/**
		 * Local port where to redirect data received from the remote.
		 * Only used if 'protocol.transport' is
		 * 'MUX_IP_PROXY_TRANSPORT_UDP'.
		 * If equal to '0', data received will be lost.
		 */
		uint16_t                redirect_port;
		/**
		 * Local address where to redirect data received
		 * from the remote.
		 * Only used if 'protocol.transport' is
		 * 'MUX_IP_PROXY_TRANSPORT_UDP'.
		 */
		struct sockaddr         addr;
		/**
		 * Length of 'addr'.
		 * Only used if 'protocol.transport' is
		 * 'MUX_IP_PROXY_TRANSPORT_UDP'.
		 */
		size_t                  addrlen;
	} udp;

	/** Local port. */
	uint16_t                localport;
	/** Peer port. */
	uint16_t                peerport;

	/** Current asynchronous request. */
	struct {
		/* Timeout timer. */
		struct pomp_timer *timeout;
		/* Pending message id otherwise MUX_CTRL_MSG_ID_UNKNOWN.*/
		uint32_t id;
		/** Request data. */
		union {
			/** Host name to resolve;
			 * Used by MUX_CTRL_MSG_ID_PROXY_RESOLVE_REQ.
			 */
			char *hostname;

		} data;
	} req;
};

/**
 * Notifies the proxy of the resolution of its remote host name.
 *
 * @param self : The proxy.
 * @param hostname : Remote host name.
 * @param addr : Address associated to the host name.
 *
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_ip_proxy_resolution(struct mux_ip_proxy *self, char *hostname,
		uint32_t addr);

/**
 * Notifies the proxy of the remote update.
 *
 * @param self : The proxy.
 * @param remoteaddr : New remote address.
 * @param remoteport : New remote port.
 *
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_ip_proxy_remote_update(struct mux_ip_proxy *self,
		uint32_t remoteaddr, uint16_t remoteport);

/**
 * Notifies the proxy that its channel is connected.
 *
 * @param self : The proxy.
 * @param peerport : Mux peer port used to communicate with the remote.
 *
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_ip_proxy_channel_connected(struct mux_ip_proxy *self,
		uint16_t peerport);

/**
 * Opens the proxy local socket.
 *
 * @param self : The proxy.
 *
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_ip_proxy_open(struct mux_ip_proxy *self);

/**
 * Closes the proxy local socket.
 *
 * @param self : The proxy.
 *
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_ip_proxy_close(struct mux_ip_proxy *self);

/**
 * Sends data through the udp local socket.
 *
 * @param self : The proxy.
 * @param buf : Data to send.
 *
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_ip_proxy_udp_local_send(struct mux_ip_proxy *self,
		struct pomp_buffer *buf);

/**
 * Initilizes the pending resolve request.
 *
 * @param self : The proxy.
 * @param hostname : Host name to resolve.
 * @param timeout : expiration delay in milliseconds.
 *
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_ip_init_pending_resolve_req(struct mux_ip_proxy *self, char *hostname,
		int timeout);

/**
 * Clear the current pending request.
 *
 * @param self : The proxy.
 *
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_ip_clear_pending_req(struct mux_ip_proxy *self);

#endif /* _MUX_IP_PROXY_PRIV_H_ */
