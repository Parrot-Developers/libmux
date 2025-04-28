/**
 * Copyright (c) 2019 Parrot Drones SAS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Parrot Drones SAS Company nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE PARROT DRONES SAS COMPANY BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "mux_test.h"
#include "mux_test_base.h"

#define LOG_TAG "mux_test_ip_proxy"
#define TST_LOG(_fmt, ...) fprintf(stderr, LOG_TAG ": " _fmt "\n", ##__VA_ARGS__)

#define REMOTE_PORT 2222
#define REMOTE_ADDR "127.0.0.1"
#define REMOTE_ADDR_RESOLVE_SYNC "resolve_sync"
#define REMOTE_ADDR_RESOLVE_ASYNC "resolve_async"
#define REMOTE_ADDR_RESOLVE_ASYNC_FAILED "resolve_async_failed"
#define REMOTE_ADDR_RESOLVE_TIMEOUT "resolve_timeout"
#define REMOTE_ADDR_RESOLVE_FAILED "resolv_failed"

#define REMOTE2_PORT 2223
#define REMOTE2_ADDR_RESOLVE_SYNC REMOTE_ADDR_RESOLVE_SYNC
#define REMOTE2_ADDR_RESOLVE_TIMEOUT REMOTE_ADDR_RESOLVE_TIMEOUT

#define MIN_DATA_LEN 10
#define DATA_MIN 'A'
#define DATA_MAX 'Z'
#define idx_to_data(_i) (((_i) % (DATA_MAX - DATA_MIN)) + DATA_MIN)

/** */
struct test_data {
	struct mux_test_env *env;
	struct mux_ip_proxy_protocol protocol;

	struct {
		struct pomp_ctx *pctx;
		const char *host;
		int timeout;
		int timeout_enabled;

		int msg_rcv_cnt;
	} remote;

	struct {
		struct pomp_ctx *pctx;
		const char *host;
		int timeout;
		int timeout_enabled;

		int msg_rcv_cnt;
	} remote2;

	struct {
		struct pomp_ctx *pctx;
		struct mux_ip_proxy *proxy;
		void (*proxy_start_cb)(void);
		void (*proxy_stop_cb)(void);

		void (*send_msg)(struct pomp_buffer *buf);

		void (*on_data_rcv)(struct pomp_buffer *buf);
		void (*on_remote_update)(void);
		void (*on_resolution_failed)(int err);

		/* sending test config. */
		size_t data_size;
		size_t chunk_size;
		struct pomp_buffer *snd_buf;
		struct pomp_buffer *turn_buf;

		/* counters */
		int msg_snd_cnt;
		int msg_rcv_cnt;
		int open_call_cnt;
		int close_call_cnt;
		int resolution_failed_call_cnt;
		int remote_update_call_cnt;

		size_t snd_cnt;
		size_t rcv_cnt;
	} local;

	struct {
		int (*resolve_cb)(struct mux_ctx *ctx, const char *hostname,
				uint32_t *addr, void *userdata);

		void (*on_connect)(void);

		int resolve_call_cnt;
	} peer;
};

struct test_data s_data;

/* #############################################################################
	Remote part
*/

static void remote_raw_cb(struct pomp_ctx *ctx, struct pomp_conn *conn,
		struct pomp_buffer *buf, void *userdata)
{
	TST_LOG("%s \n", __func__);

	if(ctx == s_data.remote.pctx)
		s_data.remote.msg_rcv_cnt++;
	else if(ctx == s_data.remote2.pctx)
		s_data.remote2.msg_rcv_cnt++;

	CU_ASSERT_PTR_NOT_NULL_FATAL(buf);
	int res = pomp_conn_send_raw_buf(conn, buf);
	CU_ASSERT_EQUAL_FATAL(res, 0);
}

static void remote_event_cb(struct pomp_ctx *ctx, enum pomp_event event,
		struct pomp_conn *conn, const struct pomp_msg *msg,
		void *userdata)
{
	TST_LOG("%s \n", __func__);

	switch (event) {
	case POMP_EVENT_CONNECTED:
		TST_LOG("remote connected \n");
		break;
	case POMP_EVENT_DISCONNECTED:
		TST_LOG("remote disconnected \n");
		break;
	case POMP_EVENT_MSG:
		/* Never received for raw context */
		CU_FAIL_FATAL("remote_event_cb POMP_EVENT_MSG not expected");
		break;
	}
}

static void remote_start(enum mux_ip_proxy_transport transport,
		enum mux_ip_proxy_application application, uint16_t remote_port,
		struct pomp_ctx **remote_pctx)
{
	int res = 0;
	struct sockaddr_in addr;
	size_t addrlen;
	struct pomp_ctx *pctx;

	TST_LOG("%s transport :%d application; %d\n", __func__, transport, application);

	pctx = pomp_ctx_new_with_loop(&remote_event_cb, NULL,
			mux_test_env_get_loop(s_data.env));
	CU_ASSERT_PTR_NOT_NULL_FATAL(pctx);

	res = pomp_ctx_set_raw(pctx, &remote_raw_cb);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(remote_port);
	addrlen = sizeof(addr);

	switch (transport) {
	case MUX_IP_PROXY_TRANSPORT_TCP:
		res = pomp_ctx_listen(pctx,
				(const struct sockaddr *)&addr, addrlen);
		CU_ASSERT_EQUAL_FATAL(res, 0);
		break;
	case MUX_IP_PROXY_TRANSPORT_UDP:
		res = pomp_ctx_bind(pctx,
				(const struct sockaddr *)&addr, addrlen);
		CU_ASSERT_EQUAL_FATAL(res, 0);
		break;
	default:
		CU_FAIL_FATAL("remote_start transport not expected");
		break;
	}

	CU_ASSERT_PTR_NOT_NULL_FATAL(remote_pctx);
	*remote_pctx = pctx;
	return;
}

static void remote_stop(struct pomp_ctx *remote_pctx)
{
	TST_LOG("%s \n", __func__);

	pomp_ctx_stop(remote_pctx);

	pomp_ctx_destroy(remote_pctx);
}

/* #############################################################################
	Peer part
*/

static void idle_srv_resolve_cb(void *userdata)
{
	TST_LOG("%s \n", __func__);

	uint32_t addr = inet_addr(REMOTE_ADDR);

	int res = mux_resolve(mux_test_env_get_srv_mux(s_data.env),
			REMOTE_ADDR_RESOLVE_ASYNC, addr);
	CU_ASSERT_EQUAL_FATAL(res, 0);
}

static void idle_srv_resolve_failed_cb(void *userdata)
{
	TST_LOG("%s \n", __func__);

	int res = mux_resolve(mux_test_env_get_srv_mux(s_data.env),
			REMOTE_ADDR_RESOLVE_ASYNC_FAILED, INADDR_NONE);
	CU_ASSERT_EQUAL_FATAL(res, 0);
}

static int srv_resolve_cb(struct mux_ctx *ctx, const char *hostname,
		uint32_t *addr, void *userdata)
{
	TST_LOG("%s \n", __func__);

	s_data.peer.resolve_call_cnt++;

	if (!strcmp(hostname, REMOTE_ADDR_RESOLVE_ASYNC)){
		*addr = INADDR_ANY;

		int res = pomp_loop_idle_add(mux_test_env_get_loop(s_data.env),
			&idle_srv_resolve_cb, NULL);
		CU_ASSERT_EQUAL_FATAL(res, 0);
		return 0;
	} if (!strcmp(hostname, REMOTE_ADDR_RESOLVE_ASYNC_FAILED)){
		*addr = INADDR_ANY;

		int res = pomp_loop_idle_add(mux_test_env_get_loop(s_data.env),
			&idle_srv_resolve_failed_cb, NULL);
		CU_ASSERT_EQUAL_FATAL(res, 0);
		return 0;
	} else if (!strcmp(hostname, REMOTE_ADDR_RESOLVE_FAILED)) {
		*addr = INADDR_NONE;
		return -ENODEV;
	} if (!strcmp(hostname, REMOTE_ADDR_RESOLVE_TIMEOUT)){
		*addr = INADDR_ANY;
		return 0;
	} else {
		*addr = inet_addr(REMOTE_ADDR);
		return 0;
	}
}

/* #############################################################################
	Local part
*/

static void local_raw_cb(struct pomp_ctx *ctx, struct pomp_conn *conn,
		struct pomp_buffer *buf, void *userdata)
{
	TST_LOG("%s \n", __func__);
	s_data.local.msg_rcv_cnt++;

	if (s_data.local.on_data_rcv != NULL)
		s_data.local.on_data_rcv(buf);
	else
		mux_test_env_loop_stop(s_data.env);
}

static void local_send_msg(void)
{
	int res;
	uint16_t localport;
	struct sockaddr_in addr;
	uint32_t addrlen;

	TST_LOG("%s \n", __func__);

	/* fill data */
	char *snd_data;
	size_t snd_cap;
	res = pomp_buffer_get_data(s_data.local.snd_buf, (void **)&snd_data, NULL, &snd_cap);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(snd_data);
	CU_ASSERT_TRUE_FATAL(snd_cap >= s_data.local.chunk_size);
	size_t i;

	size_t snd_data_size = s_data.local.data_size != 0 ?
			MIN(s_data.local.data_size - s_data.local.snd_cnt, s_data.local.chunk_size):
			MIN_DATA_LEN;
	for (i = 0; i < snd_data_size; i++) {
		snd_data[i] = idx_to_data(s_data.local.snd_cnt + i);
	}
	res = pomp_buffer_set_len(s_data.local.snd_buf, snd_data_size);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	// override
	if (s_data.local.send_msg != NULL) {
		s_data.local.send_msg(s_data.local.snd_buf);
	} else {
		switch (s_data.protocol.transport) {
		case MUX_IP_PROXY_TRANSPORT_TCP:
			res = pomp_ctx_send_raw_buf(s_data.local.pctx, s_data.local.snd_buf);
			CU_ASSERT_EQUAL_FATAL(res, 0);
			break;
		case MUX_IP_PROXY_TRANSPORT_UDP:
			res = mux_ip_proxy_get_local_info(s_data.local.proxy,
					NULL, &localport);
			CU_ASSERT_EQUAL_FATAL(res, 0);

			memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			addr.sin_port = htons(localport);
			addrlen = sizeof(addr);

			res = pomp_ctx_send_raw_buf_to(s_data.local.pctx, s_data.local.snd_buf,
					(const struct sockaddr *)&addr, addrlen);
			CU_ASSERT_EQUAL_FATAL(res, 0);
			break;
		default:
			CU_FAIL_FATAL("local_send_msg transport not expected");
			break;
		}
	}
	s_data.local.msg_snd_cnt++;
	s_data.local.snd_cnt += snd_data_size;
}

static void local_event_cb(struct pomp_ctx *ctx, enum pomp_event event,
		struct pomp_conn *conn, const struct pomp_msg *msg,
		void *userdata)
{
	TST_LOG("%s \n", __func__);

	switch (event) {
	case POMP_EVENT_CONNECTED:
		TST_LOG("local connected");
		CU_ASSERT_EQUAL(s_data.protocol.transport,
				MUX_IP_PROXY_TRANSPORT_TCP);
		local_send_msg();
		break;
	case POMP_EVENT_DISCONNECTED:
		TST_LOG("local disconnected");
		break;
	case POMP_EVENT_MSG:
		/* Never received for raw context */
		CU_FAIL_FATAL("local_event_cb POMP_EVENT_MSG not expected");
		break;
	}
}

static void local_start(struct mux_ip_proxy *self, uint16_t localport) {
	struct sockaddr_in addr;
	uint32_t addrlen = 0;

	TST_LOG("%s \n", __func__);

	s_data.local.pctx = pomp_ctx_new_with_loop(&local_event_cb, NULL,
			mux_test_env_get_loop(s_data.env));
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.local.pctx);

	int res = pomp_ctx_set_raw(s_data.local.pctx, &local_raw_cb);
	CU_ASSERT_EQUAL(res, 0);

	switch (s_data.protocol.transport) {
	case MUX_IP_PROXY_TRANSPORT_TCP:
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = htons(localport);
		addrlen = sizeof(addr);

		res = pomp_ctx_connect(s_data.local.pctx,
				(const struct sockaddr *)&addr, addrlen);
		CU_ASSERT_EQUAL(res, 0);
		break;
	case MUX_IP_PROXY_TRANSPORT_UDP:
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = 0;
		addrlen = sizeof(addr);

		res = pomp_ctx_bind(s_data.local.pctx,
				(const struct sockaddr *)&addr, addrlen);
		CU_ASSERT_EQUAL(res, 0);

		local_send_msg();
		break;
	default:
		CU_FAIL_FATAL("local_start transport not expected");
		break;
	}
}

static void local_stop(void)
{
	TST_LOG("%s \n", __func__);

	if (s_data.local.pctx != NULL) {
		pomp_ctx_stop(s_data.local.pctx);

		pomp_ctx_destroy(s_data.local.pctx);
		s_data.local.pctx = NULL;
	}
}

/* #############################################################################
	Proxy Callbacks
*/

static void proxy_open_cb(struct mux_ip_proxy *self, uint16_t localport,
		void *userdata)
{
	TST_LOG("%s \n", __func__);

	s_data.local.open_call_cnt++;

	struct mux_ip_proxy_protocol protocol;
	int res = mux_ip_proxy_get_local_info(self, &protocol, NULL);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	CU_ASSERT_EQUAL_FATAL(protocol.transport, s_data.protocol.transport);
	CU_ASSERT_EQUAL_FATAL(protocol.application, s_data.protocol.application);

	s_data.local.snd_buf = pomp_buffer_new(MAX(s_data.local.chunk_size, (size_t)MIN_DATA_LEN));
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.local.snd_buf);

	local_start(self, localport);
}

static void proxy_close_cb(struct mux_ip_proxy *self, void *userdata)
{
	TST_LOG("%s \n", __func__);

	s_data.local.close_call_cnt++;

	if (s_data.local.snd_buf != NULL)
		pomp_buffer_unref(s_data.local.snd_buf);

	local_stop();
}

static void proxy_remote_update_cb(struct mux_ip_proxy *self,  void *userdata)
{
	TST_LOG("%s \n", __func__);
	s_data.local.remote_update_call_cnt++;

	if (s_data.local.on_remote_update != NULL)
		s_data.local.on_remote_update();
}

static void proxy_resolution_failed_cb(struct mux_ip_proxy *self, int err,
		void *userdata)
{
	TST_LOG("%s \n", __func__);

	s_data.local.resolution_failed_call_cnt++;

	if (s_data.local.on_resolution_failed != NULL)
		s_data.local.on_resolution_failed(err);
}

static void cli_connect_cb(struct mux_test_env *env, void *userdata)
{
	TST_LOG("%s \n", __func__);

	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.local.proxy_start_cb);
	s_data.local.proxy_start_cb();
}

static void cli_disconnect_cb(struct mux_test_env *env, void *userdata)
{
	TST_LOG("%s \n", __func__);

	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.local.proxy_start_cb);
	s_data.local.proxy_stop_cb();
}

static void srv_connect_cb(struct mux_test_env *env, void *userdata)
{
	TST_LOG("%s \n", __func__);

	if (s_data.peer.on_connect)
		s_data.peer.on_connect();
}

static void srv_disconnect_cb(struct mux_test_env *env, void *userdata)
{
	TST_LOG("%s \n", __func__);
}

/** */
static void test_run(void)
{
	int res;
	struct mux_test_env_cbs env_cbs = {
		.cli_connect = &cli_connect_cb,
		.cli_disconnect = &cli_disconnect_cb,

		.srv_connect = &srv_connect_cb,
		.srv_disconnect = &srv_disconnect_cb,
		.srv_resolve = s_data.peer.resolve_cb,
	};

	TST_LOG("%s \n", __func__);

	res = mux_test_env_new(&env_cbs, &s_data.env);
	CU_ASSERT_EQUAL(res, 0);

	res = mux_test_env_start(s_data.env);
	CU_ASSERT_EQUAL(res, 0);

	if (s_data.remote.host != NULL)
		remote_start(s_data.protocol.transport, s_data.protocol.application,
				REMOTE_PORT, &s_data.remote.pctx);

	if (s_data.remote2.host != NULL)
		remote_start(s_data.protocol.transport, s_data.protocol.application,
				REMOTE2_PORT, &s_data.remote2.pctx);

	/* Run loop */
	res = mux_test_env_run_loop(s_data.env);
	CU_ASSERT_EQUAL(res, 0);

	mux_test_env_stop(s_data.env);

	if (s_data.remote.pctx) {
		remote_stop(s_data.remote.pctx);
		s_data.remote.pctx = NULL;
	}

	if (s_data.remote2.pctx) {
		remote_stop(s_data.remote2.pctx);
		s_data.remote2.pctx = NULL;
	}

	res = mux_test_env_destroy(s_data.env);
	CU_ASSERT_EQUAL(res, 0);
	s_data.env = NULL;
}


/* #############################################################################
	Test Part
*/

/* New proxy new failed test */

static void new_ip_proxy_failed_proxy_start(void)
{
	struct mux_ip_proxy_cbs cbs = {
		.open = &proxy_open_cb,
		.close = &proxy_close_cb,
		.remote_update = &proxy_remote_update_cb,
		.resolution_failed = &proxy_resolution_failed_cb,
		.userdata = &s_data,
	};

	struct mux_ip_proxy_info info = {
		.protocol = {
			.transport = MUX_IP_PROXY_TRANSPORT_TCP,
			.application = MUX_IP_PROXY_APPLICATION_NONE,
		},
		.remote_host = s_data.remote.host,
		.remote_port = REMOTE_PORT,
	};

	TST_LOG("%s \n", __func__);

	int res = mux_ip_proxy_new(NULL, &info, &cbs, -1, &s_data.local.proxy);
	CU_ASSERT_EQUAL(res, -EINVAL);
	CU_ASSERT_PTR_NULL(s_data.local.proxy);

	res = mux_ip_proxy_new(mux_test_env_get_cli_mux(s_data.env), NULL, &cbs,
			-1, &s_data.local.proxy);
	CU_ASSERT_EQUAL(res, -EINVAL);
	CU_ASSERT_PTR_NULL(s_data.local.proxy);

	res = mux_ip_proxy_new(mux_test_env_get_cli_mux(s_data.env), &info,
			NULL, -1, &s_data.local.proxy);
	CU_ASSERT_EQUAL(res, -EINVAL);
	CU_ASSERT_PTR_NULL(s_data.local.proxy);

	res = mux_ip_proxy_new(mux_test_env_get_cli_mux(s_data.env), &info,
			&cbs, -1, NULL);
	CU_ASSERT_EQUAL(res, -EINVAL);

	// add test cb null

	mux_test_env_loop_stop(s_data.env);
}

static void new_ip_proxy_failed_proxy_stop(void)
{
	TST_LOG("%s \n", __func__);
}

static void test_new_ip_proxy_failed(void)
{
	TST_LOG("%s \n", __func__);

	memset(&s_data, 0, sizeof(s_data));

	/* test */
	s_data.protocol.transport = MUX_IP_PROXY_TRANSPORT_TCP;
	s_data.protocol.application = MUX_IP_PROXY_APPLICATION_NONE;
	s_data.peer.resolve_cb = NULL;
	s_data.local.proxy_start_cb = &new_ip_proxy_failed_proxy_start;
	s_data.local.proxy_stop_cb = &new_ip_proxy_failed_proxy_stop;

	test_run();

	/* checks */
	CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.open_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.close_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.peer.resolve_call_cnt, 0);
}

/* TCP sync test */

static void tcp_proxy_start(void)
{
	struct mux_ip_proxy_cbs cbs = {
		.open = &proxy_open_cb,
		.close = &proxy_close_cb,
		.remote_update = &proxy_remote_update_cb,
		.resolution_failed = &proxy_resolution_failed_cb,
		.userdata = &s_data,
	};

	struct mux_ip_proxy_info info = {
		.protocol = {
			.transport = MUX_IP_PROXY_TRANSPORT_TCP,
			.application = MUX_IP_PROXY_APPLICATION_NONE,
		},
		.remote_host = s_data.remote.host,
		.remote_port = REMOTE_PORT,
	};

	int res;

	TST_LOG("%s \n", __func__);

	res = mux_ip_proxy_new(mux_test_env_get_cli_mux(s_data.env), &info,
			&cbs, -1, &s_data.local.proxy);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.local.proxy);

	/* Check mux_ip_proxy_set_udp_remote failed*/
	res = mux_ip_proxy_set_udp_remote(s_data.local.proxy, "test", 1234, -1);
	CU_ASSERT_EQUAL_FATAL(res, -EINVAL);

	/* Check mux_ip_proxy_set_udp_redirect_port failed*/
	res = mux_ip_proxy_set_udp_redirect_port(s_data.local.proxy, 1234);
	CU_ASSERT_EQUAL_FATAL(res, -EINVAL);
}

static void tcp_proxy_stop(void)
{
	TST_LOG("%s \n", __func__);

	int res = mux_ip_proxy_destroy(s_data.local.proxy);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	s_data.local.proxy = NULL;
}

/** */
static void test_ip_proxy_tcp(void)
{
	memset(&s_data, 0, sizeof(s_data));

	/* test tcp */
	s_data.protocol.transport = MUX_IP_PROXY_TRANSPORT_TCP;
	s_data.protocol.application = MUX_IP_PROXY_APPLICATION_NONE;
	s_data.remote.host = REMOTE_ADDR;
	s_data.peer.resolve_cb = NULL;
	s_data.local.proxy_start_cb = &tcp_proxy_start;
	s_data.local.proxy_stop_cb = &tcp_proxy_stop;

	test_run();

	/* checks */
	CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.open_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.close_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.peer.resolve_call_cnt, 0);
}

/* tcp large data test */

static void tcp_large_data_local_recv_data(struct pomp_buffer *buf)
{
	TST_LOG("%s \n", __func__);

	int res;
	const char *rcv_data;
	size_t rcv_len;

	res = pomp_buffer_get_cdata(buf, (const void **)&rcv_data, &rcv_len, NULL);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(rcv_data);

	/* check data */
	size_t i;
	for (i = 0; i < rcv_len; i++) {
		CU_ASSERT_EQUAL(rcv_data[i], idx_to_data(s_data.local.rcv_cnt + i));
	}
	s_data.local.rcv_cnt += rcv_len;

	if (s_data.local.rcv_cnt < s_data.local.data_size) {
		/* send to to the second port */
		local_send_msg();
	} else {
		/* stop the test */
		mux_test_env_loop_stop(s_data.env);
	}
}

/** */
static void test_ip_proxy_tcp_large_data(void)
{
	TST_LOG("%s", __func__);

	memset(&s_data, 0, sizeof(s_data));

	/* test tcp */
	s_data.protocol.transport = MUX_IP_PROXY_TRANSPORT_TCP;
	s_data.protocol.application = MUX_IP_PROXY_APPLICATION_NONE;
	s_data.remote.host = REMOTE_ADDR;
	s_data.peer.resolve_cb = NULL;
	s_data.local.proxy_start_cb = &tcp_proxy_start;
	s_data.local.proxy_stop_cb = &tcp_proxy_stop;
	s_data.local.on_data_rcv = &tcp_large_data_local_recv_data;

	s_data.local.data_size = 3 * 1024 * 1024;
	s_data.local.chunk_size = 1000;

	test_run();

	CU_ASSERT_EQUAL(s_data.local.snd_cnt, s_data.local.data_size);
	CU_ASSERT_EQUAL(s_data.local.rcv_cnt, s_data.local.data_size);
}

/* UDP */

static void udp_proxy_start(void)
{
	struct mux_ip_proxy_cbs cbs = {
		.open = &proxy_open_cb,
		.close = &proxy_close_cb,
		.remote_update = &proxy_remote_update_cb,
		.resolution_failed = &proxy_resolution_failed_cb,
		.userdata = &s_data,
	};

	struct mux_ip_proxy_info info = {
		.protocol = {
			.transport = MUX_IP_PROXY_TRANSPORT_UDP,
			.application = MUX_IP_PROXY_APPLICATION_NONE,
		},
		.remote_host = s_data.remote.host,
		.remote_port = REMOTE_PORT,
	};
	int res;

	TST_LOG("%s \n", __func__);

	int timeout = s_data.remote.timeout_enabled ? s_data.remote.timeout :
						      -1;
	res = mux_ip_proxy_new(mux_test_env_get_cli_mux(s_data.env), &info,
			&cbs, timeout, &s_data.local.proxy);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.local.proxy);
}

static void udp_proxy_stop(void)
{
	TST_LOG("%s \n", __func__);

	int res = mux_ip_proxy_destroy(s_data.local.proxy);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	s_data.local.proxy = NULL;
}

/** */
static void test_ip_proxy_udp(void)
{
	memset(&s_data, 0, sizeof(s_data));

	/* test udp */
	s_data.protocol.transport = MUX_IP_PROXY_TRANSPORT_UDP;
	s_data.protocol.application = MUX_IP_PROXY_APPLICATION_NONE;
	s_data.remote.host = REMOTE_ADDR;
	s_data.peer.resolve_cb = NULL;
	s_data.local.proxy_start_cb = &udp_proxy_start;
	s_data.local.proxy_stop_cb = &udp_proxy_stop;

	test_run();

	/* checks */
	CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.open_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.close_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.peer.resolve_call_cnt, 0);
}

/* Sync resolution test */

/** */
static void test_ip_proxy_sync_resolution(void)
{
	memset(&s_data, 0, sizeof(s_data));

	s_data.protocol.transport = MUX_IP_PROXY_TRANSPORT_UDP;
	s_data.protocol.application = MUX_IP_PROXY_APPLICATION_NONE;
	s_data.remote.host = REMOTE_ADDR_RESOLVE_SYNC;
	s_data.peer.resolve_cb = &srv_resolve_cb;
	s_data.local.proxy_start_cb = &udp_proxy_start;
	s_data.local.proxy_stop_cb = &udp_proxy_stop;

	test_run();

	/* checks */
	CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.open_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.close_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.peer.resolve_call_cnt, 1);
}

/* Async resolution test */

/** */
static void test_ip_proxy_async_resolution(void)
{
	memset(&s_data, 0, sizeof(s_data));

	s_data.protocol.transport = MUX_IP_PROXY_TRANSPORT_UDP;
	s_data.protocol.application = MUX_IP_PROXY_APPLICATION_NONE;
	s_data.remote.host = REMOTE_ADDR_RESOLVE_ASYNC;
	s_data.peer.resolve_cb = &srv_resolve_cb;
	s_data.local.proxy_start_cb = &udp_proxy_start;
	s_data.local.proxy_stop_cb = &udp_proxy_stop;

	test_run();

	/* checks */
	CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.open_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.close_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.peer.resolve_call_cnt, 1);
}

/* Async resolution failed test */

static void resolution_failed_stop(int err)
{
	CU_ASSERT_EQUAL(err, -ENODEV);

	mux_test_env_loop_stop(s_data.env);
}

/** */
static void test_ip_proxy_async_resolution_failed(void)
{
	memset(&s_data, 0, sizeof(s_data));

	s_data.protocol.transport = MUX_IP_PROXY_TRANSPORT_UDP;
	s_data.protocol.application = MUX_IP_PROXY_APPLICATION_NONE;
	s_data.remote.host = REMOTE_ADDR_RESOLVE_ASYNC_FAILED;
	s_data.peer.resolve_cb = &srv_resolve_cb;
	s_data.local.on_resolution_failed = &resolution_failed_stop;
	s_data.local.proxy_start_cb = &udp_proxy_start;
	s_data.local.proxy_stop_cb = &udp_proxy_stop;

	test_run();

	/* checks */
	CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.open_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.close_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.peer.resolve_call_cnt, 1);
}

/* Resolution failed test */

static void test_ip_proxy_resolution_failed(void)
{
	memset(&s_data, 0, sizeof(s_data));

	s_data.protocol.transport = MUX_IP_PROXY_TRANSPORT_UDP;
	s_data.protocol.application = MUX_IP_PROXY_APPLICATION_NONE;
	s_data.remote.host = REMOTE_ADDR_RESOLVE_FAILED;
	s_data.peer.resolve_cb = &srv_resolve_cb;
	s_data.local.proxy_start_cb = &udp_proxy_start;
	s_data.local.proxy_stop_cb = &udp_proxy_stop;
	s_data.local.on_resolution_failed = &resolution_failed_stop;

	test_run();

	/* checks */
	CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.open_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.close_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.peer.resolve_call_cnt, 1);
}

/* Resolution timeout test */

static void resolution_failed_timout_stop(int err)
{
	CU_ASSERT_EQUAL(err, -ETIMEDOUT);

	mux_test_env_loop_stop(s_data.env);
}

static void test_ip_proxy_resolution_timeout(void)
{
	memset(&s_data, 0, sizeof(s_data));

	s_data.protocol.transport = MUX_IP_PROXY_TRANSPORT_UDP;
	s_data.protocol.application = MUX_IP_PROXY_APPLICATION_NONE;
	s_data.remote.host = REMOTE_ADDR_RESOLVE_TIMEOUT;
	s_data.remote.timeout = 100;
	s_data.remote.timeout_enabled = 1;
	s_data.peer.resolve_cb = &srv_resolve_cb;
	s_data.local.proxy_start_cb = &udp_proxy_start;
	s_data.local.proxy_stop_cb = &udp_proxy_stop;
	s_data.local.on_resolution_failed = &resolution_failed_timout_stop;

	test_run();

	/* checks */
	CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.open_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.local.close_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 0);
	CU_ASSERT_EQUAL(s_data.peer.resolve_call_cnt, 1);
}

/* udp update remote test */

static void remote_update_cb(void)
{
	CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 3);
	CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 3);
	CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 2);
	CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.protocol.transport, MUX_IP_PROXY_TRANSPORT_UDP);
	CU_ASSERT_EQUAL(s_data.protocol.application, MUX_IP_PROXY_APPLICATION_NONE);
	local_send_msg();
}

static void udp_update_resolution_failed(int err)
{
	static int call_cnt = 0;
	TST_LOG("%s  \n", __func__);

	if (call_cnt == 0) {
		/* Resolution failed */
		CU_ASSERT_EQUAL(err, -ENODEV);

		CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 1);
		CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 1);
		CU_ASSERT_EQUAL(s_data.remote.msg_rcv_cnt, 1);
		CU_ASSERT_EQUAL(s_data.remote2.msg_rcv_cnt, 0);

		CU_ASSERT_EQUAL(s_data.local.open_call_cnt, 1);
		CU_ASSERT_EQUAL(s_data.local.close_call_cnt, 0);
		CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 1);
		CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 0);
		CU_ASSERT_EQUAL(s_data.peer.resolve_call_cnt, 1);
	} else if (call_cnt == 1) {
		/* Resolution timeout */
		CU_ASSERT_EQUAL(err, -ETIMEDOUT);

		CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 2);
		CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 2);
		CU_ASSERT_EQUAL(s_data.remote.msg_rcv_cnt, 2);
		CU_ASSERT_EQUAL(s_data.remote2.msg_rcv_cnt, 0);

		CU_ASSERT_EQUAL(s_data.local.open_call_cnt, 1);
		CU_ASSERT_EQUAL(s_data.local.close_call_cnt, 0);
		CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 2);
		CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 0);
		CU_ASSERT_EQUAL(s_data.peer.resolve_call_cnt, 2);
	}

	local_send_msg();
	call_cnt++;
}

static void local_recv_data(struct pomp_buffer *buf)
{
	int res;

	if (s_data.local.msg_rcv_cnt == 1) {
		/* First time change remote to remote2 failed*/

		CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 1);
		CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 1);
		CU_ASSERT_EQUAL(s_data.remote.msg_rcv_cnt, 1);
		CU_ASSERT_EQUAL(s_data.remote2.msg_rcv_cnt, 0);

		CU_ASSERT_EQUAL(s_data.local.open_call_cnt, 1);
		CU_ASSERT_EQUAL(s_data.local.close_call_cnt, 0);
		CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 0);
		CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 0);
		CU_ASSERT_EQUAL(s_data.peer.resolve_call_cnt, 0);

		/* Check mux_ip_proxy_set_udp_remote failed*/
		res = mux_ip_proxy_set_udp_remote(NULL,
				REMOTE2_ADDR_RESOLVE_SYNC, REMOTE2_PORT ,-1);
		CU_ASSERT_EQUAL_FATAL(res, -EINVAL);

		res = mux_ip_proxy_set_udp_remote(s_data.local.proxy,
				NULL, REMOTE2_PORT, -1);
		CU_ASSERT_EQUAL_FATAL(res, -EINVAL);

		res = mux_ip_proxy_set_udp_remote(s_data.local.proxy,
				REMOTE_ADDR, REMOTE_PORT, -1);
		CU_ASSERT_EQUAL_FATAL(res, -EALREADY);

		/* update by bad address */
		res = mux_ip_proxy_set_udp_remote(s_data.local.proxy,
				REMOTE_ADDR_RESOLVE_FAILED, REMOTE2_PORT, -1);
		CU_ASSERT_EQUAL_FATAL(res, 0);
	} else if (s_data.local.msg_rcv_cnt == 2) {
		/* Change remote to remote2 timeout */

		CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 2);
		CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 2);
		CU_ASSERT_EQUAL(s_data.remote.msg_rcv_cnt, 2);
		CU_ASSERT_EQUAL(s_data.remote2.msg_rcv_cnt, 0);

		CU_ASSERT_EQUAL(s_data.local.open_call_cnt, 1);
		CU_ASSERT_EQUAL(s_data.local.close_call_cnt, 0);
		CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 1);
		CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 0);
		CU_ASSERT_EQUAL(s_data.peer.resolve_call_cnt, 1);

		res = mux_ip_proxy_set_udp_remote(s_data.local.proxy,
				REMOTE2_ADDR_RESOLVE_TIMEOUT, REMOTE2_PORT, 50);
		CU_ASSERT_EQUAL_FATAL(res, 0);
	} else if (s_data.local.msg_rcv_cnt == 3) {
		/* Change remote to remote2 valide */

		CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 3);
		CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 3);
		CU_ASSERT_EQUAL(s_data.remote.msg_rcv_cnt, 3);
		CU_ASSERT_EQUAL(s_data.remote2.msg_rcv_cnt, 0);

		CU_ASSERT_EQUAL(s_data.local.open_call_cnt, 1);
		CU_ASSERT_EQUAL(s_data.local.close_call_cnt, 0);
		CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 2);
		CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 0);
		CU_ASSERT_EQUAL(s_data.peer.resolve_call_cnt, 2);

		res = mux_ip_proxy_set_udp_remote(s_data.local.proxy,
				REMOTE2_ADDR_RESOLVE_SYNC, REMOTE2_PORT, -1);
		CU_ASSERT_EQUAL_FATAL(res, 0);
	} else {
		/* Stop the test */
		mux_test_env_loop_stop(s_data.env);
	}
}

static void test_ip_proxy_udp_update_remote(void)
{
	memset(&s_data, 0, sizeof(s_data));

	/* test udp */
	s_data.protocol.transport = MUX_IP_PROXY_TRANSPORT_UDP;
	s_data.protocol.application = MUX_IP_PROXY_APPLICATION_NONE;
	s_data.remote.host = REMOTE_ADDR;
	s_data.remote2.host = REMOTE2_ADDR_RESOLVE_SYNC;
	s_data.peer.resolve_cb = &srv_resolve_cb;
	s_data.local.on_resolution_failed = &udp_update_resolution_failed;
	s_data.local.proxy_start_cb = &udp_proxy_start;
	s_data.local.proxy_stop_cb = &udp_proxy_stop;
	s_data.local.on_data_rcv = &local_recv_data;
	s_data.local.on_remote_update = &remote_update_cb;

	test_run();

	/* checks */
	CU_ASSERT_EQUAL(s_data.local.msg_snd_cnt, 4);
	CU_ASSERT_EQUAL(s_data.local.msg_rcv_cnt, 4);
	CU_ASSERT_EQUAL(s_data.remote.msg_rcv_cnt, 3);
	CU_ASSERT_EQUAL(s_data.remote2.msg_rcv_cnt, 1);

	CU_ASSERT_EQUAL(s_data.local.open_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.close_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.local.resolution_failed_call_cnt, 2);
	CU_ASSERT_EQUAL(s_data.local.remote_update_call_cnt, 1);
	CU_ASSERT_EQUAL(s_data.peer.resolve_call_cnt, 3);
}

/* udp large data test */

static void udp_large_data_local_recv_data(struct pomp_buffer *buf)
{
	TST_LOG("%s \n", __func__);

	int res;
	const char *rcv_data;
	size_t rcv_len;

	res = pomp_buffer_get_cdata(buf, (const void **)&rcv_data, &rcv_len, NULL);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(rcv_data);

	/* check data */
	size_t i;
	for (i = 0; i < rcv_len; i++) {
		CU_ASSERT_EQUAL(rcv_data[i], idx_to_data(s_data.local.rcv_cnt + i));
	}
	s_data.local.rcv_cnt += rcv_len;

	if (s_data.local.rcv_cnt < s_data.local.data_size) {
		/* send to to the second port */
		local_send_msg();
	} else {
		/* stop the test */
		mux_test_env_loop_stop(s_data.env);
	}
}

/** */
static void test_ip_proxy_udp_large_data(void)
{
	TST_LOG("%s", __func__);

	memset(&s_data, 0, sizeof(s_data));

	/* test udp */
	s_data.protocol.transport = MUX_IP_PROXY_TRANSPORT_UDP;
	s_data.protocol.application = MUX_IP_PROXY_APPLICATION_NONE;
	s_data.remote.host = REMOTE_ADDR;
	s_data.peer.resolve_cb = NULL;
	s_data.local.proxy_start_cb = &udp_proxy_start;
	s_data.local.proxy_stop_cb = &udp_proxy_stop;
	s_data.local.on_data_rcv = &udp_large_data_local_recv_data;

	s_data.local.data_size = 3 * 1024 * 1024;
	s_data.local.chunk_size = 1000;

	test_run();

	CU_ASSERT_EQUAL(s_data.local.snd_cnt, s_data.local.data_size);
	CU_ASSERT_EQUAL(s_data.local.rcv_cnt, s_data.local.data_size);
}

/* Disable some gcc warnings for test suite descriptions */
#ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wcast-qual"
#endif /* __GNUC__ */

/** */
static CU_TestInfo s_ip_proxy_tests[] = {
	{(char *)"new_ip_proxy_failed", &test_new_ip_proxy_failed},
	{(char *)"ip_proxy_tcp", &test_ip_proxy_tcp},
	{(char *)"ip_proxy_udp", &test_ip_proxy_udp},
	{(char *)"ip_proxy_sync_resolution", &test_ip_proxy_sync_resolution},
	{(char *)"ip_proxy_async_resolution", &test_ip_proxy_async_resolution},
	{(char *)"ip_proxy_async_resolution_failed", &test_ip_proxy_async_resolution_failed},
	{(char *)"ip_proxy_resolution_failed", &test_ip_proxy_resolution_failed},
	{(char *)"ip_proxy_resolution_timeout", &test_ip_proxy_resolution_timeout},
	{(char *)"ip_proxy_udp_update_remote", &test_ip_proxy_udp_update_remote},
	{(char *)"ip_proxy_tcp_large_data", &test_ip_proxy_tcp_large_data},
	{(char *)"ip_proxy_udp_large_data", &test_ip_proxy_udp_large_data},
	CU_TEST_INFO_NULL,
};

/** */
/*extern*/ CU_SuiteInfo g_suites_ip_proxy[] = {
	{(char *)"ip_proxy", NULL, NULL, s_ip_proxy_tests},
	CU_SUITE_INFO_NULL,
};
