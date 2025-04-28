/**
 *    Copyright (C) 2022 Parrot Drones SAS
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions
 *    are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *    * Neither the name of the Parrot Company nor the names
 *      of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *    FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *    PARROT COMPANY BE LIABLE FOR ANY DIRECT, INDIRECT,
 *    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *    OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 *    AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *    OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 *    OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *    SUCH DAMAGE.
 */

#include <errno.h>
#include <netinet/in.h>

#include "mux_sd_test.h"
#include "mux_sd_test_base.h"

struct mux_test_tip {
	enum mux_test_tip_type type;
	struct pomp_loop *loop;
	struct pomp_ctx *pctx;
	struct mux_ctx *mctx;

	struct pomp_conn *conn;
	struct mux_test_tip_cbs cbs;
};

static void tip_raw_cb(struct pomp_ctx *ctx,
		struct pomp_conn *conn,
		struct pomp_buffer *buf,
		void *userdata)
{
	struct mux_test_tip *tip = userdata;

	/* Decode read data, rx operation or channel queues will handle
	 * decoded data */
	mux_decode(tip->mctx, buf);
}

static int mux_tx_cb(struct mux_ctx *ctx, struct pomp_buffer *buf,
		void *userdata)
{
	struct mux_test_tip *tip = userdata;

	return pomp_ctx_send_raw_buf(tip->pctx, buf);
}

static void mux_rx_cb(struct mux_ctx *ctx, uint32_t chanid,
		enum mux_channel_event event, struct pomp_buffer *buf,
		void *userdata)
{
	struct mux_test_tip *tip = userdata;

	if (event == MUX_CHANNEL_DATA && tip->cbs.on_rcv_data != NULL)
		tip->cbs.on_rcv_data (tip, chanid, buf, tip->cbs.userdata);

	size_t len = 0;

	pomp_buffer_get_cdata(buf, NULL, &len, NULL);
}

static void mux_release_cb(struct mux_ctx *ctx, void *userdata)
{
}

static void tip_event_cb(struct pomp_ctx *ctx,
		enum pomp_event event,
		struct pomp_conn *conn,
		const struct pomp_msg *msg,
		void *userdata)
{
	struct mux_test_tip *tip = userdata;
	struct mux_ops ops = {
		.tx = &mux_tx_cb,
		.chan_cb = &mux_rx_cb,
		.release = &mux_release_cb,
		.resolve = tip->cbs.resolve,
		.userdata = tip,
	};

	switch (event) {
	case POMP_EVENT_CONNECTED:
		CU_ASSERT_PTR_NULL(tip->conn);

		ops.userdata = tip;
		tip->mctx = mux_new(-1, tip->loop, &ops, 0);
		CU_ASSERT_PTR_NOT_NULL_FATAL(tip->mctx);

		tip->conn = conn;
		tip->cbs.on_connect(tip, tip->cbs.userdata);
		break;

	case POMP_EVENT_DISCONNECTED:
		CU_ASSERT_EQUAL(tip->conn, conn);

		tip->cbs.on_disconnect(tip, tip->cbs.userdata);
		break;

	case POMP_EVENT_MSG:
		/* Never received for raw context */
		break;
	}
}

int mux_test_tip_new(struct pomp_loop *loop, enum mux_test_tip_type type,
		struct mux_test_tip_cbs *cbs, struct mux_test_tip **ret_tip)
{
	struct mux_test_tip *tip;

	if (loop == NULL ||
	    cbs == NULL ||
	    cbs->on_connect == NULL ||
	    cbs->on_disconnect == NULL)
		return -ENOMEM;

	tip = calloc(1, sizeof(*tip));
	CU_ASSERT_PTR_NULL_FATAL(tip->conn);

	tip->pctx = pomp_ctx_new_with_loop(&tip_event_cb, tip, loop);
	pomp_ctx_set_raw(tip->pctx, &tip_raw_cb);

	tip->type = type;
	tip->loop = loop;
	tip->cbs = *cbs;

	*ret_tip = tip;
	return 0;
}

int mux_test_tip_destroy(struct mux_test_tip *tip)
{
	pomp_ctx_destroy(tip->pctx);
	free(tip);
	return 0;
}

int mux_test_tip_start(struct mux_test_tip *tip)
{
	struct sockaddr_in addr;
	socklen_t addrlen = 0;

	/* Setup address */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(4321);
	addrlen = sizeof(addr);

	switch (tip->type) {
	case MUX_TEST_TIP_TYPE_CLIENT:
		pomp_ctx_connect(tip->pctx,
			(const struct sockaddr *)&addr, addrlen);
		break;
	case MUX_TEST_TIP_TYPE_SERVER:
		pomp_ctx_listen(tip->pctx,
			(const struct sockaddr *)&addr, addrlen);
		break;
	default:
		break;
	}

	return 0;
}

int mux_test_tip_stop(struct mux_test_tip *tip)
{
	int res;

	if (tip->mctx != NULL) {
		res = mux_stop(tip->mctx);
		CU_ASSERT_EQUAL(res, 0);
		mux_unref(tip->mctx);
		tip->mctx = NULL;
	}

	pomp_ctx_stop(tip->pctx);

	return 0;
}

struct mux_ctx *mux_test_tip_get_mux(struct mux_test_tip *tip)
{
	return (tip != NULL) ? tip->mctx : NULL;
}

struct mux_test_env {
	struct mux_test_env_cbs cbs;
	struct pomp_loop *loop;
	struct mux_test_tip *client;
	struct mux_test_tip *server;
	int running;
};

static void client_connect_cb(struct mux_test_tip *tip, void *userdata)
{
	struct mux_test_env *env = userdata;
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);

	if (env->cbs.cli_connect != NULL)
		env->cbs.cli_connect(env, env->cbs.userdata);
}

static void client_disconnect_cb(struct mux_test_tip *tip, void *userdata)
{
	struct mux_test_env *env = userdata;
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);

	if (env->cbs.cli_disconnect != NULL)
		env->cbs.cli_disconnect(env, env->cbs.userdata);

}

static void client_rcv_data_cb(struct mux_test_tip *tip,
		uint32_t chanid, struct pomp_buffer *buf, void *userdata)
{
	struct mux_test_env *env = userdata;
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);

	if (env->cbs.cli_rcv_data != NULL)
		env->cbs.cli_rcv_data(env, chanid, buf, env->cbs.userdata);
}

static void server_connect_cb(struct mux_test_tip *tip, void *userdata)
{
	struct mux_test_env *env = userdata;
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);

	if (env->cbs.srv_connect != NULL)
		env->cbs.srv_connect(env, env->cbs.userdata);
}

static void server_disconnect_cb(struct mux_test_tip *tip, void *userdata)
{
	struct mux_test_env *env = userdata;
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);

	if (env->cbs.srv_disconnect != NULL)
		env->cbs.srv_disconnect(env, env->cbs.userdata);
}

static void server_rcv_data_cb(struct mux_test_tip *tip,
		uint32_t chanid, struct pomp_buffer *buf, void *userdata)
{
	struct mux_test_env *env = userdata;
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);

	if (env->cbs.srv_rcv_data != NULL)
		env->cbs.srv_rcv_data(env, chanid, buf, env->cbs.userdata);
}

int mux_test_env_new(struct mux_test_env_cbs *cbs,
		struct mux_test_env **ret_env)
{
	int res;
	struct mux_test_env *env;
	struct mux_test_tip_cbs client_cbs = {
		.on_connect = &client_connect_cb,
		.on_disconnect = &client_disconnect_cb,
		.on_rcv_data = &client_rcv_data_cb,
	};

	struct mux_test_tip_cbs server_cbs = {
		.on_connect = &server_connect_cb,
		.on_disconnect = &server_disconnect_cb,
		.on_rcv_data = &server_rcv_data_cb,
	};

	CU_ASSERT_PTR_NOT_NULL_FATAL(cbs);

	env = calloc(1, sizeof(*env));
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);

	env->loop = pomp_loop_new();
	CU_ASSERT_PTR_NOT_NULL_FATAL(env->loop);

	client_cbs.userdata = env;
	res = mux_test_tip_new(env->loop, MUX_TEST_TIP_TYPE_CLIENT,
			&client_cbs, &env->client);
	CU_ASSERT_EQUAL(res, 0);

	server_cbs.resolve = cbs->srv_resolve;
	server_cbs.userdata = env;
	res = mux_test_tip_new(env->loop, MUX_TEST_TIP_TYPE_SERVER,
			&server_cbs, &env->server);
	CU_ASSERT_EQUAL(res, 0);

	env->cbs = *cbs;
	*ret_env = env;
	return 0;
}

int mux_test_env_destroy(struct mux_test_env *env)
{
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);

	int res = mux_test_tip_destroy(env->client);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	res = mux_test_tip_destroy(env->server);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	res = pomp_loop_destroy(env->loop);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	free(env);
	return 0;
}

int mux_test_env_start(struct mux_test_env *env)
{
	int res;
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);

	res = mux_test_tip_start(env->server);
	CU_ASSERT_EQUAL(res, 0);

	res = mux_test_tip_start(env->client);
	CU_ASSERT_EQUAL(res, 0);

	return res;
}

int mux_test_env_start_cli(struct mux_test_env *env)
{
	int res;
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);

	res = mux_test_tip_start(env->client);
	CU_ASSERT_EQUAL(res, 0);

	return res;
}

int mux_test_env_start_srv(struct mux_test_env *env)
{
	int res;
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);

	res = mux_test_tip_start(env->server);
	CU_ASSERT_EQUAL(res, 0);

	return res;
}

struct pomp_loop *mux_test_env_get_loop(struct mux_test_env *env)
{
	return (env != NULL) ? env->loop : NULL;
}

struct mux_ctx *mux_test_env_get_cli_mux(struct mux_test_env *env)
{
	return (env != NULL) ? mux_test_tip_get_mux(env->client) : NULL;
}

struct mux_ctx *mux_test_env_get_srv_mux(struct mux_test_env *env)
{
	return (env != NULL) ? mux_test_tip_get_mux(env->server) : NULL;
}

int mux_test_env_run_loop(struct mux_test_env *env)
{
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);

	env->running = 1;
	while (env->running) {
		pomp_loop_wait_and_process(env->loop, -1);
	}
	pomp_loop_idle_flush(env->loop);

	return 0;
}

void mux_test_env_loop_stop(struct mux_test_env *env)
{
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);
	env->running = 0;
}

void mux_test_env_stop(struct mux_test_env *env)
{
	int res = mux_test_tip_stop(env->server);
	CU_ASSERT_EQUAL(res, 0);

	res = mux_test_tip_stop(env->client);
	CU_ASSERT_EQUAL(res, 0);
}

int mux_test_env_stop_cli(struct mux_test_env *env)
{
	int res;
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);

	res = mux_test_tip_stop(env->client);
	CU_ASSERT_EQUAL(res, 0);

	return res;
}

int mux_test_env_stop_srv(struct mux_test_env *env)
{
	int res;
	CU_ASSERT_PTR_NOT_NULL_FATAL(env);

	res = mux_test_tip_stop(env->server);
	CU_ASSERT_EQUAL(res, 0);

	return res;
}