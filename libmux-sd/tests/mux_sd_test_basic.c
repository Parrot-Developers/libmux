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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mux_sd_test.h"
#include "mux_sd_test_publisher.h"
#include "mux_sd_test_base.h"

#define LOG_TAG "mux_test_basic"
#define TST_LOG(_fmt, ...) fprintf(stderr, LOG_TAG ": " _fmt "\n", ##__VA_ARGS__)

struct test_sd {
		int used;
		struct {
			int available;
			struct mux_sd_info info;

			int must_be_started;
			struct pomp_ctx *pctx;
			uint8_t *data_to_send;
			size_t data_to_send_len;

			void (*on_add)(struct test_sd *);
			void (*on_remove)(struct test_sd *);
			void (*on_data_rcv)(struct test_sd *, struct pomp_buffer *);
			void (*on_disconnect)(struct test_sd *);
		} client;

		struct {
			int published;
			struct mux_sd_info info;
			struct pomp_ctx *pctx;
		} server;
};

#define MAX_SD_COUNT 5

/** */
struct test_data {
	struct mux_test_env *env;

	struct test_sd sds[MAX_SD_COUNT];

	struct pomp_timer *timer;

	struct {
		void (*on_connect)(void);
		struct mux_sd_browser *browser;

		uint32_t added_cb_count;
		uint32_t removed_cb_count;
		uint32_t list_cb_count;
	} local;

	struct {
		void (*on_connect)(void);
		struct mux_sd_test_publisher *publisher;
	} peer;
};
static struct test_data s_data;

static int srv_resolve_cb(struct mux_ctx *ctx, const char *hostname,
		uint32_t *addr, void *userdata)
{
	if (!strcmp(hostname, "skycontroller")) {
		*addr = inet_addr("127.0.0.1");
		return 0;
	} else {
		return -ENODEV;
	}
}

static void cli_connect_cb(struct mux_test_env *env, void *userdata)
{
	TST_LOG("%s", __func__);

	if (s_data.local.on_connect)
		s_data.local.on_connect();
}

static void cli_disconnect_cb(struct mux_test_env *env, void *userdata)
{
	TST_LOG("%s", __func__);
}

static void srv_connect_cb(struct mux_test_env *env, void *userdata)
{
	TST_LOG("%s", __func__);

	if (s_data.peer.on_connect)
		s_data.peer.on_connect();
}

static void srv_disconnect_cb(struct mux_test_env *env, void *userdata)
{
	TST_LOG("%s", __func__);
}

/** */
static void test_run(void)
{
	TST_LOG("%s \n", __func__);

	struct mux_test_env_cbs env_cbs = {
		.cli_connect = &cli_connect_cb,
		.cli_disconnect = &cli_disconnect_cb,

		.srv_connect = &srv_connect_cb,
		.srv_disconnect = &srv_disconnect_cb,
		.srv_resolve = &srv_resolve_cb,
	};

	int res = mux_test_env_new(&env_cbs, &s_data.env);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.env);

	res = mux_test_env_start(s_data.env);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	// Run loop
	res = mux_test_env_run_loop(s_data.env);
	CU_ASSERT_EQUAL(res, 0);

	mux_test_env_stop(s_data.env);
	res = mux_test_env_destroy(s_data.env);
	CU_ASSERT_EQUAL_FATAL(res, 0);
}

/* ############################################################################# */

static void client_raw_cb(struct pomp_ctx *ctx, struct pomp_conn *conn,
		struct pomp_buffer *buf, void *userdata)
{
	struct test_sd *sd = userdata;
	TST_LOG("%s : %s %s %s:%d\n", __func__, sd->client.info.name, sd->client.info.type, sd->client.info.addr, sd->client.info.port);

	size_t len = 0;
	const void *cdata;
	int res = pomp_buffer_get_cdata(buf, &cdata, &len, NULL);
	CU_ASSERT_EQUAL(res, 0);

	// check if the data received is equal to the data sent
	CU_ASSERT_EQUAL(len, sd->client.data_to_send_len);
	if (len == sd->client.data_to_send_len) {
		CU_ASSERT_EQUAL(memcmp(cdata, sd->client.data_to_send, len), 0);
	}

	if (sd->client.on_data_rcv) {
		sd->client.on_data_rcv(sd, buf);
	}
}

static void client_send_msg(struct test_sd *sd)
{
	TST_LOG("%s \n", __func__);

	struct pomp_buffer *buf = pomp_buffer_new_with_data(sd->client.data_to_send, sd->client.data_to_send_len);
	CU_ASSERT_PTR_NOT_NULL_FATAL(buf);

	int res = pomp_ctx_send_raw_buf(sd->client.pctx, buf);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	pomp_buffer_unref(buf);
}

static void test_sd_client_stop(struct test_sd *sd)
{
	TST_LOG("%s : %s %s %s:%d", __func__, sd->client.info.name, sd->client.info.type, sd->client.info.addr, sd->client.info.port);

	CU_ASSERT_PTR_NOT_NULL_FATAL(sd);
	CU_ASSERT_TRUE_FATAL(sd->used);
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd->client.pctx);

	int res = pomp_ctx_stop(sd->client.pctx);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	res = pomp_ctx_destroy(sd->client.pctx);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	sd->client.pctx = NULL;

	if (sd->client.on_disconnect) {
		sd->client.on_disconnect(sd);
	}
}

static void test_sd_client_stop_idle_cb (void *userdata)
{
	TST_LOG("%s \n", __func__);

	struct test_sd *sd = userdata;
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd);

	if (sd->client.pctx != NULL)
		test_sd_client_stop(userdata);
}

static void client_event_cb(struct pomp_ctx *ctx, enum pomp_event event,
		struct pomp_conn *conn, const struct pomp_msg *msg,
		void *userdata)
{
	TST_LOG("%s \n", __func__);

	struct test_sd *sd = userdata;
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd);

	switch (event) {
	case POMP_EVENT_CONNECTED:
		TST_LOG("client %s %d connected \n",
				sd->client.info.name,
				sd->client.info.port);

		client_send_msg(sd);

		break;
	case POMP_EVENT_DISCONNECTED: {
		TST_LOG("client %s %d disconnected \n",
				sd->client.info.name,
				sd->client.info.port);

		struct pomp_loop *pomp = mux_test_env_get_loop(s_data.env);
		CU_ASSERT_PTR_NOT_NULL_FATAL(pomp);
		int res = pomp_loop_idle_add(pomp, &test_sd_client_stop_idle_cb, sd);
		CU_ASSERT_EQUAL_FATAL(res, 0);
		break;
	}
	case POMP_EVENT_MSG:
		/* Never received for raw context */
		CU_FAIL_FATAL("client_event_cb POMP_EVENT_MSG not expected");
		break;
	}
}

static void txt_records_cmp(char **txt_records_1, size_t txt_records_cnt_1,
			    char **txt_records_2, size_t txt_records_cnt_2)
{
	if (txt_records_1 == NULL) {
		CU_ASSERT_EQUAL(txt_records_cnt_1, 0);
		CU_ASSERT_PTR_NULL(txt_records_2);
		CU_ASSERT_EQUAL(txt_records_cnt_2, 0);
	} else {
		CU_ASSERT_PTR_NOT_NULL(txt_records_2);
		CU_ASSERT_EQUAL(txt_records_cnt_1, txt_records_cnt_2);

		for (size_t i = 0; i < txt_records_cnt_1; i++) {
			CU_ASSERT_STRING_EQUAL(txt_records_1[i], txt_records_2[i]);
		}
	}
}

static int txt_records_dup(
		char **txt_records_src, size_t txt_records_cnt_src,
		char ***txt_records_dst, size_t *txt_records_cnt_dst)
{
	CU_ASSERT_PTR_NOT_NULL_FATAL(txt_records_dst);
	CU_ASSERT_PTR_NOT_NULL_FATAL(txt_records_cnt_dst);

	if (txt_records_src == NULL || txt_records_cnt_src > 0)
		return 0;

	char **txt_records = calloc(txt_records_cnt_src, sizeof(*txt_records));
	CU_ASSERT_PTR_NOT_NULL_FATAL(txt_records);

	for (size_t i = 0; i < txt_records_cnt_src; i++) {
		txt_records[i] = strdup(txt_records_src[i]);
		if (txt_records[i] == NULL) {
			goto error;
		}
	}

	*txt_records_dst = txt_records;
	*txt_records_cnt_dst = txt_records_cnt_src;

	return 0;
error:
	/* cleanup */
	for (size_t i = 0; i < txt_records_cnt_src; i++) {
		if (txt_records[i] != NULL)
			free(txt_records[i]);
	}
	free(txt_records);
	return -ENOMEM;
}

static void test_sd_client_removed(struct test_sd *sd)
{
	TST_LOG("%s : %s %s %s:%d", __func__, sd->client.info.name, sd->client.info.type, sd->client.info.addr, sd->client.info.port);

	CU_ASSERT_PTR_NOT_NULL_FATAL(sd);
	CU_ASSERT_TRUE_FATAL(sd->used);
	CU_ASSERT_TRUE_FATAL(sd->client.available);
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd->client.info.name);
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd->client.info.type);
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd->client.info.addr);
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd->client.info.domain);

	if (sd->client.pctx != NULL)
		test_sd_client_stop(sd);

	free(sd->client.info.name);
	free(sd->client.info.type);
	free(sd->client.info.addr);
	free(sd->client.info.domain);
	if (sd->client.info.txt_records != NULL) {
		for (size_t i = 0; i < sd->client.info.txt_records_cnt; i++) {
			free(sd->client.info.txt_records[i]);
		}
		free(sd->client.info.txt_records);
	}

	sd->client.info = (struct mux_sd_info) {};
	sd->client.available = 0;

	if (sd->client.on_remove != NULL) {
		sd->client.on_remove(sd);
	}
}

static void test_sd_client_added(struct test_sd *sd, struct mux_sd_info *sd_info)
{
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd);
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd_info);
	CU_ASSERT_FALSE_FATAL(sd->client.available);
	CU_ASSERT_PTR_NULL_FATAL(sd->client.info.name);
	CU_ASSERT_PTR_NULL_FATAL(sd->client.info.type);
	CU_ASSERT_PTR_NULL_FATAL(sd->client.info.addr);
	CU_ASSERT_PTR_NULL_FATAL(sd->client.info.domain);

	TST_LOG("%s : %s %s %s:%d", __func__, sd_info->name, sd_info->type, sd_info->addr, sd_info->port);

	sd->client.info = (struct mux_sd_info) {
		.name = strdup(sd_info->name),
		.type = strdup(sd_info->type),
		.addr = strdup(sd_info->addr),
		.port = sd_info->port,
		.domain = strdup(sd_info->domain),
	};
	int res = txt_records_dup(sd_info->txt_records, sd_info->txt_records_cnt,
			&sd->client.info.txt_records, &sd->client.info.txt_records_cnt);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	sd->client.available = 1;

	if (sd->client.on_add != NULL) {
		sd->client.on_add(sd);
	}
}

static void test_sd_client_start(struct test_sd *sd) {
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd);
	CU_ASSERT_TRUE_FATAL(sd->client.available);

	TST_LOG("%s : %s %s:%d", __func__, sd->client.info.name, sd->client.info.addr, sd->client.info.port);

	struct pomp_loop *pomp = mux_test_env_get_loop(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pomp);

	sd->client.pctx = pomp_ctx_new_with_loop(&client_event_cb, sd, pomp);
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd->client.pctx);

	int res = pomp_ctx_set_raw(sd->client.pctx, &client_raw_cb);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	struct sockaddr_in sockaddr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr(sd->client.info.addr),
		.sin_port = htons(sd->client.info.port),
	};

	res = pomp_ctx_connect(sd->client.pctx, (const struct sockaddr *)&sockaddr, sizeof(sockaddr));
	CU_ASSERT_EQUAL_FATAL(res, 0);
}

static void browser_sd_added(struct mux_sd_browser *self,
			     struct mux_sd_info *sd_info, void *userdata)
{
	CU_ASSERT_PTR_NOT_NULL_FATAL(self);
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd_info);
	CU_ASSERT_PTR_EQUAL(userdata, &s_data);

	TST_LOG("%s %s %s:%d", __func__, sd_info->name, sd_info->addr, sd_info->port);

	s_data.local.added_cb_count++;

	int found = 0;
	struct test_sd *sd = NULL;
	for (size_t i = 0; i < MAX_SD_COUNT; i++) {
		sd = &s_data.sds[i];
		if (sd->used &&
		    sd->server.published &&
		    strcmp(sd_info->name, sd->server.info.name) == 0 &&
		    strcmp(sd_info->domain, sd->server.info.domain) == 0) {
			found = 1;
			break;
		}
	}

	CU_ASSERT_TRUE_FATAL(found);

	CU_ASSERT_STRING_EQUAL(sd_info->addr, "127.0.0.1");
	CU_ASSERT_NOT_EQUAL(sd_info->port, 0);

	txt_records_cmp(sd_info->txt_records, sd_info->txt_records_cnt,
			sd->server.info.txt_records, sd->server.info.txt_records_cnt);

	test_sd_client_added(sd, sd_info);
	if (sd->client.must_be_started) {
		test_sd_client_start(sd);
	}
}

static void browser_sd_removed(struct mux_sd_browser *self,
				struct mux_sd_info *sd_info, void *userdata)
{
	CU_ASSERT_PTR_NOT_NULL_FATAL(self);
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd_info);
	CU_ASSERT_PTR_EQUAL(userdata, &s_data);

	TST_LOG("%s %s %s:%d", __func__, sd_info->name, sd_info->addr, sd_info->port);

	s_data.local.removed_cb_count++;

	int found = 0;
	struct test_sd *sd = NULL;
	for (size_t i = 0; i < MAX_SD_COUNT; i++) {
		sd = &s_data.sds[i];

		if (sd->used &&
		    sd->client.available &&
		    strcmp(sd_info->name, sd->client.info.name) == 0 &&
		    sd_info->port == sd->client.info.port &&
		    strcmp(sd_info->addr, sd->client.info.addr) == 0 &&
		    strcmp(sd_info->domain, sd->client.info.domain) == 0) {
			found = 1;
			break;
		}
	}

	CU_ASSERT_TRUE_FATAL(found);
	txt_records_cmp(sd_info->txt_records, sd_info->txt_records_cnt,
			sd->server.info.txt_records, sd->server.info.txt_records_cnt);

	test_sd_client_removed(sd);
	// if the client is started; stop it
	if (sd->client.pctx != NULL) {
		test_sd_client_stop(sd);
	}
}

static void signe_service_tests_local_on_connect(void) {
	TST_LOG("%s", __func__);

	struct mux_ctx *mux = mux_test_env_get_cli_mux(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(mux);

	struct mux_sd_browser_param param = {
	};

	struct mux_sd_browser_cbs cbs = {
		.added = &browser_sd_added,
		.removed = &browser_sd_removed,
		.userdata = &s_data,
	};

	int res = mux_sd_browser_new(mux, &param, &cbs, &s_data.local.browser);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.local.browser);

	struct pomp_loop *pomp = mux_test_env_get_loop(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pomp);

	res = mux_sd_browser_start(s_data.local.browser, pomp);
	CU_ASSERT_EQUAL_FATAL(res, 0);
}

static void server_raw_cb(struct pomp_ctx *ctx, struct pomp_conn *conn,
		struct pomp_buffer *buf, void *userdata)
{
	struct test_sd *sd = userdata;
	TST_LOG("%s : %s %s:%d\n", __func__, sd->server.info.name, sd->server.info.addr, sd->server.info.port);

	// Repeat data received
	CU_ASSERT_PTR_NOT_NULL_FATAL(buf);
	int res = pomp_conn_send_raw_buf(conn, buf);
	CU_ASSERT_EQUAL_FATAL(res, 0);
}

static void server_event_cb(struct pomp_ctx *ctx, enum pomp_event event,
		struct pomp_conn *conn, const struct pomp_msg *msg,
		void *userdata)
{
	TST_LOG("%s \n", __func__);

	struct test_sd *test_sd = userdata;
	CU_ASSERT_PTR_NOT_NULL_FATAL(test_sd);

	switch (event) {
	case POMP_EVENT_CONNECTED:
		TST_LOG("server %s %d connected \n",
				test_sd->server.info.name,
				test_sd->server.info.port);

		break;
	case POMP_EVENT_DISCONNECTED:
		TST_LOG("server %s %d disconnected \n",
				test_sd->server.info.name,
				test_sd->server.info.port);
		break;
	case POMP_EVENT_MSG:
		/* Never received for raw context */
		CU_FAIL_FATAL("server_event_cb POMP_EVENT_MSG not expected");
		break;
	}
}

static void test_sd_server_stop(struct test_sd *sd)
{
	TST_LOG("%s : %s %s:%d\n", __func__, sd->server.info.name, sd->server.info.addr, sd->server.info.port);

	CU_ASSERT_PTR_NOT_NULL_FATAL(sd);
	CU_ASSERT_TRUE_FATAL(sd->used);
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd->server.pctx);

	if (sd->server.published &&
	    mux_sd_test_publisher_is_started(s_data.peer.publisher)) {
		int res = mux_sd_test_publisher_remove(s_data.peer.publisher,
						       &sd->server.info);
		CU_ASSERT_EQUAL_FATAL(res, 0);
	}
	sd->server.published = 0;

	pomp_ctx_stop(sd->server.pctx);
	pomp_ctx_destroy(sd->server.pctx);
	sd->server.pctx = NULL;
}

static void test_sd_server_start(struct test_sd *sd)
{
	TST_LOG("%s : %s %s %s:%d\n", __func__, sd->server.info.name, sd->server.info.type, sd->server.info.addr, sd->server.info.port);

	CU_ASSERT_PTR_NOT_NULL_FATAL(sd);
	CU_ASSERT_TRUE(sd->used);
	CU_ASSERT_PTR_NULL_FATAL(sd->server.pctx);

	struct pomp_loop *pomp = mux_test_env_get_loop(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pomp);

	sd->server.pctx = pomp_ctx_new_with_loop(&server_event_cb, sd, pomp);
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd->server.pctx);

	int res = pomp_ctx_set_raw(sd->server.pctx, &server_raw_cb);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = htons(sd->server.info.port),
	};
	res = pomp_ctx_listen(sd->server.pctx, (const struct sockaddr *)&addr, sizeof(addr));
	CU_ASSERT_EQUAL_FATAL(res, 0);

	res = mux_sd_test_publisher_add(s_data.peer.publisher, &sd->server.info);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	sd->server.published = 1;
}

/* #############################################################################
	signe_service_tests
*/

static void signe_service_tests_idle_stop_cb(void *userdata)
{
	TST_LOG("%s \n", __func__);

	// stop publisher
	int res = mux_sd_test_publisher_stop(s_data.peer.publisher);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	res = mux_sd_test_publisher_destroy(s_data.peer.publisher);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	s_data.peer.publisher = NULL;

	// stop browser
	res = mux_sd_browser_stop(s_data.local.browser);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	res = mux_sd_browser_destroy(s_data.local.browser);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	s_data.local.browser = NULL;

	// stop test
	mux_test_env_loop_stop(s_data.env);
}

static void signe_service_tests_client_disconnected(struct test_sd *sd)
{
	TST_LOG("%s", __func__);

	int res = pomp_loop_idle_add(mux_test_env_get_loop(s_data.env),
				     &signe_service_tests_idle_stop_cb, NULL);
	CU_ASSERT_EQUAL_FATAL(res, 0);
}

static void signe_service_tests_client_rcv_data(struct test_sd *sd, struct pomp_buffer *buf)
{
	TST_LOG("%s", __func__);

	// stop server 0
	test_sd_server_stop(&s_data.sds[0]);
}

static void signe_service_tests_peer_on_connect(void)
{
	TST_LOG("%s", __func__);

	struct mux_ctx *mux = mux_test_env_get_srv_mux(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(mux);

	int res = mux_sd_test_publisher_new(mux, &s_data.peer.publisher);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.peer.publisher);

	struct pomp_loop *pomp = mux_test_env_get_loop(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pomp);

	res = mux_sd_test_publisher_start(s_data.peer.publisher, pomp);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	// start service 0
	test_sd_server_start(&s_data.sds[0]);
}

/** */
static void signe_service_tests(void)
{
	TST_LOG("%s \n", __func__);

	memset(&s_data, 0, sizeof(s_data));
	s_data.local.on_connect = &signe_service_tests_local_on_connect;
	s_data.peer.on_connect = &signe_service_tests_peer_on_connect;
	s_data.sds[0] = (struct test_sd) {
		.used = 1,
		.server = {
			.info = (struct mux_sd_info) {
				.name = "service_0",
				.type = "_parrot._tcp",
				.addr = "127.0.0.1",
				.port = 1120,
				.domain = ".local",
			},
			.pctx = NULL,
		},
		.client = {
			.must_be_started = 1,
			.data_to_send = (uint8_t *)"coucou service_0",
			.data_to_send_len = 17,
			.on_data_rcv = &signe_service_tests_client_rcv_data,
			.on_disconnect = &signe_service_tests_client_disconnected,
		},
	};

	test_run();

	// checks
	for (size_t i = 0; i < MAX_SD_COUNT; i++) {
		struct test_sd *sd = &s_data.sds[i];
		if (sd->used) {
			CU_ASSERT_FALSE(sd->server.published);
			CU_ASSERT_FALSE(sd->client.available);
		}
	}

	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 1);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 1);
}


/* #############################################################################
	BROWSING TESTS
*/

static void browsing_tests_idle_stop_cb(void *userdata)
{
	TST_LOG("%s \n", __func__);

	// stop publisher
	int res = mux_sd_test_publisher_stop(s_data.peer.publisher);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	s_data.sds[0].server.published = 0;
	s_data.sds[1].server.published = 0;

	// stop service 0
	test_sd_server_stop(&s_data.sds[0]);

	res = mux_sd_test_publisher_destroy(s_data.peer.publisher);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	s_data.peer.publisher = NULL;

	// stop browser
	res = mux_sd_browser_stop(s_data.local.browser);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	res = mux_sd_browser_destroy(s_data.local.browser);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	s_data.local.browser = NULL;

	// stop test
	mux_test_env_loop_stop(s_data.env);
}

static void browsing_tests_list_cb(struct mux_sd_browser *self,
		struct mux_sd_info *sd, size_t idx, void *userdata)
{
	CU_ASSERT_PTR_NOT_NULL_FATAL(self);
	CU_ASSERT_PTR_NOT_NULL_FATAL(sd);
	CU_ASSERT_PTR_EQUAL(userdata, &s_data);
	CU_ASSERT_EQUAL(idx, s_data.local.list_cb_count);
	s_data.local.list_cb_count++;

	CU_ASSERT_STRING_EQUAL(sd->name, s_data.sds[idx].client.info.name);
	CU_ASSERT_STRING_EQUAL(sd->type, s_data.sds[idx].client.info.type);
	CU_ASSERT_STRING_EQUAL(sd->addr, s_data.sds[idx].client.info.addr);
	CU_ASSERT_EQUAL(sd->port, s_data.sds[idx].client.info.port);
	CU_ASSERT_STRING_EQUAL(sd->domain, s_data.sds[idx].client.info.domain);
}

static void browsing_tests_service1_removed()
{
	TST_LOG("%s \n", __func__);

	// disable timeout
	int res = pomp_timer_destroy(s_data.timer);
	CU_ASSERT_EQUAL(res, 0);

	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 4);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 3);

	s_data.local.list_cb_count = 0;
	res = mux_sd_browser_list(s_data.local.browser, &browsing_tests_list_cb, &s_data);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_EQUAL(s_data.local.list_cb_count, 1);

	// stop test
	res = pomp_loop_idle_add(mux_test_env_get_loop(s_data.env),
				 &browsing_tests_idle_stop_cb, NULL);
	CU_ASSERT_EQUAL_FATAL(res, 0);
}

static void browsing_tests_timeout_cb(struct pomp_timer *timer, void *userdata)
{
	TST_LOG("%s", __func__);

	int res = pomp_timer_destroy(s_data.timer);
	CU_ASSERT_EQUAL(res, 0);

	CU_FAIL_FATAL("browsing_tests_timeout_cb should not called");
}

static void browsing_tests_sd_added_after_browsing_start(struct test_sd *sd)
{
	TST_LOG("%s \n", __func__);

	// waiting for the two browsings
	if (s_data.local.added_cb_count != 4) {
		return;
	}

	// disable timeout
	int res = pomp_timer_destroy(s_data.timer);
	CU_ASSERT_EQUAL(res, 0);

	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 4);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 2);

	// expect the service 1 will be removed after server 1 stop
	s_data.sds[0].client.on_add = NULL;
	s_data.sds[1].client.on_add = NULL;
	s_data.sds[1].client.on_remove = &browsing_tests_service1_removed;

	// stop service 1
	test_sd_server_stop(&s_data.sds[1]);

	// set test timeout
	struct pomp_loop *pomp = mux_test_env_get_loop(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pomp);
	s_data.timer = pomp_timer_new(pomp, &browsing_tests_timeout_cb, NULL);
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.timer);
	res = pomp_timer_set(s_data.timer, 1000);
	CU_ASSERT_EQUAL_FATAL(res, 0);
}

static void browsing_tests_sd_added_after_publisher_start(struct test_sd *sd)
{
	TST_LOG("%s \n", __func__);

	// waiting for the two browsings
	if (s_data.local.added_cb_count != 2) {
		return;
	}

	// disable timeout
	int res = pomp_timer_destroy(s_data.timer);
	CU_ASSERT_EQUAL(res, 0);

	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 2);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 0);

	res = mux_sd_browser_list(s_data.local.browser, &browsing_tests_list_cb, &s_data);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_EQUAL(s_data.local.list_cb_count, 2);

	res = mux_sd_browser_stop(s_data.local.browser);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 2);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 2);

	s_data.local.list_cb_count = 0;
	res = mux_sd_browser_list(s_data.local.browser, &browsing_tests_list_cb, &s_data);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_EQUAL(s_data.local.list_cb_count, 0);

	// expect the two services will be broswed after start publisher start
	s_data.sds[0].client.on_add = &browsing_tests_sd_added_after_browsing_start;
	s_data.sds[1].client.on_add = &browsing_tests_sd_added_after_browsing_start;

	struct pomp_loop *pomp = mux_test_env_get_loop(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pomp);
	res = mux_sd_browser_start(s_data.local.browser, pomp);
	CU_ASSERT_EQUAL(res, 0);

	// set test timeout
	s_data.timer = pomp_timer_new(pomp, &browsing_tests_timeout_cb, NULL);
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.timer);
	res = pomp_timer_set(s_data.timer, 1000);
	CU_ASSERT_EQUAL_FATAL(res, 0);
}

static void browsing_tests_local_on_connect(void)
{
	TST_LOG("%s", __func__);

	struct mux_ctx *mux = mux_test_env_get_cli_mux(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(mux);

	struct mux_sd_browser_param param = {
	};

	struct mux_sd_browser_cbs cbs = {
		.added = &browser_sd_added,
		.removed = &browser_sd_removed,
		.userdata = &s_data,
	};
	int res = mux_sd_browser_new(mux, &param, &cbs, &s_data.local.browser);
	CU_ASSERT_PTR_NOT_NULL(s_data.local.browser);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 0);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 0);

	struct pomp_loop *pomp = mux_test_env_get_loop(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pomp);

	res = mux_sd_browser_start(s_data.local.browser, pomp);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 0);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 0);
}

static void browsing_tests_peer_on_connect(void)
{
	TST_LOG("%s", __func__);

	struct mux_ctx *mux = mux_test_env_get_srv_mux(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(mux);

	int res = mux_sd_test_publisher_new(mux, &s_data.peer.publisher);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.peer.publisher);

	struct pomp_loop *pomp = mux_test_env_get_loop(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pomp);

	// start service 0
	test_sd_server_start(&s_data.sds[0]);

	// start service 1
	test_sd_server_start(&s_data.sds[1]);

	// expect the two services will be broswed after start publisher start
	s_data.sds[0].client.on_add = &browsing_tests_sd_added_after_publisher_start;
	s_data.sds[1].client.on_add = &browsing_tests_sd_added_after_publisher_start;

	res = mux_sd_test_publisher_start(s_data.peer.publisher, pomp);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	// set test timeout
	s_data.timer = pomp_timer_new(pomp, &browsing_tests_timeout_cb, NULL);
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.timer);
	res = pomp_timer_set(s_data.timer, 1000);
	CU_ASSERT_EQUAL_FATAL(res, 0);
}

static void browsing_tests(void)
{
	TST_LOG("%s \n", __func__);

	memset(&s_data, 0, sizeof(s_data));
	s_data.local.on_connect = &browsing_tests_local_on_connect;
	s_data.peer.on_connect = &browsing_tests_peer_on_connect;
	s_data.sds[0] = (struct test_sd) {
		.used = 1,
		.server = {
			.info = (struct mux_sd_info) {
				.name = "service_0",
				.type = "_parrot._tcp",
				.addr = "127.0.0.1",
				.port = 1120,
				.domain = ".local",
			},
			.pctx = NULL,
		},
	};
	s_data.sds[1] = (struct test_sd) {
		.used = 1,
		.server = {
			.info = (struct mux_sd_info) {
				.name = "service_1",
				.type = "_other._tcp",
				.addr = "127.0.0.1",
				.port = 1121,
				.domain = "other.local",
				.txt_records = (char *[]){"A=1", "B=2", "C"},
				.txt_records_cnt = 3,
			},
			.pctx = NULL,
		},
	};

	test_run();

	// checks
	for (size_t i = 0; i < MAX_SD_COUNT; i++) {
		struct test_sd *sd = &s_data.sds[i];
		if (sd->used) {
			CU_ASSERT_FALSE(sd->server.published);
			CU_ASSERT_FALSE(sd->client.available);
		}
	}
}

/* #############################################################################
	BROWSING FILTERED TESTS
*/

static void browsing_filtered_tests_timeout_cb(struct pomp_timer *timer, void *userdata)
{
	TST_LOG("%s", __func__);

	int res = pomp_timer_destroy(s_data.timer);
	CU_ASSERT_EQUAL(res, 0);

	CU_FAIL_FATAL("browsing_filtered_tests_timeout_cb should not called");
}

static void browsing_filtered_tests_idle_stop_cb(void *userdata)
{
	TST_LOG("%s \n", __func__);

	// stop publisher
	int res = mux_sd_test_publisher_stop(s_data.peer.publisher);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	// start all services
	for (size_t i = 0; i < MAX_SD_COUNT; i++) {
		struct test_sd *sd = &s_data.sds[i];
		if (sd->used) {
			test_sd_server_stop(sd);
		}
	}

	res = mux_sd_test_publisher_destroy(s_data.peer.publisher);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	s_data.peer.publisher = NULL;

	// stop browser
	res = mux_sd_browser_stop(s_data.local.browser);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	res = mux_sd_browser_destroy(s_data.local.browser);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	s_data.local.browser = NULL;

	// stop test
	mux_test_env_loop_stop(s_data.env);
}

static void browsing_filtered_tests_sd_added_after_publisher_start(struct test_sd *sd)
{
	TST_LOG("%s \n", __func__);

	CU_ASSERT_STRING_EQUAL(sd->client.info.type, "_parrot._tcp");
	CU_ASSERT_STRING_EQUAL(sd->client.info.domain, "parrot.local");

	// waiting for the two browsings
	if (s_data.local.added_cb_count != 2) {
		return;
	}

	// disable timeout
	int res = pomp_timer_destroy(s_data.timer);
	CU_ASSERT_EQUAL(res, 0);

	// stop test
	res = pomp_loop_idle_add(mux_test_env_get_loop(s_data.env),
				 &browsing_filtered_tests_idle_stop_cb, NULL);
	CU_ASSERT_EQUAL_FATAL(res, 0);
}

static void browsing_filtered_tests_local_on_connect(void)
{
	TST_LOG("%s", __func__);

	struct mux_ctx *mux = mux_test_env_get_cli_mux(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(mux);

	struct mux_sd_browser_param param = {
		.types = (char *[]) {"_parrot._tcp"},
		.type_cnt = 1,
		.domains = (char *[]) {"parrot.local"},
		.domain_cnt = 1,
	};

	struct mux_sd_browser_cbs cbs = {
		.added = &browser_sd_added,
		.removed = &browser_sd_removed,
		.userdata = &s_data,
	};
	int res = mux_sd_browser_new(mux, &param, &cbs, &s_data.local.browser);
	CU_ASSERT_PTR_NOT_NULL(s_data.local.browser);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 0);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 0);

	struct pomp_loop *pomp = mux_test_env_get_loop(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pomp);

	res = mux_sd_browser_start(s_data.local.browser, pomp);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 0);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 0);
}

static void browsing_filtered_tests_peer_on_connect(void)
{
	TST_LOG("%s", __func__);

	struct mux_ctx *mux = mux_test_env_get_srv_mux(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(mux);

	int res = mux_sd_test_publisher_new(mux, &s_data.peer.publisher);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.peer.publisher);

	struct pomp_loop *pomp = mux_test_env_get_loop(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pomp);

	// start all services
	for (size_t i = 0; i < MAX_SD_COUNT; i++) {
		struct test_sd *sd = &s_data.sds[i];
		if (sd->used) {
			test_sd_server_start(sd);
		}
	}

	res = mux_sd_test_publisher_start(s_data.peer.publisher, pomp);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	// set test timeout
	s_data.timer = pomp_timer_new(pomp, &browsing_filtered_tests_timeout_cb, NULL);
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.timer);
	res = pomp_timer_set(s_data.timer, 1000);
	CU_ASSERT_EQUAL_FATAL(res, 0);
}

static void browsing_filtered_tests(void)
{
	TST_LOG("%s \n", __func__);

	memset(&s_data, 0, sizeof(s_data));
	s_data.local.on_connect = &browsing_filtered_tests_local_on_connect;
	s_data.peer.on_connect = &browsing_filtered_tests_peer_on_connect;
	s_data.sds[0] = (struct test_sd) {
		.used = 1,
		.server = {
			.info = (struct mux_sd_info) {
				.name = "service_0",
				.type = "_parrot._tcp",
				.addr = "127.0.0.1",
				.port = 1120,
				.domain = "parrot.local",
			},
			.pctx = NULL,
		},
		// expect the services will be broswed after start publisher start
		.client.on_add = &browsing_filtered_tests_sd_added_after_publisher_start,
	};
	s_data.sds[1] = (struct test_sd) {
		.used = 1,
		.server = {
			.info = (struct mux_sd_info) {
				.name = "service_1",
				.type = "_parrot._tcp",
				.addr = "127.0.0.1",
				.port = 1121,
				.domain = "other.local",
			},
			.pctx = NULL,
		},
	};
	s_data.sds[2] = (struct test_sd) {
		.used = 1,
		.server = {
			.info = (struct mux_sd_info) {
				.name = "service_2",
				.type = "_other._tcp",
				.addr = "127.0.0.1",
				.port = 1122,
				.domain = ".local",
			},
			.pctx = NULL,
		},
	};
	s_data.sds[3] = (struct test_sd) {
		.used = 1,
		.server = {
			.info = (struct mux_sd_info) {
				.name = "service_3",
				.type = "_other._tcp",
				.addr = "127.0.0.1",
				.port = 1123,
				.domain = "other.local",
			},
			.pctx = NULL,
		},
	};
	s_data.sds[4] = (struct test_sd) {
		.used = 1,
		.server = {
			.info = (struct mux_sd_info) {
				.name = "service_4",
				.type = "_parrot._tcp",
				.addr = "127.0.0.1",
				.port = 1124,
				.domain = "parrot.local",
			},
			.pctx = NULL,
		},
		// expect the services will be broswed after start publisher start
		.client.on_add = &browsing_filtered_tests_sd_added_after_publisher_start,
	};

	test_run();

	// checks
	for (size_t i = 0; i < MAX_SD_COUNT; i++) {
		struct test_sd *sd = &s_data.sds[i];
		if (sd->used) {
			CU_ASSERT_FALSE(sd->server.published);
			CU_ASSERT_FALSE(sd->client.available);
		}
	}
}

/* #############################################################################
	BASIC TESTS
*/

static void basic_tests_browser_sd_added(struct mux_sd_browser *self,
		struct mux_sd_info *sd_info, void *userdata)
{
	CU_ASSERT_PTR_NOT_NULL(self);
	CU_ASSERT_PTR_NOT_NULL(sd_info);
	CU_ASSERT_PTR_EQUAL(userdata, &s_data);

	s_data.local.added_cb_count++;

}

static void basic_tests_browser_sd_removed(struct mux_sd_browser *self,
		struct mux_sd_info *sd_info, void *userdata)
{
	CU_ASSERT_PTR_NOT_NULL(self);
	CU_ASSERT_PTR_NOT_NULL(sd_info);
	CU_ASSERT_PTR_EQUAL(userdata, &s_data);

	s_data.local.removed_cb_count++;
}

static void basic_tests_list_cb(struct mux_sd_browser *self,
		struct mux_sd_info *sd, size_t idx, void *userdata)
{
	CU_FAIL("basic_tests_list_cb should not called")
}

static void basic_tests_local_on_connect(void)
{
	TST_LOG("%s", __func__);

	struct mux_ctx *mux = mux_test_env_get_cli_mux(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(mux);

	struct mux_sd_browser_param param = {
	};

	struct mux_sd_browser_cbs cbs = {
		.added = &basic_tests_browser_sd_added,
		.removed = &basic_tests_browser_sd_removed,
		.userdata = &s_data,
	};

	int res = mux_sd_browser_new(NULL, &param, &cbs, &s_data.local.browser);
	CU_ASSERT_EQUAL(res, -EINVAL);
	CU_ASSERT_PTR_NULL(s_data.local.browser);
	res = mux_sd_browser_new(mux, NULL, &cbs, &s_data.local.browser);
	CU_ASSERT_EQUAL(res, -EINVAL);
	CU_ASSERT_PTR_NULL(s_data.local.browser);
	res = mux_sd_browser_new(mux, &param, NULL, &s_data.local.browser);
	CU_ASSERT_EQUAL(res, -EINVAL);
	CU_ASSERT_PTR_NULL(s_data.local.browser);
	res = mux_sd_browser_new(mux, &param, &cbs, NULL);
	CU_ASSERT_EQUAL(res, -EINVAL);
	CU_ASSERT_PTR_NULL(s_data.local.browser);

	cbs = (struct mux_sd_browser_cbs) {
		.added = NULL,
		.removed = &basic_tests_browser_sd_removed,
		.userdata = &s_data,
	};
	res = mux_sd_browser_new(mux, &param, &cbs, &s_data.local.browser);
	CU_ASSERT_PTR_NULL(s_data.local.browser);
	CU_ASSERT_EQUAL(res, -EINVAL);

	cbs = (struct mux_sd_browser_cbs) {
		.added = &basic_tests_browser_sd_added,
		.removed = NULL,
		.userdata = &s_data,
	};
	res = mux_sd_browser_new(mux, &param, &cbs, &s_data.local.browser);
	CU_ASSERT_PTR_NULL(s_data.local.browser);
	CU_ASSERT_EQUAL(res, -EINVAL);

	cbs = (struct mux_sd_browser_cbs) {
		.added = &basic_tests_browser_sd_added,
		.removed = &basic_tests_browser_sd_removed,
		.userdata = NULL,
	};
	res = mux_sd_browser_new(mux, &param, &cbs, &s_data.local.browser);
	CU_ASSERT_PTR_NOT_NULL(s_data.local.browser);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 0);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 0);
	res = mux_sd_browser_destroy(s_data.local.browser);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 0);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 0);
	s_data.local.browser = NULL;

	res = mux_sd_browser_destroy(NULL);
	CU_ASSERT_EQUAL(res, -EINVAL);

	cbs = (struct mux_sd_browser_cbs) {
		.added = &basic_tests_browser_sd_added,
		.removed = &basic_tests_browser_sd_removed,
		.userdata = &s_data,
	};
	res = mux_sd_browser_new(mux, &param, &cbs, &s_data.local.browser);
	CU_ASSERT_PTR_NOT_NULL(s_data.local.browser);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 0);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 0);

	struct pomp_loop *pomp = mux_test_env_get_loop(s_data.env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pomp);

	res = mux_sd_browser_list(NULL, &basic_tests_list_cb, &s_data);
	CU_ASSERT_EQUAL(res, -EINVAL);

	res = mux_sd_browser_list(s_data.local.browser, NULL, &s_data);
	CU_ASSERT_EQUAL(res, -EINVAL);

	res = mux_sd_browser_list(s_data.local.browser, &basic_tests_list_cb, NULL);
	CU_ASSERT_EQUAL(res, 0);

	res = mux_sd_browser_list(s_data.local.browser, &basic_tests_list_cb, &s_data);
	CU_ASSERT_EQUAL(res, 0);

	res = mux_sd_browser_start(NULL, pomp);
	CU_ASSERT_EQUAL(res, -EINVAL);
	res = mux_sd_browser_start(s_data.local.browser, NULL);
	CU_ASSERT_EQUAL(res, -EINVAL);
	res = mux_sd_browser_start(s_data.local.browser, pomp);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 0);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 0);

	res = mux_sd_browser_start(s_data.local.browser, pomp);
	CU_ASSERT_EQUAL(res, -EINVAL);
	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 0);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 0);

	res = mux_sd_browser_stop(s_data.local.browser);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 0);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 0);

	res = mux_sd_browser_stop(s_data.local.browser);
	CU_ASSERT_EQUAL(res, -EINVAL);
	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 0);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 0);

	res = mux_sd_browser_destroy(s_data.local.browser);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_EQUAL(s_data.local.added_cb_count, 0);
	CU_ASSERT_EQUAL(s_data.local.removed_cb_count, 0);
	s_data.local.browser = NULL;

	// stop test
	mux_test_env_loop_stop(s_data.env);
}

static void basic_tests_peer_on_connect(void)
{
	TST_LOG("%s", __func__);
}

static void basic_tests(void)
{
	TST_LOG("%s \n", __func__);

	memset(&s_data, 0, sizeof(s_data));
	s_data.local.on_connect = &basic_tests_local_on_connect;
	s_data.peer.on_connect = &basic_tests_peer_on_connect;

	test_run();
}

/* #############################################################################
	Test Part
*/

/* Disable some gcc warnings for test suite descriptions */
#ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wcast-qual"
#endif /* __GNUC__ */

/** */
static CU_TestInfo s_basic_tests[] = {
	{(char *)"basic_tests", &basic_tests},
	{(char *)"browsing_tests", &browsing_tests},
	{(char *)"browsing_filtered_tests", &browsing_filtered_tests},
	{(char *)"signe_service_tests", &signe_service_tests},
	CU_TEST_INFO_NULL,
};

/** */
/*extern*/ CU_SuiteInfo g_suites_basic[] = {
	{(char *)"basic", NULL, NULL, s_basic_tests},
	CU_SUITE_INFO_NULL,
};