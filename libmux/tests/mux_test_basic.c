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

#define LOG_TAG "mux_test_basic"
#define TST_LOG(_fmt, ...) fprintf(stderr, LOG_TAG ": " _fmt "\n", ##__VA_ARGS__)

#define TST_CHAN_ID 5

#define DATA_MIN 'A'
#define DATA_MAX 'Z'
#define idx_to_data(_i) (((_i) % (DATA_MAX - DATA_MIN)) + DATA_MIN)

/** */
struct test_data {
	struct mux_test_env *env;

	size_t data_size;
	size_t chunk_size;

	struct {
		struct mux_ctx *mux;

		/* counters */
		size_t snd_cnt;
		size_t rcv_cnt;

		struct pomp_buffer *buf;
	} cli;

	struct {
		struct mux_ctx *mux;

		/* counters */
		size_t snd_cnt;
		size_t rcv_cnt;
	} srv;
};

static struct test_data s_data;

static int tx_cb(struct mux_ctx *ctx, struct pomp_buffer *buf,
			void *userdata)
{
	return 0;
}

/** */
static void basic_tests(void)
{
	TST_LOG("%s \n", __func__);

	struct mux_ctx *mux = NULL;

	mux = mux_new(-1, NULL, NULL, 0);
	CU_ASSERT_PTR_NULL(mux);

	struct mux_ops ops = {};
	mux = mux_new(-1, NULL, &ops, 0);
	CU_ASSERT_PTR_NULL(mux);

	ops.tx = &tx_cb;
	mux = mux_new(1, NULL, &ops, 0);
	CU_ASSERT_PTR_NULL(mux);

	mux = mux_new(-1, NULL, &ops, 0);
	CU_ASSERT_PTR_NOT_NULL(mux);


	int res = mux_channel_open(mux, 0, NULL, NULL);
	CU_ASSERT_EQUAL(res, -EINVAL);

	res = mux_channel_open(mux, 1024, NULL, NULL);
	CU_ASSERT_EQUAL(res, -EINVAL);

	res = mux_channel_open(NULL, 100, NULL, NULL);
	CU_ASSERT_EQUAL(res, -EINVAL);

	res = mux_channel_open(mux, 100, NULL, NULL);
	CU_ASSERT_EQUAL(res, 0);

	res = mux_channel_close(NULL, 100);
	CU_ASSERT_EQUAL(res, -EINVAL);

	res = mux_channel_close(mux, 200);
	CU_ASSERT_EQUAL(res, -ENOENT);

	res = mux_channel_close(mux, 100);
	CU_ASSERT_EQUAL(res, 0);


	mux_unref(mux);
}

static void cli_send_data(void)
{
	char *data;
	size_t cap;
	int res = pomp_buffer_get_data(s_data.cli.buf, (void **)&data, NULL, &cap);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(data);
	CU_ASSERT_TRUE_FATAL(cap >= s_data.chunk_size);

	/* fill data */
	size_t i;
	size_t data_size = MIN(s_data.data_size - s_data.cli.snd_cnt, s_data.chunk_size);
	for (i = 0; i < data_size; i++) {
		data[i] = idx_to_data(s_data.cli.snd_cnt + i);
	}
	res = pomp_buffer_set_len(s_data.cli.buf, data_size);
	CU_ASSERT_EQUAL_FATAL(res, 0);

	res = mux_encode(s_data.cli.mux, TST_CHAN_ID, s_data.cli.buf);
	CU_ASSERT_EQUAL(res, 0);

	s_data.cli.snd_cnt += data_size;

}

static void cli_connect_cb(struct mux_test_env *env, void *userdata)
{
	TST_LOG("%s", __func__);

	s_data.cli.mux = mux_test_env_get_cli_mux(env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.cli.mux);

	int res = mux_channel_open(s_data.cli.mux, TST_CHAN_ID, NULL, &s_data);
	CU_ASSERT_EQUAL(res, 0);

	s_data.cli.buf = pomp_buffer_new(s_data.chunk_size);
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.cli.buf);

	if (s_data.cli.mux != NULL && s_data.srv.mux != NULL)
		cli_send_data();
}

static void cli_disconnect_cb(struct mux_test_env *env, void *userdata)
{
	TST_LOG("%s", __func__);

	s_data.srv.mux = NULL;

	pomp_buffer_unref(s_data.cli.buf);
	s_data.cli.buf = NULL;
}

static void cli_rcv_data_cb(struct mux_test_env *env, uint32_t chanid,
		struct pomp_buffer *buf, void *userdata)
{
	int res;

	size_t rcv_len;
	const char *rcv_data;
	res = pomp_buffer_get_cdata(buf, (const void **)&rcv_data, &rcv_len, NULL);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(rcv_data);

	/* check data */
	size_t i;
	for (i = 0; i < rcv_len; i++) {
		CU_ASSERT_EQUAL(rcv_data[i], idx_to_data(s_data.cli.rcv_cnt + i));
	}

	s_data.cli.rcv_cnt += rcv_len;

	if (s_data.cli.snd_cnt < s_data.data_size)
		cli_send_data();

	if (s_data.cli.rcv_cnt >= s_data.data_size)
		mux_test_env_loop_stop(s_data.env);
}


static void srv_connect_cb(struct mux_test_env *env, void *userdata)
{
	TST_LOG("%s", __func__);

	s_data.srv.mux = mux_test_env_get_srv_mux(env);
	CU_ASSERT_PTR_NOT_NULL_FATAL(s_data.srv.mux);

	int res = mux_channel_open(s_data.srv.mux, TST_CHAN_ID, NULL, &s_data);
	CU_ASSERT_EQUAL(res, 0);

	if (s_data.cli.mux != NULL && s_data.srv.mux != NULL)
		cli_send_data();
}

static void srv_disconnect_cb(struct mux_test_env *env, void *userdata)
{
	TST_LOG("%s", __func__);

	s_data.srv.mux = NULL;
}

static void srv_rcv_data_cb(struct mux_test_env *env,
		uint32_t chanid, struct pomp_buffer *buf, void *userdata)
{
	int res;

	const char *data;
	size_t len;
	res = pomp_buffer_get_cdata(buf, (const void **)&data, &len, NULL);
	CU_ASSERT_EQUAL_FATAL(res, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(data);

	s_data.srv.rcv_cnt += len;

	// repeat
	res = mux_encode(s_data.srv.mux, TST_CHAN_ID, buf);
	CU_ASSERT_EQUAL(res, 0);
	s_data.srv.snd_cnt += len;
}


/** */
static void long_data_send(void)
{
	int res;

	TST_LOG("%s", __func__);

	memset(&s_data, 0, sizeof(s_data));

	s_data.data_size = 2 * 1024 * 1024;
	s_data.chunk_size = 1400;

	struct mux_test_env_cbs env_cbs = {
		.cli_connect = &cli_connect_cb,
		.cli_disconnect = &cli_disconnect_cb,
		.cli_rcv_data = &cli_rcv_data_cb,

		.srv_connect = &srv_connect_cb,
		.srv_disconnect = &srv_disconnect_cb,
		.srv_rcv_data = &srv_rcv_data_cb,
	};

	res = mux_test_env_new(&env_cbs, &s_data.env);
	CU_ASSERT_EQUAL(res, 0);

	res = mux_test_env_start(s_data.env);
	CU_ASSERT_EQUAL(res, 0);

	/* Run loop */
	res = mux_test_env_run_loop(s_data.env);
	CU_ASSERT_EQUAL(res, 0);

	/* Close channels */
	res = mux_channel_close(s_data.srv.mux, TST_CHAN_ID);
	CU_ASSERT_EQUAL(res, 0);
	res = mux_channel_close(s_data.cli.mux, TST_CHAN_ID);
	CU_ASSERT_EQUAL(res, 0);

	mux_test_env_stop(s_data.env);

	res = mux_test_env_destroy(s_data.env);
	CU_ASSERT_EQUAL(res, 0);
	s_data.env = NULL;

	CU_ASSERT_EQUAL(s_data.cli.snd_cnt, s_data.data_size);
	CU_ASSERT_EQUAL(s_data.cli.rcv_cnt, s_data.data_size);
	CU_ASSERT_EQUAL(s_data.srv.snd_cnt, s_data.data_size);
	CU_ASSERT_EQUAL(s_data.srv.rcv_cnt, s_data.data_size);
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
	{(char *)"long_data_send", &long_data_send},
	CU_TEST_INFO_NULL,
};

/** */
/*extern*/ CU_SuiteInfo g_suites_basic[] = {
	{(char *)"basic", NULL, NULL, s_basic_tests},
	CU_SUITE_INFO_NULL,
};
