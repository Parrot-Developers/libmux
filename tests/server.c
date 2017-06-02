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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <libARSAL/ARSAL.h>
#include <libARNetworkAL/ARNetworkAL.h>
#include <libmux.h>
#include <libARNetwork/ARNetwork.h>
#include <libARCommands/ARCommands.h>

#include "libpomp.h"
#define ULOG_TAG mux_server
#include "ulog.h"
ULOG_DECLARE_TAG(mux_server);

#include "arparams.h"

#define LOGD(_fmt, ...)	ULOGD(_fmt, ##__VA_ARGS__)
#define LOGI(_fmt, ...)	ULOGI(_fmt, ##__VA_ARGS__)
#define LOGW(_fmt, ...)	ULOGW(_fmt, ##__VA_ARGS__)
#define LOGE(_fmt, ...)	ULOGE(_fmt, ##__VA_ARGS__)

#define LOG_ERR(_func, _err) \
	LOGE("%s err=%d(%s)", _func, _err, strerror(_err))

/** Log error with fd and errno */
#define LOG_FD_ERR(_func, _fd, _err) \
	LOGE("%s(fd=%d) err=%d(%s)", _func, _fd, _err, strerror(_err))

/** */
struct app {
	int                       running;
	struct pomp_loop          *loop;
	struct pomp_ctx           *pompctx;
	struct pomp_conn          *pompconn;

	struct mux_ctx            *muxctx;
	pthread_t                  mux_thread;

	ARCOMMANDS_Decoder_t       *decoder;
	ARNETWORK_IOBufferParam_t  *c2d_params;
	size_t                     c2d_params_nb;
	ARNETWORK_IOBufferParam_t  *d2c_params;
	size_t                     d2c_params_nb;
	ARNETWORKAL_Manager_t      *netal_mngr;
	ARNETWORK_Manager_t        *net_mngr;
	int                        read_efd;
	uint8_t                    read_buf[2048];
	pthread_t                  recv_thread;
	pthread_t                  send_thread;
};

/** */
static struct app s_app = {
	.running = 0,
	.loop = NULL,
	.pompctx = NULL,
	.pompconn = NULL,
	.muxctx = NULL,
	.decoder = NULL,
	.c2d_params = NULL,
	.c2d_params_nb = 0,
	.d2c_params = NULL,
	.d2c_params_nb = 0,
	.netal_mngr = NULL,
	.net_mngr = NULL,
	.read_efd = -1,
};

/**
 */
static int on_mux_tx(struct mux_ctx *ctx, struct pomp_buffer *buf,
		void *userdata)
{
	/* FIXME: called in mux thread, not main loop */
	return pomp_ctx_send_raw_buf(s_app.pompctx, buf);
}

/**
 */
static void on_mux_rx(struct mux_ctx *ctx, uint32_t chanid,
		enum mux_channel_event event,
		struct pomp_buffer *buf,
		void *userdata)
{
	size_t len = 0;

	/* TODO: do something with received data */
	pomp_buffer_get_cdata(buf, NULL, &len, NULL);
	LOGI("rx channel=%u len=%zu", chanid, len);
}

/**
 */
static void log_cmd(uint8_t *buf, size_t size)
{
	eARCOMMANDS_DECODER_ERROR cmd_dec_err = ARCOMMANDS_DECODER_OK;
	char strcmd[512] = "";
	cmd_dec_err = ARCOMMANDS_Decoder_DescribeBuffer(
			buf, size, strcmd, sizeof(strcmd));
	if (cmd_dec_err != ARCOMMANDS_DECODER_OK) {
		LOGE("ARCOMMANDS_Decoder_DescribeBuffer err=%d",
				cmd_dec_err);
	} else {
		LOGI("%s", strcmd);
	}
}

/**
 */
static int read_data(void)
{
	int res = -1;
	eARNETWORK_ERROR net_err = ARNETWORK_OK;
	eARCOMMANDS_DECODER_ERROR cmd_dec_err = ARCOMMANDS_DECODER_OK;
	size_t i = 0;
	int read_size = 0;

	static const int ids[] = {
		NETWORK_CD_NONACK_ID,
		NETWORK_CD_ACK_ID,
		NETWORK_CD_EMERGENCY_ID,
	};

	/* Read buffer */
	for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
		/* Try to read buffer */
		read_size = 0;
		net_err = ARNETWORK_Manager_TryReadData(s_app.net_mngr,
				ids[i],
				s_app.read_buf,
				(int)sizeof(s_app.read_buf),
				&read_size);
		if (net_err == ARNETWORK_ERROR_BUFFER_EMPTY)
			continue;

		if (net_err != ARNETWORK_OK) {
			LOGE("ARNETWORK_Manager_TryReadData err=%d(%s)",
					net_err,
					ARNETWORK_Error_ToString(net_err));
			continue;
		}

		res = 0;
		log_cmd(s_app.read_buf, read_size);

		cmd_dec_err = ARCOMMANDS_Decoder_DecodeCommand(
				s_app.decoder,
				s_app.read_buf,
				read_size);
		if (cmd_dec_err != ARCOMMANDS_DECODER_OK && cmd_dec_err !=
				ARCOMMANDS_DECODER_ERROR_NO_CALLBACK) {
			LOGE("ARCOMMANDS_Decoder_DecodeCommand err=%d",
					cmd_dec_err);
		}
	}

	return res;
}

/**
 */
static void network_read_efd_cb(int fd, uint32_t revents, void *userdata)
{
	int res = 0;
	uint64_t value = 0;

	/* Read eventfd value */
	do {
		res = (int)read(s_app.read_efd, &value, sizeof(value));
	} while (res < 0 && errno == EINTR);

	/* Read and dispatch buffer */
	do {
		res = read_data();
	} while (res == 0);
}

/**
 */
static void *mux_thread(void *userdata)
{
	mux_run(s_app.muxctx);
	return NULL;
}

/**
 */
static void *send_thread(void *userdata)
{
	ARNETWORK_Manager_SendingThreadRun(s_app.net_mngr);
	return NULL;
}

/**
 */
static void *recv_thread(void *userdata)
{
	ARNETWORK_Manager_ReceivingThreadRun(s_app.net_mngr);
	return NULL;
}

/**
 */
static void network_disconnect_cb(ARNETWORK_Manager_t *net_mngr,
		ARNETWORKAL_Manager_t *netal_mngr,
		void *userdata)
{
	/* Nothing to do, we will be notified of disconnection by another way */
}

/**
 */
static eARNETWORK_MANAGER_CALLBACK_RETURN send_cb(int iobufid,
		uint8_t *data,
		void *userdata,
		eARNETWORK_MANAGER_CALLBACK_STATUS status)
{
	return ARNETWORK_MANAGER_CALLBACK_RETURN_DEFAULT;
}

/**
 */
static void pcmd_cb(uint8_t flag, int8_t roll, int8_t pitch, int8_t yaw,
		int8_t gaz, uint32_t timestampAndSeqNum, void *userdata)
{
	eARCOMMANDS_GENERATOR_ERROR cmd_err = ARCOMMANDS_GENERATOR_OK;
	eARNETWORK_ERROR net_err = ARNETWORK_OK;
	uint8_t buf[512];
	int32_t len = 0;

	/* codecheck_ignore[LONG_LINE] */
	cmd_err = ARCOMMANDS_Generator_GenerateARDrone3GPSSettingsStateGPSFixStateChanged(
			buf, (int32_t)sizeof(buf), &len,
			0 /* _fixed */);
	if (cmd_err != ARCOMMANDS_GENERATOR_OK) {
		LOGE("ARCOMMANDS_Generator: err=%d", cmd_err);
	} else {
		net_err = ARNETWORK_Manager_SendData(s_app.net_mngr,
				NETWORK_DC_ACK_ID,
				buf, len,
				NULL, &send_cb, 1);
		if (net_err != ARNETWORK_OK) {
			LOGE("ARNETWORK_Manager_SendData: err=%d(%s)",
					net_err,
					ARNETWORK_Error_ToString(net_err));
		}
	}
}

/**
 */
static void on_connected(void)
{
	int res = 0;
	eARCOMMANDS_DECODER_ERROR cmd_err = ARCOMMANDS_DECODER_OK;
	eARNETWORKAL_ERROR netal_err = ARNETWORKAL_OK;
	eARNETWORK_ERROR net_err = ARNETWORK_OK;
	struct mux_ops ops;
	LOGI("Connected");

	/* Setup mux context */
	memset(&ops, 0, sizeof(ops));
	ops.tx = &on_mux_tx;
	ops.chan_cb = &on_mux_rx;
	s_app.muxctx = mux_new(-1, NULL, &ops, 0);

	/* create arsdk decoder */
	s_app.decoder = ARCOMMANDS_Decoder_NewDecoder(&cmd_err);
	if (cmd_err != ARCOMMANDS_DECODER_OK)
		LOGE("ARCOMMANDS_Decoder_NewDecoder: err=%d", cmd_err);

	/* create arsdk commands */
	s_app.c2d_params_nb = sizeof(s_c2d_params) / sizeof(s_c2d_params[0]);
	s_app.c2d_params = malloc(sizeof(s_c2d_params));
	s_app.d2c_params_nb = sizeof(s_d2c_params) / sizeof(s_d2c_params[0]);
	s_app.d2c_params = malloc(sizeof(s_d2c_params));
	memcpy(s_app.c2d_params, s_c2d_params, sizeof(s_c2d_params));
	memcpy(s_app.d2c_params, s_d2c_params, sizeof(s_d2c_params));

	/* Create NetworkAL manager */
	s_app.netal_mngr = ARNETWORKAL_Manager_New(&netal_err);
	if (netal_err != ARNETWORKAL_OK) {
		LOGE("ARNETWORKAL_Manager_New: err=%d(%s)",
				netal_err,
				ARNETWORKAL_Error_ToString(netal_err));
	}

	/* Setup NetworkAL over mux */
	netal_err = ARNETWORKAL_Manager_InitMuxNetwork(
			s_app.netal_mngr, s_app.muxctx);
	if (netal_err != ARNETWORKAL_OK) {
		LOGE("ARNETWORKAL_Manager_InitMuxNetwork: err=%d(%s)",
				netal_err,
				ARNETWORKAL_Error_ToString(netal_err));
	}

	/* Create Network manager */
	s_app.net_mngr = ARNETWORK_Manager_New(s_app.netal_mngr,
			s_app.d2c_params_nb,
			s_app.d2c_params,
			s_app.c2d_params_nb,
			s_app.c2d_params,
			0,
			&network_disconnect_cb,
			NULL,
			&net_err);
	if (net_err != ARNETWORK_OK) {
		LOGE("ARNETWORK_Manager_New: err=%d(%s)",
				net_err,
				ARNETWORK_Error_ToString(net_err));
	}

	/* Get input data event fd, monitor IN EVENT */
	net_err = ARNETWORK_Manager_GetInputDataEventFd(s_app.net_mngr,
			&s_app.read_efd);
	if (net_err != ARNETWORK_OK) {
		LOGE("ARNETWORK_Manager_GetInputDataEventFd: err=%d(%s)",
				net_err,
				ARNETWORK_Error_ToString(net_err));
	}
	res = pomp_loop_add(s_app.loop, s_app.read_efd, POMP_FD_EVENT_IN,
			&network_read_efd_cb, NULL);
	if (res < 0)
		LOG_ERR("pomp_loop_add", -res);

	/* Create mux thread */
	res = pthread_create(&s_app.mux_thread, NULL, &mux_thread, NULL);
	if (res != 0)
		LOG_ERR("pthread_create", res);

	/* Create sender thread */
	res = pthread_create(&s_app.send_thread, NULL, &send_thread, NULL);
	if (res != 0)
		LOG_ERR("pthread_create", res);

	/* Create receiver thread */
	res = pthread_create(&s_app.recv_thread, NULL, &recv_thread, NULL);
	if (res != 0)
		LOG_ERR("pthread_create", res);

	ARCOMMANDS_Decoder_SetARDrone3PilotingPCMDCb(s_app.decoder,
			&pcmd_cb, NULL);
}

/**
 */
static void on_disconnected(void)
{
	int res = 0;
	LOGI("Disconnected");

	/* Stop mux, this will stop all channels and unblock all queues */
	res = mux_stop(s_app.muxctx);
	if (res < 0)
		LOG_ERR("mux_stop", -res);

	/* Stop Network manager */
	if (s_app.net_mngr != NULL) {
		ARNETWORK_Manager_Stop(s_app.net_mngr);
		pthread_join(s_app.send_thread, NULL);
		pthread_join(s_app.recv_thread, NULL);

		/* Stop monitoring event */
		pomp_loop_remove(s_app.loop, s_app.read_efd);
		s_app.read_efd = -1;

		/* Stop NetworkAL manager */
		ARNETWORKAL_Manager_CloseMuxNetwork(s_app.netal_mngr);

		/* Free resources */
		ARNETWORK_Manager_Delete(&s_app.net_mngr);
		ARNETWORKAL_Manager_Delete(&s_app.netal_mngr);
		ARCOMMANDS_Decoder_DeleteDecoder(&s_app.decoder);
		free(s_app.c2d_params);
		free(s_app.d2c_params);
		s_app.c2d_params = NULL;
		s_app.d2c_params = NULL;
	}

	/* Release mux */
	pthread_join(s_app.mux_thread, NULL);
	mux_unref(s_app.muxctx);
	s_app.muxctx = NULL;
}

/**
 */
static void server_event_cb(struct pomp_ctx *ctx,
		enum pomp_event event,
		struct pomp_conn *conn,
		const struct pomp_msg *msg,
		void *userdata)
{
	switch (event) {
	case POMP_EVENT_CONNECTED:
		if (s_app.pompconn != NULL) {
			LOGI("Reject connection");
			pomp_conn_disconnect(conn);
		} else {
			s_app.pompconn = conn;
			on_connected();
		}
		break;

	case POMP_EVENT_DISCONNECTED:
		if (s_app.pompconn == conn)
			on_disconnected();
		break;

	case POMP_EVENT_MSG:
		/* Never received for raw context */
		break;
	}
}

/**
 */
static void server_raw_cb_t(struct pomp_ctx *ctx,
		struct pomp_conn *conn,
		struct pomp_buffer *buf,
		void *userdata)
{
	/* Decode read data, rx operation or channel queues will handle
	 * decoded data */
	mux_decode(s_app.muxctx, buf);
}

/* master cookie, will not be actually used for messages */
static ULOG_DECLARE_TAG(ulog_arsdk);

static int arsal_print_cb(eARSAL_PRINT_LEVEL level, const char *tag,
		const char *fmt, va_list args)
{
	int masterlevel = 0;
	uint32_t uloglevel = 0;
	struct ulog_cookie cookie;

	/* Convert levels */
	if (level == ARSAL_PRINT_ERROR)
		uloglevel = ULOG_ERR;
	else if (level == ARSAL_PRINT_WARNING)
		uloglevel = ULOG_WARN;
	else if (level == ARSAL_PRINT_INFO)
		uloglevel = ULOG_INFO;
	else if (level == ARSAL_PRINT_DEBUG)
		uloglevel = ULOG_DEBUG;
	else if (level == ARSAL_PRINT_VERBOSE)
		uloglevel = ULOG_DEBUG;
	else
		uloglevel = ULOG_DEBUG;

	/* Master cookie level, this should have been initialized */
	masterlevel = (__ULOG_REF(ulog_arsdk)).level;

	if (masterlevel >= 0) {
		/* Use temporary cookie */
		cookie.name = (tag && tag[0] != '\0') ? tag : "arsdk";
		cookie.namesize = (int)strlen(cookie.name) + 1;
		/* this is safe only because level is non-negative */
		cookie.level = masterlevel;
		cookie.next = NULL;

		/* Log message */
		ulog_vlog(uloglevel, &cookie, fmt, args);
	}

	return 0;
}

/**
 */
static void sig_handler(int signum)
{
	LOGI("signal %d(%s) received", signum, strsignal(signum));
	s_app.running = 0;
	if (s_app.loop != NULL)
		pomp_loop_wakeup(s_app.loop);
}

/**
 */
int main()
{
	struct sockaddr_in addr;
	socklen_t addrlen = 0;

	signal(SIGINT, &sig_handler);
	signal(SIGTERM, &sig_handler);
	signal(SIGPIPE, SIG_IGN);

	ARSAL_Print_SetCallback(&arsal_print_cb);
	ulog_set_level(&__ULOG_REF(ulog_arsdk), ULOG_INFO);

	/* Create loop and raw server context */
	s_app.loop = pomp_loop_new();
	s_app.pompctx = pomp_ctx_new_with_loop(
			&server_event_cb, NULL, s_app.loop);
	pomp_ctx_set_raw(s_app.pompctx, &server_raw_cb_t);

	/* Setup address */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(4321);
	addrlen = sizeof(addr);

	/* Start listening for connections */
	pomp_ctx_listen(s_app.pompctx,
			(const struct sockaddr *)&addr, addrlen);

	/* Run loop */
	s_app.running = 1;
	while (s_app.running)
		pomp_loop_wait_and_process(s_app.loop, -1);

	/* Cleanup */
	pomp_ctx_stop(s_app.pompctx);
	pomp_ctx_destroy(s_app.pompctx);
	pomp_loop_destroy(s_app.loop);

	return 0;
}
