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

#ifndef _MUX_TEST_BASE_H_
#define _MUX_TEST_BASE_H_

#include "libpomp.h"

enum mux_test_tip_type {
	MUX_TEST_TIP_TYPE_CLIENT,
	MUX_TEST_TIP_TYPE_SERVER,
};

struct mux_test_tip;

struct mux_test_tip_cbs {
	void (*on_connect)(struct mux_test_tip *tip, void *userdata);
	void (*on_disconnect)(struct mux_test_tip *tip, void *userdata);
	void (*on_rcv_data)(struct mux_test_tip *tip, uint32_t chanid,
			struct pomp_buffer *buf, void *userdata);
	int (*resolve)(struct mux_ctx *ctx, const char *hostname,
			uint32_t *addr, void *userdata);

	void *userdata;
};

int mux_test_tip_new(struct pomp_loop *loop, enum mux_test_tip_type type,
		struct mux_test_tip_cbs *cbs, struct mux_test_tip **ret_tip);

int mux_test_tip_destroy(struct mux_test_tip *tip);

int mux_test_tip_start(struct mux_test_tip *tip);

int mux_test_tip_stop(struct mux_test_tip *tip);

struct mux_ctx *mux_test_tip_get_mux(struct mux_test_tip *tip);

struct mux_test_env;

struct mux_test_env_cbs {
	void (*cli_connect)(struct mux_test_env *env, void *userdata);
	void (*cli_disconnect)(struct mux_test_env *env, void *userdata);
	void (*cli_rcv_data)(struct mux_test_env *env, uint32_t chanid, struct pomp_buffer *buf,
			void *userdata);

	void (*srv_connect)(struct mux_test_env *env, void *userdata);
	void (*srv_disconnect)(struct mux_test_env *env, void *userdata);
	void (*srv_rcv_data)(struct mux_test_env *env, uint32_t chanid, struct pomp_buffer *buf,
			void *userdata);

	int (*srv_resolve)(struct mux_ctx *ctx, const char *hostname,
			uint32_t *addr, void *userdata);

	void *userdata;
};

int mux_test_env_new(struct mux_test_env_cbs *cbs,
		struct mux_test_env **ret_env);

int mux_test_env_destroy(struct mux_test_env *env);

int mux_test_env_start(struct mux_test_env *env);

int mux_test_env_start_cli(struct mux_test_env *env);

int mux_test_env_start_srv(struct mux_test_env *env);

void mux_test_env_stop(struct mux_test_env *env);

int mux_test_env_stop_cli(struct mux_test_env *env);

int mux_test_env_stop_srv(struct mux_test_env *env);

struct pomp_loop *mux_test_env_get_loop(struct mux_test_env *env);

struct mux_ctx *mux_test_env_get_cli_mux(struct mux_test_env *env);

struct mux_ctx *mux_test_env_get_srv_mux(struct mux_test_env *env);

int mux_test_env_run_loop(struct mux_test_env *env);

void mux_test_env_loop_stop(struct mux_test_env *env);

#endif /* !_MUX_TEST_BASE_H_ */