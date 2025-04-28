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

#ifndef _LIBMUX_SD_TEST_PUBLISHER_H_
#define _LIBMUX_SD_TEST_PUBLISHER_H_

#include <stdlib.h>
#include <stdint.h>

#include "libpomp.h"
#include <libmux.h>
#include <libmux_sd_browser.h>

/* Forward declarations */
struct mux_sd_test_publisher;

/**
 * Create a new mux services publisher.
 * @param mux The mux context to use.
 * @param ret_publisher Will receive the publisher object.
 * @return `0` in case of success, negative errno value in case of error.
 */
int mux_sd_test_publisher_new(struct mux_ctx *mux,
		struct mux_sd_test_publisher **ret_publisher);

/**
 * Destroy a mux services publisher.
 *
 * @param browser The mux services publisher to destroy.
 *
 * @return `0` in case of success, negative errno value in case of error.
 */
int mux_sd_test_publisher_destroy(struct mux_sd_test_publisher *self);

int mux_sd_test_publisher_start(struct mux_sd_test_publisher *self,
		struct pomp_loop *pomp);

int mux_sd_test_publisher_stop(struct mux_sd_test_publisher *self);

int mux_sd_test_publisher_is_started(struct mux_sd_test_publisher *self);

int mux_sd_test_publisher_list(struct mux_sd_test_publisher *self,
		void (*list_cb)(struct mux_sd_test_publisher *self,
				struct mux_sd_info **sd, size_t sd_cnt,
				void *userdata));

int mux_sd_test_publisher_add(struct mux_sd_test_publisher *self,
		struct mux_sd_info *sd);
int mux_sd_test_publisher_remove(struct mux_sd_test_publisher *self,
		struct mux_sd_info *sd);

#endif /* !_LIBMUX_SD_TEST_PUBLISHER_H_ */
