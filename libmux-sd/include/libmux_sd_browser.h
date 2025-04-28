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

#ifndef _LIBMUX_SD_BROWSER_H_
#define _LIBMUX_SD_BROWSER_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdint.h>

#include "libpomp.h"
#include <libmux.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** To be used for all public API */
#ifdef MUX_SD_API_EXPORTS
#  ifdef _WIN32
#    define MUX_SD_API	__declspec(dllexport)
#  else /* !_WIN32 */
#    define MUX_SD_API	__attribute__((visibility("default")))
#  endif /* !_WIN32 */
#else /* !MUX_SD_API_EXPORTS */
#  define MUX_SD_API
#endif /* !MUX_SD_API_EXPORTS */

/* Forward declarations */
struct mux_sd_browser;

/**
 * Service Discovery info
 */
struct mux_sd_info {
	/** Name of service. */
	char *name;
	/** Type of service. */
	char *type;
	/** Port number. */
	uint16_t port;
	/** IP address. */
	char *addr;
	/** Domain name. */
	char *domain;
	/** List of text records. */
	char **txt_records;
	/** List of text records count. */
	size_t txt_records_cnt;
};

/**
 * Mux services discovery browser parameters.
 */
struct mux_sd_browser_param {
	/**
	 * List of the services discovery types to browse ;
	 * `NULL` to browse all types.
	 */
	char **types;
	/** Count of types to browse; not used if `types` is `NULL`. */
	size_t type_cnt;

	/**
	 * List of the services discovery domains to browse ;
	 * `NULL` to domains all types.
	 */
	char **domains;
	/** Count of domains to browse; not used if `domains` is `NULL`. */
	size_t domain_cnt;
};

/**
 * Mux services discovery browser callbacks.
 */
struct mux_sd_browser_cbs {
	/**
	 * Function called when a service is added.
	 *
	 * @param self The browser.
	 * @param sd The service added.
	 * @param userdata User data.
	 */
	void (*added)(struct mux_sd_browser *self,
		      struct mux_sd_info *sd_info, void *userdata);

	/**
	 * Function called when a service is removed.
	 *
	 * @param self The browser.
	 * @param sd The service removed.
	 * @param userdata User data.
	 */
	void (*removed)(struct mux_sd_browser *self,
			struct mux_sd_info *sd_info, void *userdata);

	/** User data given in callbacks. */
	void *userdata;
};

/**
 * Creates a new mux services browser.
 * @param mux The mux context to use.
 * @param param Mux services browser parameters.
 * @param cbs Mux services browser callbacks.
 * @param ret_browser Will receive the browser object.
 * @return '0' in case of success, negative errno value in case of error.
 */
MUX_SD_API int mux_sd_browser_new(struct mux_ctx *mux,
		struct mux_sd_browser_param *param,
		struct mux_sd_browser_cbs *cbs,
		struct mux_sd_browser **ret_browser);

/**
 * Destroys a mux services browser.
 *
 * @param self The mux services browser to destroy.
 *
 * @return '0' in case of success, negative errno value in case of error.
 */
MUX_SD_API int mux_sd_browser_destroy(struct mux_sd_browser *self);

/**
 * Starts to browse services.
 *
 * @param self The mux services browser.
 * @param pomp The pomp loop to use.
 *
 * @return '0' in case of success, negative errno value in case of error.
 */
MUX_SD_API int mux_sd_browser_start(struct mux_sd_browser *self,
		struct pomp_loop *pomp);

/**
 * Stops to browse services.
 *
 * @param self The mux services browser.
 *
 * @return '0' in case of success, negative errno value in case of error.
 */
MUX_SD_API int mux_sd_browser_stop(struct mux_sd_browser *self);

/**
 * Retrieves whether the browsing is started.
 *
 * @param self The mux services browser.
 *
 * @return '1' if the browsing is started, otherwise '0'.
 */
MUX_SD_API int mux_sd_browser_is_started(struct mux_sd_browser *self);

/**
 * Browses the list of the current services.
 *
 * @param self The mux services browser.
 * @param list_cb Callback for each service.
 *                 self The mux services browser.
 *                 sd One service from the list.
 *                 idx Index of the service in the list.
 *                 userdata User data.
 * @param userdata User data given in `list_cb` callback.
 *
 * @return `0` in case of success, negative errno value in case of error.
 */
MUX_SD_API int mux_sd_browser_list(struct mux_sd_browser *self,
		void (*list_cb)(struct mux_sd_browser *self,
				struct mux_sd_info *sd_info, size_t idx,
				void *userdata),
		void *userdata);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_LIBMUX_SD_BROWSER_H_ */
