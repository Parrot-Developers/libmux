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

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif /* !_GNU_SOURCE */

#include "errno.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "ulog.h"
#include "libpomp.h"
#include "futils/list.h"
#include "msghub.h"
#include "libmux.h"
#include "libmux_sd_browser.h"

#include "service_discovery.pb-c.h"
#include "service_discovery.msghub-c.h"

/** mdns-proxy port. */
#define MUX_SD_MDNS_PORT 5454

/** Skytrontroller host name. */
#define MUX_SD_SKYCTRL_HOST_NAME "skycontroller"

ULOG_DECLARE_TAG(libmux_sd_browser);

/** Mux Service Browser. */
struct mux_sd_browser {
	/** Mux instance */
	struct mux_ctx *mux;
	/** Pomp loop */
	struct pomp_loop *pomp;
	/** Mdns mux proxy */
	struct mux_ip_proxy *ip_proxy;
	/** Message hub instance */
	struct msghub *msghub;
	/** Message hub channel */
	struct msghub_channel *msghub_channel;
	/** Message hub service discovery handler */
	ServiceDiscovery__Messages__EventHandler *msghub_handler;
	/** Browser parameters */
	struct mux_sd_browser_param param;
	/** Callbacks */
	struct mux_sd_browser_cbs cbs;
	/* Service list */
	struct list_node services;
};

/** Service node */
struct mux_sd {
	/** List node */
	struct list_node node;
	/** Mux Service Browser */
	struct mux_sd_browser *browser;
	/** Remote service information */
	struct mux_sd_info remote_info;
	/** Local service information */
	struct mux_sd_info local_info;
	/** Service mux proxy */
	struct mux_ip_proxy *proxy;
};

/**
 * Retrieves the service according to the service info.
 *
 * @param list Service list.
 * @param sd_info Service info to search.
 *
 * @return The service according to the service info, 'NULL' if not found.
 */
static struct mux_sd *mux_sd_list_get(struct list_node *list,
				      struct mux_sd_info *sd_info)
{
	struct mux_sd *i_sd = NULL;
	list_walk_entry_forward(list, i_sd, node) {
		if (strcmp(sd_info->name, i_sd->remote_info.name) == 0 &&
		    strcmp(sd_info->type, i_sd->remote_info.type) == 0 &&
		    strcmp(sd_info->addr, i_sd->remote_info.addr) == 0 &&
		    sd_info->port == i_sd->remote_info.port &&
		    strcmp(sd_info->domain, i_sd->remote_info.domain) == 0) {
			return i_sd;
		}
	}
	return NULL;
}

/**
 * Function called when the mux proxy on a service is opened.
 *
 * @param self Proxy object.
 * @param localport Proxy local socket port on the service.
 * @param userdata The service.
 */
static void sd_proxy_open_cb(struct mux_ip_proxy *self, uint16_t localport,
		void *userdata)
{
	struct mux_sd *sd = userdata;
	ULOG_ERRNO_RETURN_IF(sd == NULL, EINVAL);
	struct mux_sd_browser *browser = sd->browser;
	ULOG_ERRNO_RETURN_IF(browser == NULL, EINVAL);

	/* Format local service */
	sd->local_info = sd->remote_info;
	sd->local_info.port = localport;
	sd->local_info.addr = "127.0.0.1";

	/* Notify the service added. */
	browser->cbs.added(browser, &sd->local_info, browser->cbs.userdata);
}

/**
 * Function called when the mux proxy on a service is closed.
 *
 * @param self Proxy object.
 * @param localport Proxy local socket port on the service.
 * @param userdata The service.
 */
static void sd_proxy_close_cb(struct mux_ip_proxy *self, void *userdata)
{
}

/**
 * Destroys a service.
 *
 * @param self The service to destroy.
 *
 * @return '0' in case of success, negative errno value in case of error.
 */
static int mux_sd_destroy(struct mux_sd *self)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	free(self->remote_info.name);
	free(self->remote_info.type);
	free(self->remote_info.addr);
	free(self->remote_info.domain);
	if (self->remote_info.txt_records != NULL) {
		for (size_t i = 0; i < self->remote_info.txt_records_cnt; i++)
			free(self->remote_info.txt_records[i]);
		free(self->remote_info.txt_records);
	}

	mux_ip_proxy_destroy(self->proxy);
	free(self);

	return 0;
}

/**
 * Duplicates text records.
 *
 * @param self Mux services browser.
 * @param txt_records_src Text records to duplicate in the service.
 * @param txt_records_cnt_src Size of `txt_records_src`.
 */
static int mux_sd_txt_records_dup(struct mux_sd *self,
		char **txt_records_src, size_t txt_records_cnt_src)
{
	if (txt_records_src == NULL || txt_records_cnt_src == 0)
		return 0;

	char **txt_records = calloc(txt_records_cnt_src, sizeof(*txt_records));
	ULOG_ERRNO_RETURN_ERR_IF(txt_records == NULL, EINVAL);

	for (size_t i = 0; i < txt_records_cnt_src; i++) {
		txt_records[i] = strdup(txt_records_src[i]);
		if (txt_records[i] == NULL)
			goto error;
	}

	self->remote_info.txt_records = txt_records;
	self->remote_info.txt_records_cnt = txt_records_cnt_src;

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

/**
 * Creates a new service.
 *
 * @param self Mux services browser.
 * @param sd_info Service info to add.
 * @param ret_sd Will receive the service object.
 *
 * @return '0' in case of success, negative errno value in case of error.
 */
static int mux_sd_new(struct mux_sd_browser *browser, struct mux_sd_info *info,
		      struct mux_sd **ret_sd)
{
	ULOG_ERRNO_RETURN_ERR_IF(browser == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(info == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(info->name == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(info->type == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(info->addr == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(info->domain == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(ret_sd == NULL, EINVAL);

	int res;
	struct mux_ip_proxy_info proxy_info;
	struct mux_ip_proxy_cbs cbs;
	char *transport;

	struct mux_sd *self = calloc(1, sizeof(*self));
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, ENOMEM);
	self->browser = browser;
	self->remote_info.name = strdup(info->name);
	if (self->remote_info.name == NULL) {
		res = -ENOMEM;
		goto error;
	}
	self->remote_info.type = strdup(info->type);
	if (self->remote_info.type == NULL) {
		res = -ENOMEM;
		goto error;
	}
	self->remote_info.addr = strdup(info->addr);
	if (self->remote_info.addr == NULL) {
		res = -ENOMEM;
		goto error;
	}
	self->remote_info.port = info->port;
	self->remote_info.domain = strdup(info->domain);
	if (self->remote_info.domain == NULL) {
		res = -ENOMEM;
		goto error;
	}

	cbs = (struct mux_ip_proxy_cbs) {
		.open = &sd_proxy_open_cb,
		.close = &sd_proxy_close_cb,
		.remote_update = NULL,
		.resolution_failed = NULL,
		.userdata = self,
	};

	transport = strrchr(info->type, '.');
	if (transport == NULL) {
		res = -EPROTO;
		goto error;
	}

	proxy_info = (struct mux_ip_proxy_info) {
		.protocol = {
			.transport = (strcmp(transport, "._udp") == 0) ?
					MUX_IP_PROXY_TRANSPORT_UDP :
					MUX_IP_PROXY_TRANSPORT_TCP,
			.application = MUX_IP_PROXY_APPLICATION_NONE,
		},
		.remote_host = self->remote_info.addr,
		.remote_port = self->remote_info.port,
	};

	/* copy txt_records */
	res = mux_sd_txt_records_dup(self, info->txt_records,
				     info->txt_records_cnt);
	if (res < 0)
		goto error;

	res = mux_ip_proxy_new(browser->mux, &proxy_info, &cbs, -1,
			       &self->proxy);
	if (res < 0)
		goto error;

	*ret_sd = self;
	return 0;
error:
	mux_sd_destroy(self);
	return res;
}

/**
 * Adds a service.
 *
 * @param self Mux services browser.
 * @param sd_info Service info to add.
 *
 * @return '0' in case of success, negative errno value in case of error.
 */
static int mux_sd_browser_add(struct mux_sd_browser *self,
		struct mux_sd_info *sd_info)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(sd_info == NULL, EINVAL);

	/* check if the service already exists */
	struct mux_sd *sd = mux_sd_list_get(&self->services, sd_info);
	ULOG_ERRNO_RETURN_ERR_IF(sd != NULL, EEXIST);

	int res = mux_sd_new(self, sd_info, &sd);
	ULOG_ERRNO_RETURN_ERR_IF(res < 0, -res);

	list_add_after(&self->services, &sd->node);

	return 0;
}

/**
 * Removes a service.
 *
 * @param self Mux services browser.
 * @param sd_info Service info to remove.
 *
 * @return '0' in case of success, negative errno value in case of error.
 */
static int mux_sd_browser_remove(struct mux_sd_browser *self,
		struct mux_sd_info *sd_info)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(sd_info == NULL, EINVAL);

	struct mux_sd *sd = mux_sd_list_get(&self->services, sd_info);
	if (sd == NULL) {
		/* Service not found. */
		return 0;
	}

	list_del(&sd->node);

	/* Notify the service removed. */
	self->cbs.removed(self, &sd->local_info, self->cbs.userdata);

	mux_sd_destroy(sd);

	return 0;
}

/**
 * Removes all services.
 *
 * @param self Mux services browser.
 *
 * @return '0' in case of success, negative errno value in case of error.
 */
static int mux_sd_browser_remove_all_services(struct mux_sd_browser *self)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);

	struct mux_sd *sd = NULL;
	struct mux_sd *sd_tmp = NULL;
	list_walk_entry_forward_safe(&self->services, sd, sd_tmp, node) {
		int res = mux_sd_browser_remove(self, &sd->remote_info);
		if (res < 0)
			ULOGE_ERRNO(-res, "mux_sd_browser_remove");
	}

	return 0;
}

/**
 * Retrieves whether the service should be browsed.
 *
 * @param self Mux services browser.
 * @param sd_info Service info to check.
 *
 * @return `1` if the service should be browsed, otherwise `0`.
 */
static int mux_sd_browser_service_to_browse(struct mux_sd_browser *self,
		struct mux_sd_info *sd_info)
{
	ULOG_ERRNO_RETURN_VAL_IF(self == NULL, EINVAL, 0);
	ULOG_ERRNO_RETURN_VAL_IF(sd_info == NULL, EINVAL, 0);

	if (self->param.types) {
		int found = 0;
		for (size_t i = 0; i < self->param.type_cnt; i++) {

			if (strcmp(self->param.types[i], sd_info->type) == 0) {
				found = 1;
				break;
			}
		}

		if (!found)
			return 0;
	}

	if (self->param.domains) {
		int found = 0;
		for (size_t i = 0; i < self->param.domain_cnt; i++) {
			if (strcmp(self->param.domains[i],
				   sd_info->domain) == 0) {
				found = 1;
				break;
			}
		}
		if (!found)
			return 0;
	}

	return 1;
}

/**
 * Function called when mdns-proxy msghub received a "AddServices" message.
 *
 * @param arg "AddServices" message arguments.
 * @param userdata The mux services browser.
 */
static void mux_sd_browser_msghub_add_services(
	const ServiceDiscovery__Messages__Event__AddServices *arg,
	void *userdata)
{
	struct mux_sd_browser *self = userdata;
	ULOG_ERRNO_RETURN_IF(arg == NULL, EINVAL);

	for (size_t i = 0; i < arg->n_services; i++) {
		/* codecheck_ignore[LONG_LINE] */
		ServiceDiscovery__Messages__ServiceInfo *sd_pb = arg->services[i];

		struct mux_sd_info sd_info = {
			.name = sd_pb->name,
			.type = sd_pb->type,
			.addr = sd_pb->address,
			.port = sd_pb->port,
			.domain = sd_pb->domain,
			.txt_records = sd_pb->txt_records,
			.txt_records_cnt = sd_pb->n_txt_records,
		};

		/* check if it is a service to browse */
		int browse = mux_sd_browser_service_to_browse(self, &sd_info);
		if (!browse)
			continue;

		int res = mux_sd_browser_add(self, &sd_info);
		if (res < 0)
			ULOGE_ERRNO(-res, "mux_sd_browser_add");
	}
}

/**
 * Function called when mdns-proxy msghub received a "DelServices" message.
 *
 * @param arg "DelServices" message arguments.
 * @param userdata The mux services browser.
 */
static void mux_sd_browser_msghub_del_services(
	const ServiceDiscovery__Messages__Event__DelServices *arg,
	void *userdata)
{
	struct mux_sd_browser *self = userdata;
	ULOG_ERRNO_RETURN_IF(self == NULL, EINVAL);

	for (size_t i = 0; i < arg->n_services; i++) {
		/* codecheck_ignore[LONG_LINE] */
		ServiceDiscovery__Messages__ServiceInfo *sd_pb = arg->services[i];

		struct mux_sd_info sd_info = {
			.name = sd_pb->name,
			.type = sd_pb->type,
			.addr = sd_pb->address,
			.port = sd_pb->port,
			.domain = sd_pb->domain,
			.txt_records = sd_pb->txt_records,
			.txt_records_cnt = sd_pb->n_txt_records,
		};

		int res = mux_sd_browser_remove(self, &sd_info);
		if (res < 0)
			ULOGE_ERRNO(-res, "mux_sd_browser_remove");
	}
}

/**
 * Function called when mdns-proxy msghub is connected.
 * @param hub Message hub object.
 * @param channel Associated Channel object.
 * @param conn Associated 'pomp' Connection object.
 * @param userdata The mux services browser.
 */
static void mux_sd_browser_msghub_connected(struct msghub *hub,
		struct msghub_channel *channel,
		struct pomp_conn *conn,
		void *userdata)
{
}

/**
 * Function called when mdns-proxy msghub is disconnected.
 * @param hub Message hub object.
 * @param channel Associated Channel object.
 * @param conn Associated 'pomp' Connection object.
 * @param userdata The mux services browser.
 */
static void mux_sd_browser_msghub_disconnected(struct msghub *hub,
		struct msghub_channel *channel,
		struct pomp_conn *conn,
		void *userdata)
{
	int res = mux_sd_browser_remove_all_services(userdata);
	ULOG_ERRNO_RETURN_IF(res < 0, -res);
}

/**
 * Stops mdns-proxy msghub.
 *
 * @param self Mux services browser.
 *
 * @return '0' in case of success, negative errno value in case of error.
 */
static int mux_sd_browser_msghub_stop(struct mux_sd_browser *self)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(self->msghub == NULL, EINVAL);

	if (self->msghub_handler != NULL) {
		/* codecheck_ignore[LONG_LINE] */
		struct msghub_handler *base = service_discovery__messages__event_handler__get_base(self->msghub_handler);
		if (base != NULL)
			msghub_detach_handler(self->msghub, base);
		/* codecheck_ignore[LONG_LINE] */
		service_discovery__messages__event_handler__destroy(self->msghub_handler);
		self->msghub_handler = NULL;
	}
	msghub_stop(self->msghub);
	msghub_destroy(self->msghub);
	self->msghub = NULL;
	self->msghub_channel = NULL;

	return 0;
}

/**
 * Starts mdns-proxy msghub.
 *
 * @param self Mux services browser.
 * @param localport Local socket port on mdns-proxy.
 *
 * @return '0' in case of success, negative errno value in case of error.
 */
static int mux_sd_browser_msghub_start(struct mux_sd_browser *self,
		uint16_t localport)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(self->msghub != NULL, EINVAL);

	struct msghub_handler *handler_base = NULL;

	struct msghub_conn_handler_cbs msghub_cbs = {
		.connected = &mux_sd_browser_msghub_connected,
		.disconnected = &mux_sd_browser_msghub_disconnected,
	};

	ServiceDiscovery__Messages__EventHandler__Cbs handler_cbs = {
		.add_services = &mux_sd_browser_msghub_add_services,
		.del_services = &mux_sd_browser_msghub_del_services,
	};

	int res = msghub_new(self->pomp, &msghub_cbs, self, &self->msghub);
	ULOG_ERRNO_RETURN_ERR_IF(res < 0, -res);

	char *addr = NULL;
	res = asprintf(&addr, "inet:127.0.0.1:%d", localport);
	if (res < 0) {
		ULOG_ERRNO("asprintf addr", -res);
		goto error;
	}

	res = msghub_start_client_channel(self->msghub, addr,
			&self->msghub_channel);
	free(addr);
	if (res < 0) {
		ULOG_ERRNO("msghub_start_client_channel", -res);
		goto error;
	}

	res = service_discovery__messages__event_handler__new(&handler_cbs,
			self, &self->msghub_handler);
	if (res < 0) {
		ULOG_ERRNO("msghub_handler_new", -res);
		goto error;
	}

	/* codecheck_ignore[LONG_LINE] */
	handler_base = service_discovery__messages__event_handler__get_base(self->msghub_handler);
	if (handler_base == NULL) {
		res = -EPROTO;
		ULOG_ERRNO("handler__get_base", -res);
		goto error;
	}

	res = msghub_attach_handler(self->msghub, handler_base);
	if (res < 0) {
		ULOG_ERRNO("msghub_attach_handler", -res);
		goto error;
	}

	return 0;

error:
	mux_sd_browser_msghub_stop(self);
	return res;
}

/**
 * Function called when the mux proxy local socket is opened on the mdns-proxy.
 *
 * @param self Proxy object.
 * @param localport Proxy local socket port on mdns-proxy.
 * @param userdata Mux Service Browser.
 */
static void mux_sd_browser_ip_open(struct mux_ip_proxy *ip_proxy,
		uint16_t localport, void *userdata)
{
	int res = mux_sd_browser_msghub_start(userdata, localport);
	if (res < 0)
		ULOG_ERRNO("mux_sd_browser_msghub_start", -res);
}

/**
 * Function called when the local socket is closed.
 *
 * @param self Proxy object.
 * @param localport Proxy local socket port.
 * @param userdata User data.
 */
static void mux_sd_browser_ip_close(struct mux_ip_proxy *ip_proxy,
		void *userdata)
{
	struct mux_sd_browser *self = userdata;
	ULOG_ERRNO_RETURN_IF(self == NULL, EINVAL);

	/* Close msghub if it is started */
	if (self->msghub == NULL) {
		int res = mux_sd_browser_msghub_stop(self);
		if (res < 0)
			ULOG_ERRNO("mux_sd_browser_msghub_stop", -res);
	}
}

/**
 * Function called if host address resolution fails.
 *
 * @param self Proxy object.
 * @param err Negative errno value.
 * @param userdata User data.
 */
static void mux_sd_browser_ip_resolution_failed(struct mux_ip_proxy *self,
		int err, void *userdata)
{
	ULOG_ERRNO("mux_sd_browser_ip_resolution_failed", -err);
}


/**
 * Frees browser parameters
 *
 * @param self The mux services browser.
 *
 * @return '0' in case of success, negative errno value in case of error.
 */
static int mux_sd_browser_param_free(struct mux_sd_browser *self)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);

	if (self->param.types != NULL) {
		for (size_t i = 0; i < self->param.type_cnt; i++) {
			if (self->param.types[i] != NULL)
				free(self->param.types[i]);
		}
		free(self->param.types);
		self->param.type_cnt = 0;
	}

	if (self->param.domains != NULL) {
		for (size_t i = 0; i < self->param.domain_cnt; i++) {
			if (self->param.domains[i] != NULL)
				free(self->param.domains[i]);
		}
		free(self->param.domains);
		self->param.domain_cnt = 0;
	}

	return 0;
}

/**
 * Initializes browser parameters
 *
 * @param self The mux services browser.
 * @param src Parameters to copy.
 *
 * @return '0' in case of success, negative errno value in case of error.
 */
static int mux_sd_browser_param_init(struct mux_sd_browser *self,
		struct mux_sd_browser_param *src)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(src == NULL, EINVAL);

	int res = 0;

	/* Copy types */
	if (src->types != NULL) {
		self->param.types = calloc(src->type_cnt,
					   sizeof(*self->param.types));
		if (self->param.types == NULL) {
			res = -ENOMEM;
			goto error;
		}

		for (size_t i = 0; i < src->type_cnt; i++) {
			if (src->types[i] == NULL) {
				res = EINVAL;
				goto error;
			}
			self->param.types[i] = strdup(src->types[i]);
			if (self->param.types[i] == NULL) {
				res = -ENOMEM;
				goto error;
			}
		}
		self->param.type_cnt = src->type_cnt;
	}

	/* Copy domains */
	if (src->domains != NULL) {
		self->param.domains = calloc(src->domain_cnt,
					      sizeof(*self->param.domains));
		if (self->param.domains == NULL) {
			res = -ENOMEM;
			goto error;
		}

		for (size_t i = 0; i < src->domain_cnt; i++) {
			if (src->domains[i] == NULL) {
				res = EINVAL;
				goto error;
			}
			self->param.domains[i] = strdup(src->domains[i]);
			if (self->param.domains[i] == NULL) {
				res = -ENOMEM;
				goto error;
			}
		}
		self->param.domain_cnt = src->domain_cnt;
	}

	return 0;
error:
	mux_sd_browser_param_free(self);
	return res;
}

/**
 * See documentation in public header.
 */
int mux_sd_browser_new(struct mux_ctx *mux, struct mux_sd_browser_param *param,
		struct mux_sd_browser_cbs *cbs,
		struct mux_sd_browser **ret_browser)
{
	ULOG_ERRNO_RETURN_ERR_IF(mux == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(param == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(cbs == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(cbs->added == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(cbs->removed == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(ret_browser == NULL, EINVAL);

	struct mux_sd_browser *self = NULL;

	/* Allocate browser structure */
	self = calloc(1, sizeof(*self));
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, ENOMEM);

	/* Copy parameters */
	int res = mux_sd_browser_param_init(self, param);
	if (res < 0) {
		free(self);
		return res;
	}

	self->mux = mux;
	self->cbs = *cbs;
	list_init(&self->services);

	*ret_browser = self;
	return 0;
}

int mux_sd_browser_destroy(struct mux_sd_browser *self)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(self->ip_proxy != NULL, EINVAL);

	/* Free parameters */
	mux_sd_browser_param_free(self);

	free(self);
	return 0;
}

int mux_sd_browser_start(struct mux_sd_browser *self, struct pomp_loop *pomp)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(self->ip_proxy != NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(pomp == NULL, EINVAL);

	self->pomp = pomp;

	/* Connect a mux ip proxy to the mdns-proxy port. */

	struct mux_ip_proxy_info info = {
		.protocol = {
			.transport = MUX_IP_PROXY_TRANSPORT_TCP,
		},
		.remote_host = MUX_SD_SKYCTRL_HOST_NAME,
		.remote_port = MUX_SD_MDNS_PORT,
	};
	struct mux_ip_proxy_cbs cbs = {
		.open = &mux_sd_browser_ip_open,
		.close = &mux_sd_browser_ip_close,
		.resolution_failed = &mux_sd_browser_ip_resolution_failed,
		.userdata = self,
	};

	int res = mux_ip_proxy_new(self->mux, &info, &cbs, -1, &self->ip_proxy);
	ULOG_ERRNO_RETURN_ERR_IF(res != 0, -res);

	return 0;
}

int mux_sd_browser_stop(struct mux_sd_browser *self)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(self->ip_proxy == NULL, EINVAL);

	int res = mux_ip_proxy_destroy(self->ip_proxy);
	ULOG_ERRNO_RETURN_ERR_IF(res != 0, -res);
	self->ip_proxy = NULL;

	res = mux_sd_browser_msghub_stop(self);
	if (res < 0)
		ULOG_ERRNO("mux_sd_browser_msghub_stop", -res);

	res = mux_sd_browser_remove_all_services(self);
	if (res < 0)
		ULOG_ERRNO("mux_sd_browser_remove_all_services", -res);

	return res;
}

int mux_sd_browser_is_started(struct mux_sd_browser *self)
{
	return self != NULL && self->ip_proxy != NULL;
}

int mux_sd_browser_list(struct mux_sd_browser *self,
		void (*list_cb)(struct mux_sd_browser *self,
				struct mux_sd_info *sd_info, size_t idx,
				void *userdata),
		void *userdata)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(list_cb == NULL, EINVAL);

	struct mux_sd *sd = NULL;
	size_t index = 0;
	list_walk_entry_forward(&self->services, sd, node) {
		/* Notify the service. */
		list_cb(self, &sd->local_info, index, userdata);
		index++;
	}

	return 0;
}
