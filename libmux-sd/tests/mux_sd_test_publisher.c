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

#include "errno.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ulog.h"
#include "futils/list.h"
#include "libpomp.h"
#include "msghub.h"
#include "libmux.h"
#include "mux_sd_test_publisher.h"

#include "service_discovery.pb-c.h"
#include "service_discovery.msghub-c.h"

/* codecheck_ignore_file[LONG_LINE] */

#define MUX_SD_MDNS_PORT "5454"

ULOG_DECLARE_TAG(libmux_sd_test_publisher);

/** Mux Service Publisher. */
struct mux_sd_test_publisher {

	/** MUX instance */
	struct mux_ctx *mux;

	//struct pomp_ctx *pctx;
	struct msghub *msghub;
	struct msghub_channel *msghub_channel;
	ServiceDiscovery__Messages__EventSender *msghub_sender;
	const ServiceDiscovery__Messages__EventSender__Ops *msghub_sender_ops;

	/* serviec list */
	struct list_node services;
};

struct mux_sd {
	struct list_node node;
	struct mux_sd_info info;
};

static struct mux_sd *mux_sd_list_get(struct list_node *list,
		struct mux_sd_info *sd_info)
{
	struct mux_sd *i_sd = NULL;
	list_walk_entry_forward(list, i_sd, node) {
		if (strcmp(sd_info->name, i_sd->info.name) == 0 &&
		    strcmp(sd_info->type, i_sd->info.type) == 0 &&
		    strcmp(sd_info->addr, i_sd->info.addr) == 0 &&
		    sd_info->port == i_sd->info.port &&
		    strcmp(sd_info->domain, i_sd->info.domain) == 0) {
			return i_sd;
		}
	}
	return NULL;
}

static int mux_sd_destroy(struct mux_sd *self)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	free(self->info.name);
	free(self->info.type);
	free(self->info.addr);
	free(self->info.domain);
	if (self->info.txt_records != NULL) {
		for (size_t i = 0; i < self->info.txt_records_cnt; i++) {
			free(self->info.txt_records[i]);
		}
		free(self->info.txt_records);
	}

	free(self);

	return 0;
}

static int txt_records_dup(
		char **txt_records_src, size_t txt_records_cnt_src,
		char ***txt_records_dst, size_t *txt_records_cnt_dst)
{
	ULOG_ERRNO_RETURN_ERR_IF(txt_records_dst == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(txt_records_cnt_dst == NULL, EINVAL);

	if (txt_records_src == NULL || txt_records_cnt_src == 0)
		return 0;

	char **txt_records = calloc(txt_records_cnt_src, sizeof(*txt_records));
	ULOG_ERRNO_RETURN_ERR_IF(txt_records == NULL, EINVAL);

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

static int mux_sd_new(struct mux_sd_info *info, struct mux_sd **ret_sd)
{
	ULOG_ERRNO_RETURN_ERR_IF(info == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(info->name == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(info->type == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(info->addr == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(info->domain == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(ret_sd == NULL, EINVAL);

	struct mux_sd *self;
	self = calloc(1, sizeof(*self));
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, ENOMEM);
	self->info.name = strdup(info->name);
	self->info.type = strdup(info->type);
	self->info.addr = strdup(info->addr);
	self->info.port = info->port;
	self->info.domain = strdup(info->domain);
	/* copy txt_records */
	int res = txt_records_dup(info->txt_records, info->txt_records_cnt,
			&self->info.txt_records, &self->info.txt_records_cnt);
	if (res < 0)
		goto error;

	*ret_sd = self;
	return 0;
error:
	mux_sd_destroy(self);
	return res;
}

static int sd_info_pb_new(struct mux_sd_info *sd_info,
		ServiceDiscovery__Messages__ServiceInfo **ret_sd_info_pb) {
	ULOG_ERRNO_RETURN_ERR_IF(sd_info == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(ret_sd_info_pb == NULL, EINVAL);

	ServiceDiscovery__Messages__ServiceInfo *sd_info_pb =
			calloc(1, sizeof(*sd_info_pb));
	ULOG_ERRNO_RETURN_ERR_IF(sd_info_pb == NULL, ENOMEM);

	service_discovery__messages__service_info__init(sd_info_pb);
	sd_info_pb->name = strdup(sd_info->name);
	sd_info_pb->type = strdup(sd_info->type);
	sd_info_pb->address = strdup(sd_info->addr);
	sd_info_pb->port = sd_info->port;
	sd_info_pb->domain = strdup(sd_info->domain);
	/* copy txt_records */
	int res = txt_records_dup(sd_info->txt_records, sd_info->txt_records_cnt,
			&sd_info_pb->txt_records, &sd_info_pb->n_txt_records);
	if (res < 0)
		goto error;

	*ret_sd_info_pb = sd_info_pb;
	return 0;
error:
	service_discovery__messages__service_info__free_unpacked(sd_info_pb, NULL);
	return res;
}

static int sd_info_pb_destroy(ServiceDiscovery__Messages__ServiceInfo *sd_info_pb)
{
	ULOG_ERRNO_RETURN_ERR_IF(sd_info_pb == NULL, EINVAL);

	free(sd_info_pb->name);
	free(sd_info_pb->type);
	free(sd_info_pb->address);
	free(sd_info_pb->domain);

	free(sd_info_pb);
	return 0;
}

static int send_sd_del(struct mux_sd_test_publisher *self, struct mux_sd *sd)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(sd == NULL, EINVAL);

	int res = 0;

	ServiceDiscovery__Messages__Event__DelServices del_services;
	service_discovery__messages__event__del_services__init(&del_services);

	del_services.n_services = 1;
	del_services.services = calloc(1, sizeof(*del_services.services));
	ULOG_ERRNO_RETURN_ERR_IF(del_services.services == NULL, EINVAL);

	res = sd_info_pb_new(&sd->info, &del_services.services[0]);
	if (res < 0)
		goto out;


	res = self->msghub_sender_ops->del_services(self->msghub_sender, &del_services, NULL);
	if (res < 0)
		ULOGE_ERRNO(-res, "send_Event_del_services");

out:
	service_discovery__messages__service_info__free_unpacked(del_services.services[0], NULL);
	free(del_services.services);

	return res;
}

static int send_sd_add(struct mux_sd_test_publisher *self, struct mux_sd *sd)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(sd == NULL, EINVAL);

	int res = 0;

	ServiceDiscovery__Messages__Event__AddServices add_services;
	service_discovery__messages__event__add_services__init(&add_services);

	add_services.n_services = 1;
	add_services.services = calloc(1, sizeof(*add_services.services));
	ULOG_ERRNO_RETURN_ERR_IF(add_services.services == NULL, EINVAL);

	res = sd_info_pb_new(&sd->info, &add_services.services[0]);
	if (res < 0)
		goto out;

	res = self->msghub_sender_ops->add_services(self->msghub_sender, &add_services, NULL);
	if (res < 0)
		ULOGE_ERRNO(-res, "send_Event_add_services");

out:
	service_discovery__messages__service_info__free_unpacked(add_services.services[0], NULL);
	free(add_services.services);

	return res;
}


static int send_all_sds(struct mux_sd_test_publisher *self, struct pomp_conn *conn)
{

	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(conn == NULL, EINVAL);

	int res = 0;

	size_t sd_count = list_length(&self->services);
	if (sd_count == 0)
		return 0;

	ServiceDiscovery__Messages__Event__AddServices add_services;
	service_discovery__messages__event__add_services__init(&add_services);

	add_services.n_services = sd_count;
	add_services.services = calloc(add_services.n_services, sizeof(*add_services.services));
	ULOG_ERRNO_RETURN_ERR_IF(add_services.services == NULL, EINVAL);

	struct mux_sd *sd = NULL;
	ServiceDiscovery__Messages__ServiceInfo **sd_pb_i = add_services.services;
	list_walk_entry_forward(&self->services, sd, node) {
		res = sd_info_pb_new(&sd->info, sd_pb_i);
		if (res < 0)
			goto out;

		sd_pb_i++;
	}

	res = self->msghub_sender_ops->add_services(self->msghub_sender, &add_services, conn);
	if (res < 0)
		ULOGE_ERRNO(-res, "send_Event_add_services");

out:
	for (size_t i = 0; i < add_services.n_services; i++) {
		// NULL ?
		service_discovery__messages__service_info__free_unpacked(add_services.services[i], NULL);
	}
	free(add_services.services);

	return res;
}


static void on_connect(struct mux_sd_test_publisher *self, struct pomp_conn *conn)
{
	ULOG_ERRNO_RETURN_IF(self == NULL, EINVAL);

	int res = send_all_sds(self, conn);
	ULOG_ERRNO_RETURN_IF(res < 0, -res);
}

/**
 * See documentation in public header.
 */
int mux_sd_test_publisher_new(struct mux_ctx *mux,
		struct mux_sd_test_publisher **ret_publisher)
{
	ULOG_ERRNO_RETURN_ERR_IF(mux == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(ret_publisher == NULL, EINVAL);

	struct mux_sd_test_publisher *self = NULL;

	/* Allocate publisher structure */
	self = calloc(1, sizeof(*self));
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, ENOMEM);

	self->mux = mux;
	list_init(&self->services);

	*ret_publisher = self;
	return 0;
}

int mux_sd_test_publisher_destroy(struct mux_sd_test_publisher *self)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);

	free(self);
	return 0;
}

/**
 * Function called when a remote peer is connected.
 * @param hub message hub object.
 * @param channel associated Channel object.
 * @param conn associated 'pomp' Connection object.
 * @param userdata user data associated with the callback
 */
static void mux_sd_test_publisher_msghub_connected(struct msghub *hub,
		struct msghub_channel *channel,
		struct pomp_conn *conn,
		void *userdata)
{
	on_connect(userdata, conn);
}

/**
 * Function called when a remote peer is disconnected.
 * @param hub message hub object.
 * @param channel associated Channel object.
 * @param conn associated 'pomp' Connection object.
 * @param userdata user data associated with the callback
 */
static void mux_sd_test_publisher_msghub_disconnected(struct msghub *hub,
		struct msghub_channel *channel,
		struct pomp_conn *conn,
		void *userdata)
{
}

int mux_sd_test_publisher_start(struct mux_sd_test_publisher *self, struct pomp_loop *pomp)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(pomp == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(self->msghub != NULL, EINVAL);

	struct msghub_sender *sender_base = NULL;

	const struct msghub_conn_handler_cbs cbs = {
		.connected = &mux_sd_test_publisher_msghub_connected,
		.disconnected = &mux_sd_test_publisher_msghub_disconnected,
	};

	int res = msghub_new(pomp, &cbs, self, &self->msghub);
	ULOG_ERRNO_RETURN_ERR_IF(res < 0, -res);

	res = msghub_start_server_channel(self->msghub, "inet:127.0.0.1:"MUX_SD_MDNS_PORT,
			&self->msghub_channel);
	if (res < 0) {
		ULOG_ERRNO("msghub_start_server_channel", -res);
		goto error;
	}

	res = service_discovery__messages__event_sender__new(&self->msghub_sender);
	if (res < 0) {
		ULOG_ERRNO("service_discovery__messages__event_sender__new", -res);
		goto error;
	}

	sender_base = service_discovery__messages__event_sender__get_base(self->msghub_sender);
	if (sender_base == NULL) {
		ULOG_ERRNO("service_discovery__messages__event_sender__get_base", -EPROTO);
		goto error;
	}

	res = msghub_attach_sender(self->msghub, sender_base, self->msghub_channel);
	if (res < 0) {
		ULOG_ERRNO("msghub_attach_sender", -res);
		goto error;
	}

	self->msghub_sender_ops = service_discovery__messages__event_sender__get_ops(self->msghub_sender);
	if (self->msghub_sender_ops == NULL) {
		ULOG_ERRNO("service_discovery__messages__event_sender__get_ops", -EPROTO);
		goto error;
	}

	return 0;
error:
	if (self->msghub_sender != NULL) {
		if (sender_base != NULL)
			msghub_detach_sender(self->msghub, sender_base);
		service_discovery__messages__event_sender__destroy(self->msghub_sender);
		self->msghub_sender = NULL;
	}
	msghub_stop(self->msghub);
	msghub_destroy(self->msghub);
	self->msghub = NULL;
	self->msghub_channel = NULL;

	return res;
}

int mux_sd_test_publisher_stop(struct mux_sd_test_publisher *self)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(self->msghub == NULL, EINVAL);

	if (self->msghub_sender != NULL) {
		struct msghub_sender *sender_base = service_discovery__messages__event_sender__get_base(self->msghub_sender);
		if (sender_base != NULL)
			msghub_detach_sender(self->msghub, sender_base);
		service_discovery__messages__event_sender__destroy(self->msghub_sender);
		self->msghub_sender = NULL;
		self->msghub_sender_ops = NULL;
	}
	msghub_stop(self->msghub);
	msghub_destroy(self->msghub);
	self->msghub_channel = NULL;
	self->msghub = NULL;

	struct mux_sd *sd = NULL;
	struct mux_sd *sd_tmp = NULL;
	list_walk_entry_forward_safe(&self->services, sd, sd_tmp, node) {
		list_del(&sd->node);
		mux_sd_destroy(sd);
	}

	return 0;
}

int mux_sd_test_publisher_is_started(struct mux_sd_test_publisher *self)
{
	return self != NULL && self->msghub != NULL;
}

int mux_sd_test_publisher_add(struct mux_sd_test_publisher *self, struct mux_sd_info *sd_info)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(sd_info == NULL, EINVAL);

	struct mux_sd *sd = mux_sd_list_get(&self->services, sd_info);
	ULOG_ERRNO_RETURN_ERR_IF(sd != NULL, EEXIST);

	int res = mux_sd_new(sd_info, &sd);
	ULOG_ERRNO_RETURN_ERR_IF(res < 0, -res);

	list_add_after(&self->services, &sd->node);

	// If started
	if (self->msghub != NULL) {
		res = send_sd_add(self, sd);
		ULOG_ERRNO_RETURN_ERR_IF(res < 0, -res);
	}

	return 0;
}

int mux_sd_test_publisher_remove(struct mux_sd_test_publisher *self, struct mux_sd_info *sd_info)
{
	ULOG_ERRNO_RETURN_ERR_IF(self == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(sd_info == NULL, EINVAL);

	struct mux_sd *sd = mux_sd_list_get(&self->services, sd_info);
	ULOG_ERRNO_RETURN_ERR_IF(sd == NULL, ENODEV);

	// If started
	if (self->msghub != NULL) {
		int res = send_sd_del(self, sd);
		ULOG_ERRNO_RETURN_ERR_IF(res < 0, -res);
	}

	list_del(&sd->node);
	mux_sd_destroy(sd);

	return 0;
}