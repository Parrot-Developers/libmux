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
 * @file libmux-arsdk.h
 *
 */

#ifndef _LIBMUX_ARSDK_H_
#define _LIBMUX_ARSDK_H_

#define MUX_ARSDK_CHANNEL_ID_TRANSPORT        1
#define MUX_ARSDK_CHANNEL_ID_DISCOVERY        2
#define MUX_ARSDK_CHANNEL_ID_BACKEND          3
#define MUX_ARSDK_CHANNEL_ID_STREAM_DATA      4
#define MUX_ARSDK_CHANNEL_ID_STREAM_CONTROL   5

/*
 * Discover message. Request remote to send list of published devices
 */
#define MUX_ARSDK_MSG_ID_DISCOVER             1

/*
 * Device added message. Notify published device.
 * arg1: %s : device name.
 * arg2: %u : device type.
 * arg3: %s : device id.
 */
#define MUX_ARSDK_MSG_ID_DEVICE_ADDED         2
#define MUX_ARSDK_MSG_FMT_ENC_DEVICE_ADDED    "%s%u%s"
#define MUX_ARSDK_MSG_FMT_DEC_DEVICE_ADDED    "%ms%u%ms"

/*
 * Device removed message.
 * arg1: %s : device name.
 * arg2: %u : device type.
 * arg3: %s : device id.
 */
#define MUX_ARSDK_MSG_ID_DEVICE_REMOVED       3
#define MUX_ARSDK_MSG_FMT_ENC_DEVICE_REMOVED  "%s%u%s"
#define MUX_ARSDK_MSG_FMT_DEC_DEVICE_REMOVED  "%ms%u%ms"

/*
 * Connect request message.
 * arg1: %s : controller name.
 * arg2: %s : controller type.
 * arg3: %s : device id.
 * arg4: %s : json.
 */
#define MUX_ARSDK_MSG_ID_CONN_REQ             1
#define MUX_ARSDK_MSG_FMT_ENC_CONN_REQ        "%s%s%s%s"
#define MUX_ARSDK_MSG_FMT_DEC_CONN_REQ        "%ms%ms%ms%ms"

/*
 * Connect response message.
 * arg1: %d : status.
 * arg1: %s : json.
 */
#define MUX_ARSDK_MSG_ID_CONN_RESP            2
#define MUX_ARSDK_MSG_FMT_ENC_CONN_RESP       "%d%s"
#define MUX_ARSDK_MSG_FMT_DEC_CONN_RESP       "%d%ms"

#endif /* !_LIBMUX_ARSDK_H_ */
