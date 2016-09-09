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

#ifndef _ARPARAMS_H_
#define _ARPARAMS_H_

#include <libARNetwork/ARNetwork.h>

#define NETWORK_CD_NONACK_ID	10
#define NETWORK_CD_ACK_ID	11
#define NETWORK_CD_EMERGENCY_ID	12

#define NETWORK_DC_NONACK_ID	127
#define NETWORK_DC_ACK_ID	126

/** */
static const ARNETWORK_IOBufferParam_t s_c2d_params[] = {
	/* Non-acknowledged commands. */
	{
		.ID = NETWORK_CD_NONACK_ID,
		.dataType = ARNETWORKAL_FRAME_TYPE_DATA,
		.sendingWaitTimeMs = 0, /* unused */
		.ackTimeoutMs = 0, /* unused */
		.numberOfRetry = -1, /* unused */
		.numberOfCell = 2,
		.dataCopyMaxSize = 128,
		.isOverwriting = 1,
	},
	/* Acknowledged commands. */
	{
		.ID = NETWORK_CD_ACK_ID,
		.dataType = ARNETWORKAL_FRAME_TYPE_DATA_WITH_ACK,
		.sendingWaitTimeMs = 0, /* unused */
		.ackTimeoutMs = 0, /* unused */
		.numberOfRetry = -1, /* unused */
		.numberOfCell = 20,
		.dataCopyMaxSize = 128,
		.isOverwriting = 0,
	},
	/* Emergency commands. */
	{
		.ID = NETWORK_CD_EMERGENCY_ID,
		.dataType = ARNETWORKAL_FRAME_TYPE_DATA_WITH_ACK,
		.sendingWaitTimeMs = 0, /* unused */
		.ackTimeoutMs = 0, /* unused */
		.numberOfRetry = -1, /* unused */
		.numberOfCell = 1,
		.dataCopyMaxSize = 128,
		.isOverwriting = 0,
	} ,
#if 0
	/* video ack buffer, initialized later */
	{
		.ID = 0,
		.dataType = ARNETWORKAL_FRAME_TYPE_UNINITIALIZED,
		.sendingWaitTimeMs = -1, /* unused */
		.ackTimeoutMs = -1, /* unused */
		.numberOfRetry = -1, /* unused */
		.numberOfCell = 0,
		.dataCopyMaxSize = 0,
		.isOverwriting = 0,
	}
#endif
};

/** */
static const ARNETWORK_IOBufferParam_t s_d2c_params[] = {
	/* Non-acknowledged commands. */
	{
		.ID = NETWORK_DC_NONACK_ID,
		.dataType = ARNETWORKAL_FRAME_TYPE_DATA,
		.sendingWaitTimeMs = 1,
		.ackTimeoutMs = -1, /* unused */
		.numberOfRetry = 10,
		.numberOfCell = 20,
		.dataCopyMaxSize = 128,
		.isOverwriting = 1,
	},
	/* Acknowledged commands. */
	{
		.ID = NETWORK_DC_ACK_ID,
		.dataType = ARNETWORKAL_FRAME_TYPE_DATA_WITH_ACK,
		.sendingWaitTimeMs = 1,
		.ackTimeoutMs = 150,
		.numberOfRetry = 10,
		.numberOfCell = 256,
		.dataCopyMaxSize = 128,
		.isOverwriting = 0,
	},
#if 0
	/* video data buffer, initialized later */
	{
		.ID = 0,
		.dataType = ARNETWORKAL_FRAME_TYPE_UNINITIALIZED,
		.sendingWaitTimeMs = 0,
		.ackTimeoutMs = 0,
		.numberOfRetry = 0,
		.numberOfCell = 0,
		.dataCopyMaxSize = 0,
		.isOverwriting = 0,
	}
#endif
};

#endif /* !_ARPARAMS_H_ */
