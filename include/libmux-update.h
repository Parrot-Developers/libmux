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
 * @file libmux-update.h
 *
 */

#ifndef _LIBMUX_UPDATE_H_
#define _LIBMUX_UPDATE_H_

#define MUX_UPDATE_CHANNEL_ID_UPDATE 10

/*
 * update request.
 * arg1: %s   : update image version.
 * arg2: %p%u : md5 of transfered file.
 * arg3: %u   : size of update file in bytes.
 */
#define MUX_UPDATE_MSG_ID_UPDATE_REQ           1
#define MUX_UPDATE_MSG_FMT_ENC_UPDATE_REQ      "%s%p%u%u"
#define MUX_UPDATE_MSG_FMT_DEC_UPDATE_REQ      "%ms%p%u%u"

/*
 * update response message.
 * arg1: %d : response (0 for OK, -1 NOK)
 */
#define MUX_UPDATE_MSG_ID_UPDATE_RESP            2
#define MUX_UPDATE_MSG_FMT_ENC_UPDATE_RESP       "%d"
#define MUX_UPDATE_MSG_FMT_DEC_UPDATE_RESP       "%d"

/*
 * update chunk message.
 * arg1: %u : chunk id.
 * arg1: %p : chunk data.
 */
#define MUX_UPDATE_MSG_ID_CHUNK            3
#define MUX_UPDATE_MSG_FMT_ENC_CHUNK       "%u%p%u"
#define MUX_UPDATE_MSG_FMT_DEC_CHUNK       "%u%p%u"

/*
 * update chunk ack message.
 * arg1: %u : chunk id.
 */
#define MUX_UPDATE_MSG_ID_CHUNK_ACK        4
#define MUX_UPDATE_MSG_FMT_ENC_CHUNK_ACK    "%u"
#define MUX_UPDATE_MSG_FMT_DEC_CHUNK_ACK    "%u"

/*
 * upload status.
 * arg1: %d : 0 if update file status.
 */
#define MUX_UPDATE_MSG_ID_STATUS  5
#define MUX_UPDATE_MSG_FMT_ENC_STATUS    "%d"
#define MUX_UPDATE_MSG_FMT_DEC_STATUS    "%d"

#endif /* !_LIBMUX_UPDATE_H_ */
