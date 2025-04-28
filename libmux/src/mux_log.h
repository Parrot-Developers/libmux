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
 * @file mux_log.h
 *
 */

#ifndef _MUX_LOG_H_
#define _MUX_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if defined(BUILD_LIBULOG)

#define ULOG_TAG mux
#include "ulog.h"

/** Log as debug */
#define MUX_LOGD(_fmt, ...)	ULOGD(_fmt, ##__VA_ARGS__)
/** Log as info */
#define MUX_LOGI(_fmt, ...)	ULOGI(_fmt, ##__VA_ARGS__)
/** Log as warning */
#define MUX_LOGW(_fmt, ...)	ULOGW(_fmt, ##__VA_ARGS__)
/** Log as error */
#define MUX_LOGE(_fmt, ...)	ULOGE(_fmt, ##__VA_ARGS__)

#else /* !BUILD_LIBULOG */

/** Generic log */
#define MUX_LOG(_fmt, ...)	fprintf(stderr, _fmt "\n", ##__VA_ARGS__)
/** Log as debug */
#define MUX_LOGD(_fmt, ...)	MUX_LOG("[D]" _fmt, ##__VA_ARGS__)
/** Log as info */
#define MUX_LOGI(_fmt, ...)	MUX_LOG("[I]" _fmt, ##__VA_ARGS__)
/** Log as warning */
#define MUX_LOGW(_fmt, ...)	MUX_LOG("[W]" _fmt, ##__VA_ARGS__)
/** Log as error */
#define MUX_LOGE(_fmt, ...)	MUX_LOG("[E]" _fmt, ##__VA_ARGS__)

#endif /* !BUILD_LIBULOG */

/** Log error with errno */
#define MUX_LOG_ERR(_func, _err) \
	MUX_LOGE("%s err=%d(%s)", _func, _err, strerror(_err))

/** Log error with fd and errno */
#define MUX_LOG_FD_ERR(_func, _fd, _err) \
	MUX_LOGE("%s(fd=%d) err=%d(%s)", _func, _fd, _err, strerror(_err))

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_MUX_LOG_H_ */
