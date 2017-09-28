/**
 * Copyright (c) 2017 Parrot S.A.
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
 * @file libmux-blackbox.h
 *
 */

#ifndef _LIBMUX_BLACKBOX_H_
#define _LIBMUX_BLACKBOX_H_

/* blackbox channel ID */
#define MUX_BLACKBOX_CHANNEL_ID_BLACKBOX 20

/*
 * button action notification.
 * arg1: %hhi : button action id (see sdk button action mapper enumeration).
 */
#define MUX_BLACKBOX_MSG_ID_BUTTON_ACTION		1
#define MUX_BLACKBOX_MSG_FMT_ENC_BUTTON_ACTION		"%hhi"
#define MUX_BLACKBOX_MSG_FMT_DEC_BUTTON_ACTION		"%hhi"

/*
 * axis action notification.
 * arg1: %hhi : source (0 for app, 1 for skycontroller).
 * arg2: %hhi : roll axis value.
 * arg3: %hhi : pitch axis value.
 * arg4: %hhi : yaw axis value.
 * arg5: %hhi : gaz axis value.
 */
#define MUX_BLACKBOX_MSG_ID_PILOTING_INFO		2
#define MUX_BLACKBOX_MSG_FMT_ENC_PILOTING_INFO		"%hhi%hhi%hhi%hhi%hhi"
#define MUX_BLACKBOX_MSG_FMT_DEC_PILOTING_INFO		"%hhi%hhi%hhi%hhi%hhi"

#endif /* !_LIBMUX_BLACKBOX_H_ */
