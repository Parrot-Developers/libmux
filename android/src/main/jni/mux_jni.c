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
#include <jni.h>
#include <stdlib.h>
#include <errno.h>
#include <errno.h>

#include <android/log.h>
#include <libmux.h>

#define LOG_TAG "MUX JNI"

/** Log as debug */
#define LOGD(_fmt, ...) \
	__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, _fmt, ##__VA_ARGS__)

/** Log as info */
#define LOGI(_fmt, ...) \
	__android_log_print(ANDROID_LOG_INFO, LOG_TAG, _fmt, ##__VA_ARGS__)

/** Log as warning */
#define LOGW(_fmt, ...) \
	__android_log_print(ANDROID_LOG_WARN, LOG_TAG, _fmt, ##__VA_ARGS__)

/** Log as error */
#define LOGE(_fmt, ...) \
	__android_log_print(ANDROID_LOG_ERROR, LOG_TAG, _fmt, ##__VA_ARGS__)

struct jni_ctx {
	struct mux_ctx *muxctx;
	jobject *thizz;
};

static JavaVM* g_jvm;
static jmethodID g_fdeof;

static void on_mux_channel_cb(struct mux_ctx *mux_ctx, uint32_t chanid,
			enum mux_channel_event event, struct pomp_buffer *buf,
			void *userdata)
{
	LOGW("Ignoring unexpected message on chanid=%d", chanid);
}

static void on_mux_fdeof(struct mux_ctx *mux_ctx, void *userdata)
{
	JNIEnv* env = NULL;
	if ((*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6) != JNI_OK)
	{
		LOGW("thread not attached to JVM");
		return;
	}
	struct jni_ctx *ctx = (struct jni_ctx*) userdata;
	(*env)->CallVoidMethod(env, ctx->thizz, g_fdeof);
}

static void cleanup(JNIEnv *env, struct jni_ctx *ctx)
{
	if (ctx != NULL)
	{
		if (ctx->muxctx != NULL)
		{
			mux_stop(ctx->muxctx);
			mux_unref(ctx->muxctx);
		}
		if (ctx->thizz != NULL)
		{
			(*env)->DeleteGlobalRef(env, ctx->thizz);
		}
		free (ctx);
		ctx = NULL;
	}
}


JNIEXPORT void JNICALL
Java_com_parrot_mux_Mux_nativeClInit (JNIEnv *env, jclass clazz)
{
	jint res = (*env)->GetJavaVM(env, &g_jvm);
	if (res < 0)
	{
		LOGE("Unable to get JavaVM pointer");
	}

	g_fdeof = (*env)->GetMethodID (env, clazz, "onEof", "()V");
	if (!g_fdeof)
	{
		LOGE("Unable to find method \'void onEof()\'");
	}
}

JNIEXPORT jlong JNICALL
Java_com_parrot_mux_Mux_nativeNew (JNIEnv *env, jobject thizz, jint fd)
{
	LOGI("Creating new Mux fd=%d", fd);
	struct jni_ctx *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
	{
		LOGE("Error allocating global context");
		goto fail;
	}

	ctx->thizz = (*env)->NewGlobalRef(env, thizz);
	if (ctx->thizz == NULL)
	{
		LOGE("Error creating object global ref");
		goto fail;
	}

	struct mux_ops ops;
	ops.chan_cb = &on_mux_channel_cb;
	ops.fdeof = &on_mux_fdeof;
	ops.userdata = ctx;

	ctx->muxctx = mux_new(fd, NULL, &ops, MUX_FLAG_FD_NOT_POLLABLE);
	if (ctx->muxctx == NULL)
	{
		LOGE("Error allocating mux");
		goto fail;
	}
	return (jlong)(intptr_t)ctx;

fail:
	cleanup(env, ctx);
	return (jlong)(intptr_t)NULL;
}

JNIEXPORT void JNICALL
Java_com_parrot_mux_Mux_nativeStop (JNIEnv *env, jobject thizz, jlong jctx)
{
	LOGI("Stopping Mux");
	struct jni_ctx *ctx = (struct jni_ctx*) (intptr_t) jctx;
	mux_stop(ctx->muxctx);
}

JNIEXPORT void JNICALL
Java_com_parrot_mux_Mux_nativeDispose (JNIEnv *env, jobject thizz, jlong jctx)
{
	LOGI("Disposing mux");
	struct jni_ctx *ctx = (struct jni_ctx*) (intptr_t) jctx;
	cleanup(env, ctx);
}

JNIEXPORT jlong JNICALL
Java_com_parrot_mux_Mux_nativeAquireMuxRef(JNIEnv *env, jobject thizz, jlong jctx)
{
	struct jni_ctx *ctx = (struct jni_ctx*) (intptr_t) jctx;
	mux_ref(ctx->muxctx);
	return (jlong)(intptr_t)ctx->muxctx;
}

JNIEXPORT void JNICALL
Java_com_parrot_mux_Mux_nativeReleaseMuxRef(JNIEnv *env, jobject thizz, jlong jctx)
{
	struct jni_ctx *ctx = (struct jni_ctx*) (intptr_t) jctx;
	mux_unref(ctx->muxctx);
}

JNIEXPORT void JNICALL
Java_com_parrot_mux_Mux_nativeRunThread(JNIEnv *env, jobject obj, jlong jctx)
{
	struct jni_ctx *ctx = (struct jni_ctx*) (intptr_t) jctx;
	mux_run(ctx->muxctx);
}

