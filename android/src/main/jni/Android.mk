LOCAL_PATH := $(call my-dir)

# JNI Wrapper
include $(CLEAR_VARS)

LOCAL_MODULE := libmux_android
LOCAL_SRC_FILES := mux_jni.c
LOCAL_LDLIBS := -llog
LOCAL_SHARED_LIBRARIES := libmux libpomp
include $(BUILD_SHARED_LIBRARY)
