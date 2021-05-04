LOCAL_PATH := $(call my-dir)

ifneq ($(CONFIG_ALCHEMY_BUILD_LIBMUX_LEGACY_CONFIG),y)

include $(CLEAR_VARS)
LOCAL_MODULE := libmux
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include/
LOCAL_CFLAGS := -DMUX_API_EXPORTS -fvisibility=hidden
LOCAL_SRC_FILES := \
	src/mux.c \
	src/mux_channel.c \
	src/mux_log.c \
	src/mux_queue.c \
	src/mux_ip_proxy.c
LOCAL_LIBRARIES := libpomp libfutils
LOCAL_CONDITIONAL_LIBRARIES := OPTIONAL:libulog
ifeq ("$(TARGET_OS)","windows")
  LOCAL_LDLIBS += -lws2_32
endif
include $(BUILD_LIBRARY)

###############################################################################
###############################################################################

ifdef TARGET_TEST

include $(CLEAR_VARS)
LOCAL_MODULE := tst-mux
LOCAL_C_INCLUDES := $(LOCAL_PATH)/src

LOCAL_SRC_FILES := \
	tests/mux_test.c \
	tests/mux_test_base.c \
	tests/mux_test_basic.c \
	tests/mux_test_ip_proxy.c

LOCAL_LIBRARIES := libmux libcunit libpomp libfutils
LOCAL_CONDITIONAL_LIBRARIES := OPTIONAL:libulog

ifeq ("$(TARGET_OS)","windows")
  LOCAL_LDLIBS += -lws2_32
endif

include $(BUILD_EXECUTABLE)

endif
endif
