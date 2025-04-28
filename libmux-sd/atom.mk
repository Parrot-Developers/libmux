LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := libmux-sd-browser

LOCAL_DESCRIPTION := Service Discovery MUX Proxy
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include/
# Public API headers - top level headers first
# This header list is currently used to generate a python binding
LOCAL_EXPORT_CUSTOM_VARIABLES := LIBMUXSD_HEADERS=\
	$(LOCAL_PATH)/include/libmux_sd_browser.h
LOCAL_CFLAGS := -DMUX_SD_API_EXPORTS -fvisibility=hidden
LOCAL_SRC_FILES := \
	src/mux_sd_browser.c
LOCAL_LIBRARIES := libfutils \
		   libmdns-proxy-msghub-c \
		   libmdns-proxy-pb-c \
		   libmsghub \
		   libmux \
		   libpomp \
		   libulog \
		   protobuf
ifeq ("$(TARGET_OS)","windows")
  LOCAL_LDLIBS += -lws2_32
endif
include $(BUILD_LIBRARY)

###############################################################################
###############################################################################

ifdef TARGET_TEST

include $(CLEAR_VARS)
LOCAL_MODULE := tst-mux-sd
LOCAL_C_INCLUDES := $(LOCAL_PATH)/src

LOCAL_SRC_FILES := \
	tests/mux_sd_test.c \
	tests/mux_sd_test_base.c \
	tests/mux_sd_test_basic.c \
	tests/mux_sd_test_publisher.c

LOCAL_LIBRARIES := libcunit \
		   libfutils \
		   libmdns-proxy-msghub-c \
		   libmdns-proxy-pb-c protobuf \
		   libmsghub \
		   libmux \
		   libmux-sd-browser \
		   libpomp \
		   libulog

ifeq ("$(TARGET_OS)","windows")
  LOCAL_LDLIBS += -lws2_32
endif

include $(BUILD_EXECUTABLE)

endif
