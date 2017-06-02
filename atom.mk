LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := libmux
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include/
LOCAL_CFLAGS := -DMUX_API_EXPORTS -fvisibility=hidden
LOCAL_SRC_FILES := \
	src/mux.c \
	src/mux_channel.c \
	src/mux_log.c \
	src/mux_queue.c
LOCAL_LIBRARIES := libpomp
LOCAL_CONDITIONAL_LIBRARIES := OPTIONAL:libulog
include $(BUILD_LIBRARY)

ifeq ("$(TARGET_OS)","linux")

include $(CLEAR_VARS)
LOCAL_MODULE := mux-client
LOCAL_SRC_FILES := tests/client.c
LOCAL_LIBRARIES := \
	libARSAL \
	libARNetworkAL \
	libARNetwork \
	libARCommands \
	libARUtils \
	libpomp \
	libmux \
	libulog
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := mux-server
LOCAL_SRC_FILES := tests/server.c
LOCAL_LIBRARIES := \
	libARSAL \
	libARNetworkAL \
	libARNetwork \
	libARCommands \
	libpomp \
	libmux \
	libulog
include $(BUILD_EXECUTABLE)

endif
