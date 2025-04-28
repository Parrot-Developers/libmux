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
package com.parrot.mux;

import android.os.ParcelFileDescriptor;
import android.util.Log;

public class Mux {
    private static final String TAG = "Mux";

    public interface IOnClosedListener {
        void onClosed();
    }

    public class Ref {
        private long muxRef;

        protected Ref() {
            muxRef = nativeAquireMuxRef(muxCtx);
        }

        public long getCPtr() {
            return muxRef;
        }

        public void release() {
            nativeReleaseMuxRef(muxCtx);
            muxRef = 0;
        }

        public void finalize() {
            if (muxRef != 0) {
                throw new RuntimeException("Leaking a mux reference !");
            }
        }
    }

    private final IOnClosedListener onClosedListener;
    private long muxCtx;

    static {
        nativeClInit();
    }

    public Mux(ParcelFileDescriptor fileDescriptor, IOnClosedListener onClosedListener) {
        this.onClosedListener = onClosedListener;
        this.muxCtx = nativeNew(fileDescriptor.getFd());
    }

    public boolean isValid() {
        return muxCtx != 0;
    }

    public void stop() {
        nativeStop(muxCtx);
    }

    public void destroy() {
        nativeDispose(muxCtx);
    }

    public void runReader() {
        nativeRunThread(muxCtx);
    }

    public Ref newMuxRef() {
        return new Ref();
    }

    /**
     * Called from native code, notify EOF on the mux
     */
    protected void onEof() {
        try {
            onClosedListener.onClosed();
        } catch (Throwable t) {
            // catch all before returning to native code
            Log.e(TAG, "exception in onDeviceRemoved", t);
        }
    }

    private static native long nativeClInit();

    private native long nativeNew(int fd);

    private native void nativeStop(long muxCtx);

    private native void nativeDispose(long muxCtx);

    private native long nativeAquireMuxRef(long muxCtx);

    private native void nativeReleaseMuxRef(long muxCtx);

    private native void nativeRunThread(long muxCtx);
}
