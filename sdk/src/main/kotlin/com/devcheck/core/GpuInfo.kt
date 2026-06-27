package com.devcheck.core

import android.opengl.EGL14
import android.opengl.EGLConfig
import android.opengl.GLES20

/** 通过离屏 EGL/GLES 上下文读取 GPU 渲染器字符串，用于识别软件渲染(模拟器)。 */
internal object GpuInfo {

    /** 返回 "vendor / renderer"，失败返回 null。需在非主线程调用。 */
    fun renderer(): String? {
        val dpy = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY)
        if (dpy == EGL14.EGL_NO_DISPLAY) return null
        val ver = IntArray(2)
        if (!EGL14.eglInitialize(dpy, ver, 0, ver, 1)) return null
        return try {
            val configs = arrayOfNulls<EGLConfig>(1)
            val num = IntArray(1)
            val attrs = intArrayOf(
                EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT,
                EGL14.EGL_NONE,
            )
            if (!EGL14.eglChooseConfig(dpy, attrs, 0, configs, 0, 1, num, 0) || num[0] <= 0) return null
            val ctx = EGL14.eglCreateContext(
                dpy, configs[0], EGL14.EGL_NO_CONTEXT,
                intArrayOf(EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE), 0,
            )
            val surf = EGL14.eglCreatePbufferSurface(
                dpy, configs[0], intArrayOf(EGL14.EGL_WIDTH, 1, EGL14.EGL_HEIGHT, 1, EGL14.EGL_NONE), 0,
            )
            EGL14.eglMakeCurrent(dpy, surf, surf, ctx)
            val renderer = GLES20.glGetString(GLES20.GL_RENDERER)
            val vendor = GLES20.glGetString(GLES20.GL_VENDOR)
            EGL14.eglMakeCurrent(dpy, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT)
            EGL14.eglDestroySurface(dpy, surf)
            EGL14.eglDestroyContext(dpy, ctx)
            if (renderer == null && vendor == null) null else "$vendor / $renderer"
        } catch (t: Throwable) {
            null
        } finally {
            EGL14.eglTerminate(dpy)
        }
    }
}
