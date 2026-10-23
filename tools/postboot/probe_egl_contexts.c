/* Bounded EGL context probe; creates no window and changes no configuration. */
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <stdio.h>

static void trial(EGLDisplay d, EGLConfig cfg, const char *name,
                  int major, int minor, int explicit_minor) {
    EGLint attrs[] = {EGL_CONTEXT_CLIENT_VERSION, major,
                      EGL_CONTEXT_MINOR_VERSION_KHR, minor, EGL_NONE};
    if (!explicit_minor) attrs[2] = EGL_NONE;
    eglGetError();
    EGLContext c = eglCreateContext(d, cfg, EGL_NO_CONTEXT, attrs);
    EGLint error = eglGetError();
    printf("%s ES%d.%d minor_attr=%d context=%s error=0x%x\n",
           name, major, minor, explicit_minor, c ? "OK" : "FAIL", error);
    if (c) eglDestroyContext(d, c);
}

int main(void) {
    EGLDisplay d = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLint major, minor;
    if (!eglInitialize(d, &major, &minor)) {
        printf("eglInitialize failed 0x%x\n", eglGetError());
        return 1;
    }
    printf("EGL %d.%d vendor=%s version=%s\nextensions=%s\n", major, minor,
           eglQueryString(d, EGL_VENDOR), eglQueryString(d, EGL_VERSION),
           eglQueryString(d, EGL_EXTENSIONS));
    EGLint attrs[] = {EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_RENDERABLE_TYPE,
                      EGL_OPENGL_ES2_BIT | EGL_OPENGL_ES3_BIT_KHR, EGL_NONE};
    EGLConfig config;
    EGLint count = 0;
    if (!eglChooseConfig(d, attrs, &config, 1, &count) || !count) {
        printf("No ES2/ES3 pbuffer config 0x%x\n", eglGetError());
        eglTerminate(d);
        return 2;
    }
    for (int version = 2; version <= 3; ++version) {
        trial(d, config, "configured", version, 0, 0);
        trial(d, config, "configured", version, 0, 1);
        trial(d, EGL_NO_CONFIG_KHR, "no-config", version, 0, 1);
    }
    trial(d, config, "configured", 3, 1, 1);
    trial(d, config, "configured", 3, 2, 1);
    eglTerminate(d);
    return 0;
}
