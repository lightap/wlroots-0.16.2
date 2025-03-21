// render/gles2/surfaceless.c
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <wlr/render/egl.h>
#include <wlr/util/log.h>
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include "render/egl.h" 
#include "render/gles2/surfaceless.h"

bool setup_surfaceless_context(struct wlr_egl *egl);

 bool setup_surfaceless_context(struct wlr_egl *egl) {
    // Check surfaceless support first
   // const char *extensions = eglQueryString(EGL_NO_DISPLAY, EGL_EXTENSIONS);
 // /   bool has_surfaceless = strstr(extensions, "EGL_MESA_platform_surfaceless") != NULL;

    PFNEGLGETPLATFORMDISPLAYEXTPROC get_platform_display = 
        (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");

    // First try to create display with surfaceless platform
    EGLDisplay display = get_platform_display(
        EGL_PLATFORM_SURFACELESS_MESA, 
        EGL_DEFAULT_DISPLAY, 
        NULL
    );

    // Initialize EGL
    EGLint major, minor;
    if (!eglInitialize(display, &major, &minor)) {
        // Here's the key difference - try platform device
        PFNEGLQUERYDEVICESEXTPROC eglQueryDevicesEXT = 
            (PFNEGLQUERYDEVICESEXTPROC)eglGetProcAddress("eglQueryDevicesEXT");

        if (eglQueryDevicesEXT) {
            EGLint num_devices;
            EGLDeviceEXT device;
            if (eglQueryDevicesEXT(1, &device, &num_devices) && num_devices > 0) {
                // Try creating display with device platform
                display = get_platform_display(EGL_PLATFORM_DEVICE_EXT, 
                                            device, NULL);
                if (!eglInitialize(display, &major, &minor)) {
                    wlr_log(WLR_ERROR, "Failed to initialize EGL with device platform");
                    return false;
                }
            }
        }
    }

    // Create context with relaxed constraints for WSL2/Zink
    EGLint context_attribs[] = {
        EGL_CONTEXT_CLIENT_VERSION, 2,
        EGL_CONTEXT_OPENGL_ROBUST_ACCESS_EXT, EGL_FALSE,
        EGL_NONE
    };

    egl->context = eglCreateContext(egl->display, EGL_NO_CONFIG_KHR,
                                  EGL_NO_CONTEXT, context_attribs);

    egl->display = display;
    return true;
}

// Put the setup_surfaceless_context() function here