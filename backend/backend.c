#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wayland-server-core.h>

#include <wlr/backend/headless.h>
#include <wlr/backend/interface.h>
#include <wlr/backend/multi.h>
#include <wlr/backend/noop.h>
#include <wlr/backend/session.h>
#include <wlr/backend/wayland.h>
#include <wlr/config.h>
#include <wlr/render/wlr_renderer.h>
#include <wlr/util/log.h>
#include "backend/backend.h"
#include "backend/multi.h"
#include "render/allocator/allocator.h"
#include "util/signal.h"

#if WLR_HAS_DRM_BACKEND
#include <wlr/backend/drm.h>
#endif

#if WLR_HAS_LIBINPUT_BACKEND
#include <wlr/backend/libinput.h>
#endif

#if WLR_HAS_RDP_BACKEND
#include <wlr/backend/RDP.h>
#endif

#define WAIT_SESSION_TIMEOUT 10000 // ms


struct wlr_allocator *backend_get_allocator(struct wlr_backend *backend);




void wlr_signal_emit_safe(struct wl_signal *signal, void *data) {
    struct wl_listener *listener, *tmp;
    wl_list_for_each_safe(listener, tmp, &signal->listener_list, link) {
        listener->notify(listener, data);
    }
}


void wlr_backend_init(struct wlr_backend *backend,
		const struct wlr_backend_impl *impl) {
	assert(backend);
	backend->impl = impl;
	wl_signal_init(&backend->events.destroy);
	wl_signal_init(&backend->events.new_input);
	wl_signal_init(&backend->events.new_output);
}

void wlr_backend_finish(struct wlr_backend *backend) {
    // Keep original signal emission for compatibility
    wl_signal_emit_mutable(&backend->events.destroy, backend);
    
    // Add cleanup but preserve original behavior if components don't exist
    if (backend->allocator) {
        wlr_allocator_destroy(backend->allocator);
    }
    if (backend->has_own_renderer && backend->renderer) {
        wlr_renderer_destroy(backend->renderer);
    }
}

bool wlr_backend_start(struct wlr_backend *backend) {
	if (backend->impl->start) {
		return backend->impl->start(backend);
	}
	return true;
}

void wlr_backend_destroy(struct wlr_backend *backend) {
	if (!backend) {
		return;
	}

	if (backend->impl && backend->impl->destroy) {
		backend->impl->destroy(backend);
	} else {
		free(backend);
	}
}




// Declare the function prototype
struct wlr_renderer *wlr_renderer_autocreate_with_hints(
    struct wlr_backend *backend, uint32_t hints);

struct wlr_renderer *wlr_backend_get_renderer(struct wlr_backend *backend) {
    if (backend->renderer != NULL) {
        return backend->renderer;
    }

    if (backend_get_buffer_caps(backend) != 0) {
        backend->renderer = wlr_renderer_autocreate(backend);
        
        if (backend->renderer) {
            backend->has_own_renderer = true;
            return backend->renderer;
        }
        
        wlr_log(WLR_ERROR, "Failed to create backend renderer");
    }

    return NULL;
}

struct wlr_session *wlr_backend_get_session(struct wlr_backend *backend) {
	if (backend->impl->get_session) {
		return backend->impl->get_session(backend);
	}
	return NULL;
}

static uint64_t get_current_time_ms(void) {
	struct timespec ts = {0};
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static struct wlr_session *session_create_and_wait(struct wl_display *disp) {
	struct wlr_session *session = wlr_session_create(disp);

	if (!session) {
		wlr_log(WLR_ERROR, "Failed to start a session");
		return NULL;
	}

	if (!session->active) {
		wlr_log(WLR_INFO, "Waiting for a session to become active");

		uint64_t started_at = get_current_time_ms();
		uint64_t timeout = WAIT_SESSION_TIMEOUT;
		struct wl_event_loop *event_loop =
			wl_display_get_event_loop(session->display);

		while (!session->active) {
			int ret = wl_event_loop_dispatch(event_loop, (int)timeout);
			if (ret < 0) {
				wlr_log_errno(WLR_ERROR, "Failed to wait for session active: "
					"wl_event_loop_dispatch failed");
				return NULL;
			}

			uint64_t now = get_current_time_ms();
			if (now >= started_at + WAIT_SESSION_TIMEOUT) {
				break;
			}
			timeout = started_at + WAIT_SESSION_TIMEOUT - now;
		}

		if (!session->active) {
			wlr_log(WLR_ERROR, "Timeout waiting session to become active");
			return NULL;
		}
	}

	return session;
}

clockid_t wlr_backend_get_presentation_clock(struct wlr_backend *backend) {
	if (backend->impl->get_presentation_clock) {
		return backend->impl->get_presentation_clock(backend);
	}
	return CLOCK_MONOTONIC;
}
/*
int wlr_backend_get_drm_fd(struct wlr_backend *backend) {
	if (!backend->impl->get_drm_fd) {
		return -1;
	}
	return backend->impl->get_drm_fd(backend);
}*/

int wlr_backend_get_drm_fd(struct wlr_backend *backend) {
    // For RDP backend, always return -1
    return -1;
}

uint32_t backend_get_buffer_caps(struct wlr_backend *backend) {
	if (!backend->impl->get_buffer_caps) {
		return 0;
	}

	return backend->impl->get_buffer_caps(backend);
}

struct wlr_allocator *backend_get_allocator(struct wlr_backend *backend) {
	if (backend->allocator != NULL) {
		return backend->allocator;
	}

	struct wlr_renderer *renderer = wlr_backend_get_renderer(backend);
	if (renderer == NULL) {
		return NULL;
	}

	backend->allocator = wlr_allocator_autocreate(backend, renderer);
	if (backend->allocator == NULL) {
		wlr_log(WLR_ERROR, "Failed to create backend allocator");
	}
	return backend->allocator;
}

static size_t parse_outputs_env(const char *name) {
	const char *outputs_str = getenv(name);
	if (outputs_str == NULL) {
		return 1;
	}

	char *end;
	int outputs = (int)strtol(outputs_str, &end, 10);
	if (*end || outputs < 0) {
		wlr_log(WLR_ERROR, "%s specified with invalid integer, ignoring", name);
		return 1;
	}

	return outputs;
}

static struct wlr_backend *ensure_backend_renderer_and_allocator(
		struct wlr_backend *backend) {
	struct wlr_renderer *renderer = wlr_backend_get_renderer(backend);
	if (renderer == NULL) {
		wlr_backend_destroy(backend);
		return NULL;
	}
	struct wlr_allocator *allocator = backend_get_allocator(backend);
	if (allocator == NULL) {
		wlr_backend_destroy(backend);
		return NULL;
	}
	return backend;
}

static struct wlr_backend *attempt_wl_backend(struct wl_display *display) {
	struct wlr_backend *backend = wlr_wl_backend_create(display, NULL);
	if (backend == NULL) {
		return NULL;
	}

	size_t outputs = parse_outputs_env("WLR_WL_OUTPUTS");
	for (size_t i = 0; i < outputs; ++i) {
		wlr_wl_output_create(backend);
	}

	return ensure_backend_renderer_and_allocator(backend);
}

static struct wlr_backend *attempt_RDP_backend(struct wl_display *display) {
#if WLR_HAS_RDP_BACKEND
    if (!display) {
        wlr_log(WLR_ERROR, "No display available for RDP backend");
        return NULL;
    }

    wlr_log(WLR_INFO, "Creating RDP backend");

  
    
    // Try different graphics drivers in order of preference
    const char* preferred_driver = getenv("WLR_RENDERER");
    if (!preferred_driver) {
        // First try llvmpipe for software rendering
        setenv("GALLIUM_DRIVER", "zink", 1);
       
    }

    struct wlr_backend *backend = wlr_RDP_backend_create(display);
    if (!backend) {
        wlr_log(WLR_ERROR, "Failed to create RDP backend");
        return NULL;
    }

    size_t outputs = parse_outputs_env("WLR_RDP_OUTPUTS");
    if (outputs > 0) {
        wlr_log(WLR_INFO, "RDP backend will use default output configuration");
    }

    
    return backend;
#else
    wlr_log(WLR_ERROR, "RDP backend not enabled during compilation");
    return NULL;
#endif
}
static struct wlr_backend *attempt_headless_backend(
		struct wl_display *display) {
	struct wlr_backend *backend = wlr_headless_backend_create(display);
	if (backend == NULL) {
		return NULL;
	}

	size_t outputs = parse_outputs_env("WLR_HEADLESS_OUTPUTS");
	for (size_t i = 0; i < outputs; ++i) {
		wlr_headless_add_output(backend, 1280, 720);
	}

	return ensure_backend_renderer_and_allocator(backend);
}



#if WLR_HAS_DRM_BACKEND
static struct wlr_backend *attempt_drm_backend(struct wl_display *display,
		struct wlr_backend *backend, struct wlr_session *session) {
	struct wlr_device *gpus[8];
	ssize_t num_gpus = wlr_session_find_gpus(session, 8, gpus);
	if (num_gpus < 0) {
		wlr_log(WLR_ERROR, "Failed to find GPUs");
		return NULL;
	}

	if (num_gpus == 0) {
		wlr_log(WLR_ERROR, "Found 0 GPUs, cannot create backend");
		return NULL;
	} else {
		wlr_log(WLR_INFO, "Found %zu GPUs", num_gpus);
	}

	struct wlr_backend *primary_drm = NULL;
	for (size_t i = 0; i < (size_t)num_gpus; ++i) {
		struct wlr_backend *drm = wlr_drm_backend_create(display, session,
			gpus[i], primary_drm);
		if (!drm) {
			wlr_log(WLR_ERROR, "Failed to create DRM backend");
			continue;
		}

		if (!primary_drm) {
			primary_drm = drm;
		}

		wlr_multi_backend_add(backend, drm);
	}
	if (!primary_drm) {
		wlr_log(WLR_ERROR, "Could not successfully create backend on any GPU");
		return NULL;
	}

	return ensure_backend_renderer_and_allocator(primary_drm);
}
#endif

static struct wlr_backend *attempt_backend_by_name(struct wl_display *display,
        struct wlr_backend *backend, struct wlr_session **session,
        const char *name) {
    if (strcmp(name, "wayland") == 0) {
        return attempt_wl_backend(display);
#if WLR_HAS_RDP_BACKEND
    if (!display) {
        wlr_log(WLR_ERROR, "No display available for RDP backend");
        return NULL;
    }

    wlr_log(WLR_INFO, "Creating RDP backend (surfaceless approach)");
    // Follow the old version's successful path:
    // 1. No environment variables set
    // 2. Create backend
    // 3. Let EGL surfaceless setup happen naturally
    struct wlr_backend *backend = wlr_RDP_backend_create(display);
    if (backend == NULL) {
        return NULL;
    }

    wlr_log(WLR_INFO, "RDP backend created successfully");

    return backend;
#else
    wlr_log(WLR_ERROR, "RDP backend not enabled during compilation");
    return NULL;
#endif

#if WLR_HAS_RDP_BACKEND
    } else if (strcmp(name, "RDP") == 0) {
        // Configure Vulkan/D3D12 for WSL2
        setenv("MESA_VK_VERSION_OVERRIDE", "1.2", 1);
        setenv("MESA_LOADER_DRIVER_OVERRIDE", "zink", 1);
        setenv("GALLIUM_DRIVER", "zink", 1);
        setenv("ZINK_DEBUG", "nofp64,nofast_color_clear", 1);
        setenv("VK_DRIVER_FILES", "/usr/share/vulkan/icd.d/vulkan_icd.json", 1);
        
        // Disable problematic features
        setenv("ZINK_DESCRIPTORS", "lazy", 1);
        setenv("ZINK_NO_TIMELINES", "1", 1);
        setenv("ZINK_NO_DECOMPRESS", "1", 1);
        
        wlr_log(WLR_INFO, "Creating RDP backend (surfaceless approach)");
        struct wlr_backend *rdp = wlr_RDP_backend_create(display);
        if (rdp) {
            wlr_log(WLR_INFO, "RDP backend created successfully");
            return rdp;
        }
        return NULL;
#endif
    } else if (strcmp(name, "headless") == 0) {
        return attempt_headless_backend(display);
    } else if (strcmp(name, "drm") == 0 || strcmp(name, "libinput") == 0) {
        if (!*session) {
            *session = session_create_and_wait(display);
            if (!*session) {
                wlr_log(WLR_ERROR, "failed to start a session");
                return NULL;
            }
        }

        if (strcmp(name, "libinput") == 0) {
#if WLR_HAS_LIBINPUT_BACKEND
            return wlr_libinput_backend_create(display, *session);
#else
            return NULL;
#endif
        } else {
#if WLR_HAS_DRM_BACKEND
            return attempt_drm_backend(display, backend, *session);
#else
            return NULL;
#endif
        }
    }

    wlr_log(WLR_ERROR, "unrecognized backend '%s'", name);
    return NULL;
}
struct wlr_backend *wlr_backend_autocreate(struct wl_display *display) {
	struct wlr_backend *backend = wlr_multi_backend_create(display);
	struct wlr_multi_backend *multi = (struct wlr_multi_backend *)backend;
	if (!backend) {
		wlr_log(WLR_ERROR, "could not allocate multibackend");
		return NULL;
	}

	char *names = getenv("WLR_BACKENDS");
	if (names) {
		wlr_log(WLR_INFO, "Loading user-specified backends due to WLR_BACKENDS: %s",
			names);

		names = strdup(names);
		if (names == NULL) {
			wlr_log(WLR_ERROR, "allocation failed");
			wlr_backend_destroy(backend);
			return NULL;
		}

		char *saveptr;
		char *name = strtok_r(names, ",", &saveptr);
		while (name != NULL) {
			struct wlr_backend *subbackend = attempt_backend_by_name(display,
				backend, &multi->session, name);
			if (subbackend == NULL) {
				wlr_log(WLR_ERROR, "failed to start backend '%s'", name);
				wlr_session_destroy(multi->session);
				wlr_backend_destroy(backend);
				free(names);
				return NULL;
			}

			if (!wlr_multi_backend_add(backend, subbackend)) {
				wlr_log(WLR_ERROR, "failed to add backend '%s'", name);
				wlr_session_destroy(multi->session);
				wlr_backend_destroy(backend);
				free(names);
				return NULL;
			}

			name = strtok_r(NULL, ",", &saveptr);
		}

		free(names);
		return backend;
	}

	if (getenv("WAYLAND_DISPLAY") || getenv("WAYLAND_SOCKET")) {
		struct wlr_backend *wl_backend = attempt_wl_backend(display);
		if (!wl_backend) {
			goto error;
		}

		wlr_multi_backend_add(backend, wl_backend);
		return backend;
	}

#if WLR_HAS_RDP_BACKEND
    const char *RDP_display = getenv("DISPLAY");
    if (RDP_display) {
        struct wlr_backend *RDP_backend =
            attempt_RDP_backend(display);
        if (!RDP_backend) {
            goto error;
        }

        wlr_multi_backend_add(backend, RDP_backend);
        return backend;
    }
#endif

	// Attempt DRM+libinput
	multi->session = session_create_and_wait(display);
	if (!multi->session) {
		wlr_log(WLR_ERROR, "Failed to start a DRM session");
		wlr_backend_destroy(backend);
		return NULL;
	}

#if WLR_HAS_LIBINPUT_BACKEND
	struct wlr_backend *libinput = wlr_libinput_backend_create(display,
		multi->session);
	if (!libinput) {
		wlr_log(WLR_ERROR, "Failed to start libinput backend");
		wlr_session_destroy(multi->session);
		wlr_backend_destroy(backend);
		return NULL;
	}
	wlr_multi_backend_add(backend, libinput);
#endif

#if WLR_HAS_DRM_BACKEND
	struct wlr_backend *primary_drm =
		attempt_drm_backend(display, backend, multi->session);
	if (!primary_drm) {
		wlr_log(WLR_ERROR, "Failed to open any DRM device");
		wlr_session_destroy(multi->session);
		wlr_backend_destroy(backend);
		return NULL;
	}

	return backend;
#endif

error:
	wlr_backend_destroy(backend);
	return NULL;
}
