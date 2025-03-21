/*#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <wlr/config.h>
#include <wlr/interfaces/wlr_buffer.h>
#include <wlr/render/allocator.h>
#include <wlr/util/log.h>
#include <xf86drm.h>
#include <xf86drmMode.h>
#include "backend/backend.h"
#include "render/allocator/allocator.h"
#include "render/allocator/drm_dumb.h"
#include "render/allocator/shm.h"
#include "render/wlr_renderer.h"

#if WLR_HAS_GBM_ALLOCATOR
#include "render/allocator/gbm.h"
#endif

void wlr_allocator_init(struct wlr_allocator *alloc,
		const struct wlr_allocator_interface *impl, uint32_t buffer_caps) {
	assert(impl && impl->destroy && impl->create_buffer);
	memset(alloc, 0, sizeof(*alloc));
	alloc->impl = impl;
	alloc->buffer_caps = buffer_caps;
	wl_signal_init(&alloc->events.destroy);
}


static int reopen_drm_node(int drm_fd, bool allow_render_node) {
	if (drmIsMaster(drm_fd)) {
		// Only recent kernels support empty leases
		uint32_t lessee_id;
		int lease_fd = drmModeCreateLease(drm_fd, NULL, 0, O_CLOEXEC, &lessee_id);
		if (lease_fd >= 0) {
			return lease_fd;
		} else if (lease_fd != -EINVAL && lease_fd != -EOPNOTSUPP) {
			wlr_log_errno(WLR_ERROR, "drmModeCreateLease failed");
			return -1;
		}
		wlr_log(WLR_DEBUG, "drmModeCreateLease failed, "
			"falling back to plain open");
	}

	char *name = NULL;
	if (allow_render_node) {
		name = drmGetRenderDeviceNameFromFd(drm_fd);
	}
	if (name == NULL) {
		// Either the DRM device has no render node, either the caller wants
		// a primary node
		name = drmGetDeviceNameFromFd2(drm_fd);
		if (name == NULL) {
			wlr_log(WLR_ERROR, "drmGetDeviceNameFromFd2 failed");
			return -1;
		}
	}

	int new_fd = open(name, O_RDWR | O_CLOEXEC);
	if (new_fd < 0) {
		wlr_log_errno(WLR_ERROR, "Failed to open DRM node '%s'", name);
		free(name);
		return -1;
	}

	free(name);

	// If we're using a DRM primary node (e.g. because we're running under the
	// DRM backend, or because we're on split render/display machine), we need
	// to use the legacy DRM authentication mechanism to have the permission to
	// manipulate buffers.
	if (drmGetNodeTypeFromFd(new_fd) == DRM_NODE_PRIMARY) {
		drm_magic_t magic;
		if (drmGetMagic(new_fd, &magic) < 0) {
			wlr_log_errno(WLR_ERROR, "drmGetMagic failed");
			close(new_fd);
			return -1;
		}

		if (drmAuthMagic(drm_fd, magic) < 0) {
			wlr_log_errno(WLR_ERROR, "drmAuthMagic failed");
			close(new_fd);
			return -1;
		}
	}

	return new_fd;
}

struct wlr_allocator *allocator_autocreate_with_drm_fd(
		struct wlr_backend *backend, struct wlr_renderer *renderer,
		int drm_fd) {
	uint32_t backend_caps = backend_get_buffer_caps(backend);
	uint32_t renderer_caps = renderer_get_render_buffer_caps(renderer);

	struct wlr_allocator *alloc = NULL;

#if WLR_HAS_GBM_ALLOCATOR
	uint32_t gbm_caps = WLR_BUFFER_CAP_DMABUF;
	if ((backend_caps & gbm_caps) && (renderer_caps & gbm_caps)
			&& drm_fd >= 0) {
		wlr_log(WLR_DEBUG, "Trying to create gbm allocator");
		int gbm_fd = reopen_drm_node(drm_fd, true);
		if (gbm_fd < 0) {
			return NULL;
		}
		if ((alloc = wlr_gbm_allocator_create(gbm_fd)) != NULL) {
			return alloc;
		}
		close(gbm_fd);
		wlr_log(WLR_DEBUG, "Failed to create gbm allocator");
	}
#endif

	uint32_t shm_caps = WLR_BUFFER_CAP_SHM | WLR_BUFFER_CAP_DATA_PTR;
	if ((backend_caps & shm_caps) && (renderer_caps & shm_caps)) {
		wlr_log(WLR_DEBUG, "Trying to create shm allocator");
		if ((alloc = wlr_shm_allocator_create()) != NULL) {
			return alloc;
		}
		wlr_log(WLR_DEBUG, "Failed to create shm allocator");
	}

	uint32_t drm_caps = WLR_BUFFER_CAP_DMABUF | WLR_BUFFER_CAP_DATA_PTR;
	if ((backend_caps & drm_caps) && (renderer_caps & drm_caps)
			&& drm_fd >= 0 && drmIsMaster(drm_fd)) {
		wlr_log(WLR_DEBUG, "Trying to create drm dumb allocator");
		int dumb_fd = reopen_drm_node(drm_fd, false);
		if (dumb_fd < 0) {
			return NULL;
		}
		if ((alloc = wlr_drm_dumb_allocator_create(dumb_fd)) != NULL) {
			return alloc;
		}
		close(dumb_fd);
		wlr_log(WLR_DEBUG, "Failed to create drm dumb allocator");
	}

	wlr_log(WLR_ERROR, "Failed to create allocator");
	return NULL;
}

struct wlr_allocator *wlr_allocator_autocreate(struct wlr_backend *backend,
		struct wlr_renderer *renderer) {
	// Note, drm_fd may be negative if unavailable
	int drm_fd = wlr_backend_get_drm_fd(backend);
	if (drm_fd < 0) {
		drm_fd = wlr_renderer_get_drm_fd(renderer);
	}
	return allocator_autocreate_with_drm_fd(backend, renderer, drm_fd);
}

void wlr_allocator_destroy(struct wlr_allocator *alloc) {
	if (alloc == NULL) {
		return;
	}
	wl_signal_emit_mutable(&alloc->events.destroy, NULL);
	alloc->impl->destroy(alloc);
}

struct wlr_buffer *wlr_allocator_create_buffer(struct wlr_allocator *alloc,
		int width, int height, const struct wlr_drm_format *format) {
	struct wlr_buffer *buffer =
		alloc->impl->create_buffer(alloc, width, height, format);
	if (buffer == NULL) {
		return NULL;
	}
	if (alloc->buffer_caps & WLR_BUFFER_CAP_DATA_PTR) {
		assert(buffer->impl->begin_data_ptr_access &&
			buffer->impl->end_data_ptr_access);
	}
	if (alloc->buffer_caps & WLR_BUFFER_CAP_DMABUF) {
		assert(buffer->impl->get_dmabuf);
	}
	if (alloc->buffer_caps & WLR_BUFFER_CAP_SHM) {
		assert(buffer->impl->get_shm);
	}
	return buffer;
}
*/
/*
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include <wlr/interfaces/wlr_buffer.h>
#include <wlr/render/allocator.h>
#include <wlr/render/wlr_renderer.h>
#include <wlr/util/log.h>

// RDP-specific allocator header
#include "render/allocator/allocator.h"
#include <drm_fourcc.h>
#include <wlr/render/drm_format_set.h>

// Forward declaration of the allocator implementation
static const struct wlr_allocator_interface rdp_allocator_impl;

// RDP-specific buffer structure
struct rdp_buffer {
    struct wlr_buffer base;
    struct wlr_renderer *renderer;
    struct wlr_dmabuf_attributes dmabuf;
    void *data;
};

// Create a new RDP allocator
struct wlr_allocator *wlr_rdp_allocator_create(struct wlr_renderer *renderer) {
    if (!renderer) {
        wlr_log(WLR_ERROR, "Cannot create RDP allocator: no renderer provided");
        return NULL;
    }

    struct wlr_allocator *alloc = calloc(1, sizeof(struct wlr_allocator));
    if (!alloc) {
        wlr_log(WLR_ERROR, "Failed to allocate RDP allocator");
        return NULL;
    }

    // Define buffer capabilities - be explicit about what we support
    uint32_t buffer_caps = WLR_BUFFER_CAP_DATA_PTR;  // Start with minimal caps
    
    // Initialize the allocator
    wlr_allocator_init(alloc, &rdp_allocator_impl, buffer_caps);

    return alloc;
}

// Destroy the RDP allocator
static void rdp_allocator_destroy(struct wlr_allocator *alloc) {
    free(alloc);
}

// Destroy an RDP buffer
static void rdp_buffer_destroy(struct wlr_buffer *wlr_buffer) {
    if (!wlr_buffer) {
        return;
    }

    struct rdp_buffer *buffer = wl_container_of(wlr_buffer, buffer, base);
    if (!buffer) {
        return;
    }
    
    if (buffer->data) {
        free(buffer->data);
        buffer->data = NULL;
    }

    // Clean up DMA buffer attributes safely
    wlr_dmabuf_attributes_finish(&buffer->dmabuf);
    
    free(buffer);
}

// Get DMA buffer attributes for RDP buffer
static bool rdp_buffer_get_dmabuf(struct wlr_buffer *wlr_buffer, 
                                   struct wlr_dmabuf_attributes *attribs) {
    struct rdp_buffer *buffer = wl_container_of(wlr_buffer, buffer, base);
    
    memcpy(attribs, &buffer->dmabuf, sizeof(buffer->dmabuf));
    return true;
}

// Begin data pointer access for RDP buffer
static bool rdp_buffer_begin_data_ptr_access(
    struct wlr_buffer *wlr_buffer, 
    uint32_t flags, 
    void **data, 
    uint32_t *format, 
    size_t *stride
) {
    struct rdp_buffer *buffer = wl_container_of(wlr_buffer, buffer, base);
    *data = buffer->data;
    *format = buffer->dmabuf.format;
    *stride = buffer->dmabuf.stride[0];
    return true;
}

// End data pointer access for RDP buffer
static void rdp_buffer_end_data_ptr_access(struct wlr_buffer *wlr_buffer) {
    // No-op for this implementation
}

// Buffer implementation for RDP buffers
static const struct wlr_buffer_impl rdp_buffer_impl = {
    .destroy = rdp_buffer_destroy,
    .get_dmabuf = rdp_buffer_get_dmabuf,
    .begin_data_ptr_access = rdp_buffer_begin_data_ptr_access,
    .end_data_ptr_access = rdp_buffer_end_data_ptr_access,
};

// Create a buffer for the RDP allocator

static struct wlr_buffer *rdp_allocator_create_buffer(
    struct wlr_allocator *alloc,
    int width, int height, 
    const struct wlr_drm_format *format) {
    
    uint32_t fmt = DRM_FORMAT_XRGB8888;  // Default format
    uint64_t modifier = DRM_FORMAT_MOD_LINEAR;

    // Simpler format handling without accessing internal structure
    if (format) {
        // Let's use a helper function if available, or just use defaults
        fmt = DRM_FORMAT_XRGB8888;  // Stick with default format for now
        modifier = DRM_FORMAT_MOD_LINEAR;
    }

    struct rdp_buffer *buffer = calloc(1, sizeof(struct rdp_buffer));
    if (!buffer) {
        wlr_log(WLR_ERROR, "Failed to allocate RDP buffer");
        return NULL;
    }

    // Initialize buffer
    wlr_buffer_init(&buffer->base, &rdp_buffer_impl, width, height);

    // Calculate stride and allocate data
    size_t stride = (size_t)width * 4;  // XRGB8888 = 4 bytes
    if (stride > 0 && height > 0 && stride <= SIZE_MAX / height) {
        size_t size = stride * height;
        buffer->data = calloc(1, size);  // Use calloc for zero-initialization
    }

    if (!buffer->data) {
        wlr_log(WLR_ERROR, "Failed to allocate buffer data");
        free(buffer);
        return NULL;
    }

    // Initialize DMA buffer attributes
    buffer->dmabuf = (struct wlr_dmabuf_attributes) {
        .width = width,
        .height = height,
        .format = fmt,
        .modifier = modifier,
        .n_planes = 1,
        .fd = {-1},
        .offset = {0},
        .stride = {stride}
    };

    return &buffer->base;
}
// Allocator implementation for RDP
static const struct wlr_allocator_interface rdp_allocator_impl = {
    .create_buffer = rdp_allocator_create_buffer,
    .destroy = rdp_allocator_destroy,
};


struct wlr_allocator *allocator_autocreate_with_drm_fd(
        struct wlr_backend *backend, struct wlr_renderer *renderer,
        int drm_fd) {
    uint32_t backend_caps = backend_get_buffer_caps(backend);
    uint32_t renderer_caps = renderer_get_render_buffer_caps(renderer);

    struct wlr_allocator *alloc = NULL;

#if WLR_HAS_GBM_ALLOCATOR
    uint32_t gbm_caps = WLR_BUFFER_CAP_DMABUF;
    if ((backend_caps & gbm_caps) && (renderer_caps & gbm_caps)
            && drm_fd >= 0) {
        wlr_log(WLR_DEBUG, "Trying to create gbm allocator");
        int gbm_fd = reopen_drm_node(drm_fd, true);
        if (gbm_fd < 0) {
            return NULL;
        }
        if ((alloc = wlr_gbm_allocator_create(gbm_fd)) != NULL) {
            return alloc;
        }
        close(gbm_fd);
        wlr_log(WLR_DEBUG, "Failed to create gbm allocator");
    }
#endif

    // Special case for RDP backend
    if (strcmp(renderer_get_name(renderer), "RDP") == 0) {
        wlr_log(WLR_DEBUG, "Trying to create RDP allocator");
        if ((alloc = wlr_rdp_allocator_create(renderer)) != NULL) {
            return alloc;
        }
        wlr_log(WLR_DEBUG, "Failed to create RDP allocator");
    }

    uint32_t shm_caps = WLR_BUFFER_CAP_SHM | WLR_BUFFER_CAP_DATA_PTR;
    if ((backend_caps & shm_caps) && (renderer_caps & shm_caps)) {
        wlr_log(WLR_DEBUG, "Trying to create shm allocator");
        if ((alloc = wlr_shm_allocator_create()) != NULL) {
            return alloc;
        }
        wlr_log(WLR_DEBUG, "Failed to create shm allocator");
    }

    uint32_t drm_caps = WLR_BUFFER_CAP_DMABUF | WLR_BUFFER_CAP_DATA_PTR;
    if ((backend_caps & drm_caps) && (renderer_caps & drm_caps)
            && drm_fd >= 0 && drmIsMaster(drm_fd)) {
        wlr_log(WLR_DEBUG, "Trying to create drm dumb allocator");
        int dumb_fd = reopen_drm_node(drm_fd, false);
        if (dumb_fd < 0) {
            return NULL;
        }
        if ((alloc = wlr_drm_dumb_allocator_create(dumb_fd)) != NULL) {
            return alloc;
        }
        close(dumb_fd);
        wlr_log(WLR_DEBUG, "Failed to create drm dumb allocator");
    }

    wlr_log(WLR_ERROR, "Failed to create allocator");
    return NULL;
}



































// Implement wlr_allocator_init (if not already defined)
void wlr_allocator_init(struct wlr_allocator *alloc,
        const struct wlr_allocator_interface *impl, uint32_t buffer_caps) {
    assert(impl && impl->destroy && impl->create_buffer);
    memset(alloc, 0, sizeof(*alloc));
    alloc->impl = impl;
    alloc->buffer_caps = buffer_caps;
    wl_signal_init(&alloc->events.destroy);
}

// Implement wlr_allocator_create_buffer (if not already defined)
struct wlr_buffer *wlr_allocator_create_buffer(struct wlr_allocator *alloc,
        int width, int height, const struct wlr_drm_format *format) {
    struct wlr_buffer *buffer =
        alloc->impl->create_buffer(alloc, width, height, format);
    if (buffer == NULL) {
        return NULL;
    }
    if (alloc->buffer_caps & WLR_BUFFER_CAP_DATA_PTR) {
        assert(buffer->impl->begin_data_ptr_access &&
            buffer->impl->end_data_ptr_access);
    }
    if (alloc->buffer_caps & WLR_BUFFER_CAP_DMABUF) {
        assert(buffer->impl->get_dmabuf);
    }
    if (alloc->buffer_caps & WLR_BUFFER_CAP_SHM) {
        assert(buffer->impl->get_shm);
    }
    return buffer;
}

// Implement wlr_allocator_destroy (if not already defined)
void wlr_allocator_destroy(struct wlr_allocator *alloc) {
    if (alloc == NULL) {
        return;
    }
    wl_signal_emit_mutable(&alloc->events.destroy, NULL);
    alloc->impl->destroy(alloc);
}

// Implement wlr_allocator_autocreate (if not already defined)
struct wlr_allocator *wlr_allocator_autocreate(struct wlr_backend *backend,
        struct wlr_renderer *renderer) {
    int drm_fd = wlr_backend_get_drm_fd(backend);
    if (drm_fd < 0) {
        drm_fd = wlr_renderer_get_drm_fd(renderer);
    }
    return allocator_autocreate_with_drm_fd(backend, renderer, drm_fd);
}

// Implement placeholder functions for those referenced but not defined
const char *renderer_get_name(struct wlr_renderer *renderer) {
    // Specific implementation for RDP renderer
    if (renderer) {
        // Add any specific logic to identify RDP renderer if needed
        return "RDP";
    }
    return "unknown";
}

int reopen_drm_node(int drm_fd, bool allow_render_node) {
    // More robust placeholder for DRM node reopening
    if (drm_fd >= 0) {
        // For RDP backend, we might not have a real DRM node
        return drm_fd;
    }
    return -1;
}

int drmIsMaster(int fd) {
    // For RDP backend, we might always want to return true
    // or implement a more sophisticated check
    return 1;
}*/

#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include <wlr/interfaces/wlr_buffer.h>
#include <wlr/render/allocator.h>
#include <wlr/render/wlr_renderer.h>
#include <wlr/util/log.h>

// RDP-specific allocator header
#include "render/allocator/allocator.h"
#include <drm_fourcc.h>
#include <wlr/render/drm_format_set.h>
#include <string.h>
#include <stdlib.h>
#include <wlr/util/log.h>

// Forward declaration of the allocator implementation
static const struct wlr_allocator_interface rdp_allocator_impl;

// Destroy the RDP allocator
static void rdp_allocator_destroy(struct wlr_allocator *alloc) {
    free(alloc);
}

// Destroy an RDP buffer
static void rdp_buffer_destroy(struct wlr_buffer *wlr_buffer) {
    if (!wlr_buffer) return;

    struct rdp_buffer *buffer = wl_container_of(wlr_buffer, buffer, base);
    if (buffer->data) {
        free(buffer->data);
    }
    free(buffer);
}

// Get DMA buffer attributes for RDP buffer
/*
static bool rdp_buffer_get_dmabuf(struct wlr_buffer *wlr_buffer,
                                  struct wlr_dmabuf_attributes *attribs) {
    struct rdp_buffer *buffer = wl_container_of(wlr_buffer, buffer, base);
    
    // Set up basic DMABUF attributes
    attribs->width = buffer->base.width;
    attribs->height = buffer->base.height;
    attribs->format = DRM_FORMAT_XRGB8888;
    attribs->modifier = DRM_FORMAT_MOD_LINEAR;
    attribs->n_planes = 1;
    attribs->offset[0] = 0;
    attribs->stride[0] = buffer->stride;
    attribs->fd[0] = -1;  // We don't actually have a DMA-BUF, but we claim support
    
    return true;  // Return true to indicate we "support" DMABUF
}*/

static bool rdp_buffer_get_dmabuf(struct wlr_buffer *wlr_buffer,
                                  struct wlr_dmabuf_attributes *attribs) {
    // RDP allocator does not support DMABUF
    return false;
}

// Begin data pointer access for RDP buffer
/*
static bool rdp_buffer_begin_data_ptr_access(
    struct wlr_buffer *wlr_buffer, 
    uint32_t flags, 
    void **data, 
    uint32_t *format, 
    size_t *stride
) {
    wlr_log(WLR_DEBUG, "Beginning buffer access");
    struct rdp_buffer *buffer = wl_container_of(wlr_buffer, buffer, base);
    *data = buffer->data;
    *format = DRM_FORMAT_XRGB8888;
    *stride = buffer->base.width * 4;
    wlr_log(WLR_DEBUG, "Buffer access granted");
    return true;
}*/

static bool rdp_buffer_begin_data_ptr_access(
    struct wlr_buffer *wlr_buffer, 
    uint32_t flags, 
    void **data, 
    uint32_t *format, 
    size_t *stride
) {
    struct rdp_buffer *buffer = wl_container_of(wlr_buffer, buffer, base);
    
    if (!buffer->data) {
        wlr_log(WLR_ERROR, "Buffer data is NULL in data ptr access");
        return false;
    }

    *data = buffer->data;
    *format = DRM_FORMAT_XRGB8888;  // Consistent with WSL2/Zink expectations
    *stride = buffer->base.width * 4;
    
    wlr_log(WLR_DEBUG, "Data ptr access granted: %p, stride: %zu", *data, *stride);
    return true;
}
static void rdp_buffer_end_data_ptr_access(struct wlr_buffer *wlr_buffer) {
    // No-op, but could add logging or synchronization if needed
    wlr_log(WLR_DEBUG, "Ending buffer data ptr access");
}

static bool rdp_buffer_get_shm(struct wlr_buffer *wlr_buffer,
    struct wlr_shm_attributes *attribs) {
    struct rdp_buffer *buffer = wl_container_of(wlr_buffer, buffer, base);
    
    if (!buffer->data) {
        return false;
    }
    
    attribs->format = DRM_FORMAT_XRGB8888;
    attribs->width = buffer->base.width;
    attribs->height = buffer->base.height;
    attribs->stride = buffer->stride;
    attribs->offset = 0;
    
    return true;
}



// Buffer implementation for RDP buffers
static const struct wlr_buffer_impl rdp_buffer_impl = {
    .destroy = rdp_buffer_destroy,
    .get_dmabuf = rdp_buffer_get_dmabuf,
    .get_shm = rdp_buffer_get_shm,
    .begin_data_ptr_access = rdp_buffer_begin_data_ptr_access,
    .end_data_ptr_access = rdp_buffer_end_data_ptr_access,
};

// Create a buffer for the RDP allocator

static struct wlr_buffer *rdp_allocator_create_buffer(
    struct wlr_allocator *alloc,
    int width, int height, 
    const struct wlr_drm_format *format
) {
    wlr_log(WLR_INFO, "RDP allocator: creating buffer %dx%d", width, height);
    
    // Create default format with manual allocation
    struct wlr_drm_format *default_format = malloc(sizeof(struct wlr_drm_format) + sizeof(uint64_t));
    if (!default_format) {
        wlr_log(WLR_ERROR, "Failed to allocate default format");
        return NULL;
    }
    
    default_format->format = DRM_FORMAT_XRGB8888;
    default_format->len = 1;
    default_format->modifiers[0] = DRM_FORMAT_MOD_LINEAR;
    
    // If no format is provided, use the default format
    if (!format) {
        wlr_log(WLR_DEBUG, "No format provided, using default XRGB8888");
        format = default_format;
    }

    // Explicitly check and log format
    wlr_log(WLR_DEBUG, "Requested format: 0x%x", format->format);
    
    // Only support XRGB8888 for now
    if (format->format != DRM_FORMAT_XRGB8888) {
        wlr_log(WLR_ERROR, "Unsupported format 0x%x requested from RDP allocator", format->format);
        free(default_format);
        return NULL;
    }
    
    struct rdp_buffer *buffer = calloc(1, sizeof(struct rdp_buffer));
    if (!buffer) {
        wlr_log(WLR_ERROR, "Failed to allocate RDP buffer");
        free(default_format);
        return NULL;
    }

    // Initialize buffer
    wlr_buffer_init(&buffer->base, &rdp_buffer_impl, width, height);

    // Calculate stride and allocate data
    size_t stride = width * 4;  // XRGB8888 = 4 bytes
    if (stride > 0 && height > 0 && stride <= SIZE_MAX / height) {
        size_t size = stride * height;
        wlr_log(WLR_INFO, "RDP buffer: Allocating %zu bytes", size);
        buffer->data = calloc(1, size);
    }

    if (!buffer->data) {
        wlr_log(WLR_ERROR, "Failed to allocate buffer data");
        free(buffer);
        free(default_format);
        return NULL;
    }

    buffer->stride = stride;

    // Free the default format if we created it
    if (default_format != format) {
        free(default_format);
    }

    wlr_log(WLR_INFO, "RDP buffer created successfully");
    return &buffer->base;
}

// Allocator implementation for RDP
static const struct wlr_allocator_interface rdp_allocator_impl = {
    .create_buffer = rdp_allocator_create_buffer,
    .destroy = rdp_allocator_destroy,
};

// Create a new RDP allocator
/*
struct wlr_allocator *wlr_rdp_allocator_create(struct wlr_renderer *renderer) {
    if (!renderer) {
        wlr_log(WLR_ERROR, "Cannot create RDP allocator: no renderer provided");
        return NULL;
    }

    struct wlr_allocator *alloc = calloc(1, sizeof(struct wlr_allocator));
    if (!alloc) {
        wlr_log(WLR_ERROR, "Failed to allocate memory for RDP allocator");
        return NULL;
    }

    uint32_t buffer_caps = WLR_BUFFER_CAP_DATA_PTR | WLR_BUFFER_CAP_SHM;
    
    wlr_allocator_init(alloc, &rdp_allocator_impl, buffer_caps);
    wlr_log(WLR_DEBUG, "RDP allocator created successfully");
    
    return alloc;
}*/

/*
struct wlr_allocator *wlr_rdp_allocator_create(struct wlr_renderer *renderer) {
    if (!renderer) {
        wlr_log(WLR_ERROR, "Cannot create RDP allocator: no renderer provided");
        return NULL;
    }

    // Get renderer capabilities
    uint32_t render_caps = renderer_get_render_buffer_caps(renderer);
    wlr_log(WLR_DEBUG, "Renderer capabilities: 0x%x", render_caps);

    struct wlr_allocator *alloc = calloc(1, sizeof(struct wlr_allocator));
    if (!alloc) {
        wlr_log(WLR_ERROR, "Failed to allocate memory for RDP allocator");
        return NULL;
    }

    // Match renderer capabilities
    uint32_t buffer_caps = render_caps & (WLR_BUFFER_CAP_DATA_PTR | WLR_BUFFER_CAP_SHM);
    wlr_log(WLR_DEBUG, "Setting allocator capabilities: 0x%x", buffer_caps);
    
    wlr_allocator_init(alloc, &rdp_allocator_impl, buffer_caps);
    wlr_log(WLR_DEBUG, "RDP allocator created successfully with caps: 0x%x", alloc->buffer_caps);
    
    return alloc;
}*/

#define WLR_BUFFER_CAP_DMABUF   (1 << 1)

struct wlr_allocator *wlr_rdp_allocator_create(struct wlr_renderer *renderer) {
    if (!renderer) {
        wlr_log(WLR_ERROR, "Cannot create RDP allocator: no renderer provided");
        return NULL;
    }

    // Include all possible capabilities to maximize compatibility
    uint32_t buffer_caps = WLR_BUFFER_CAP_DATA_PTR | 
                           WLR_BUFFER_CAP_DMABUF |   
                           WLR_BUFFER_CAP_SHM;

    wlr_log(WLR_DEBUG, "Creating RDP allocator with explicit capabilities: 0x%x", buffer_caps);

    struct wlr_allocator *alloc = calloc(1, sizeof(struct wlr_allocator));
    if (!alloc) {
        wlr_log(WLR_ERROR, "Failed to allocate memory for RDP allocator");
        return NULL;
    }

    wlr_allocator_init(alloc, &rdp_allocator_impl, buffer_caps);

    wlr_log(WLR_DEBUG, "RDP allocator created with caps: 0x%x", alloc->buffer_caps);
    
    return alloc;
}


































// Implement wlr_allocator_init (if not already defined)
void wlr_allocator_init(struct wlr_allocator *alloc,
        const struct wlr_allocator_interface *impl, uint32_t buffer_caps) {
    assert(impl && impl->destroy && impl->create_buffer);
    memset(alloc, 0, sizeof(*alloc));
    alloc->impl = impl;
    alloc->buffer_caps = buffer_caps;
    wl_signal_init(&alloc->events.destroy);
}

// Implement wlr_allocator_create_buffer (if not already defined)
struct wlr_buffer *wlr_allocator_create_buffer(struct wlr_allocator *alloc,
        int width, int height, const struct wlr_drm_format *format) {
    struct wlr_buffer *buffer =
        alloc->impl->create_buffer(alloc, width, height, format);
    if (buffer == NULL) {
        return NULL;
    }
    if (alloc->buffer_caps & WLR_BUFFER_CAP_DATA_PTR) {
        assert(buffer->impl->begin_data_ptr_access &&
            buffer->impl->end_data_ptr_access);
    }
    if (alloc->buffer_caps & WLR_BUFFER_CAP_DMABUF) {
        assert(buffer->impl->get_dmabuf);
    }
    if (alloc->buffer_caps & WLR_BUFFER_CAP_SHM) {
        assert(buffer->impl->get_shm);
    }
    return buffer;
}

// Implement wlr_allocator_destroy (if not already defined)
void wlr_allocator_destroy(struct wlr_allocator *alloc) {
    if (alloc == NULL) {
        return;
    }
    wl_signal_emit_mutable(&alloc->events.destroy, NULL);
    alloc->impl->destroy(alloc);
}

// Implement wlr_allocator_autocreate (if not already defined)
struct wlr_allocator *wlr_allocator_autocreate(struct wlr_backend *backend,
        struct wlr_renderer *renderer) {
    int drm_fd = wlr_backend_get_drm_fd(backend);
    if (drm_fd < 0) {
        drm_fd = wlr_renderer_get_drm_fd(renderer);
    }
    return allocator_autocreate_with_drm_fd(backend, renderer, drm_fd);
}

// Implement placeholder functions for those referenced but not defined
const char *renderer_get_name(struct wlr_renderer *renderer) {
    // Specific implementation for RDP renderer
    if (renderer) {
        // Add any specific logic to identify RDP renderer if needed
        return "RDP";
    }
    return "unknown";
}

int reopen_drm_node(int drm_fd, bool allow_render_node) {
    // More robust placeholder for DRM node reopening
    if (drm_fd >= 0) {
        // For RDP backend, we might not have a real DRM node
        return drm_fd;
    }
    return -1;
}

int drmIsMaster(int fd) {
    // For RDP backend, we might always want to return true
    // or implement a more sophisticated check
    return 1;
}




struct wlr_allocator *allocator_autocreate_with_drm_fd(
        struct wlr_backend *backend, struct wlr_renderer *renderer,
        int drm_fd) {
    uint32_t backend_caps = backend_get_buffer_caps(backend);
    uint32_t renderer_caps = renderer_get_render_buffer_caps(renderer);

    struct wlr_allocator *alloc = NULL;

    // Try RDP allocator first if it's an RDP backend
    const char *renderer_name = renderer_get_name(renderer);
    if (renderer_name && strcmp(renderer_name, "RDP") == 0) {
        wlr_log(WLR_DEBUG, "Attempting to create RDP allocator");
        alloc = wlr_rdp_allocator_create(renderer);
        if (alloc) {
            wlr_log(WLR_DEBUG, "Successfully created RDP allocator");
            return alloc;
        }
        wlr_log(WLR_ERROR, "Failed to create RDP allocator, trying fallbacks");
    }

    // Try SHM allocator as fallback
    uint32_t shm_caps = WLR_BUFFER_CAP_SHM | WLR_BUFFER_CAP_DATA_PTR;
    if ((backend_caps & shm_caps) && (renderer_caps & shm_caps)) {
        wlr_log(WLR_DEBUG, "Trying to create shm allocator");
        alloc = wlr_shm_allocator_create();
        if (alloc) {
            return alloc;
        }
    }

    wlr_log(WLR_ERROR, "Failed to create any allocator");
    return NULL;
}