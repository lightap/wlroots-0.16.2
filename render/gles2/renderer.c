#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>  // For setenv
#include <assert.h>
#include <drm_fourcc.h>
#include <gbm.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <wayland-server-protocol.h>
#include <wayland-util.h>
#include <wlr/render/egl.h>
#include <wlr/render/interface.h>
#include <wlr/render/wlr_renderer.h>
#include <wlr/types/wlr_matrix.h>
#include <wlr/util/box.h>
#include <wlr/util/log.h>
#include "render/egl.h"
#include "render/gles2.h"
#include "render/pixel_format.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wayland-server-core.h>
#include <wlr/render/egl.h>
#include <wlr/render/interface.h>
#include <wlr/render/wlr_renderer.h>
#include <wlr/util/log.h>
#include <wlr/render/gles2.h>
#include <string.h>  // For strstr
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <wlr/types/wlr_matrix.h>
#include <EGL/eglext.h>



static bool gles2_read_pixels(struct wlr_renderer *wlr_renderer,
    uint32_t drm_format, uint32_t stride, uint32_t width, uint32_t height,
    uint32_t src_x, uint32_t src_y, uint32_t dst_x, uint32_t dst_y, void *data);

// For version checking and vertex array support
#ifndef GL_MAJOR_VERSION
#define GL_MAJOR_VERSION 0x821B
#define GL_MINOR_VERSION 0x821C
#endif



struct wlr_renderer *wlr_gles2_renderer_create_surfaceless(void);

static const GLfloat verts[] = {
	1, 0, // top right
	0, 0, // top left
	1, 1, // bottom right
	0, 1, // bottom left
};




#include <GLES2/gl2.h>
#include "render/gles2.h"

// Colored quads
const GLchar quad_vertex_src[] =
"uniform mat3 proj;\n"
"uniform vec4 color;\n"
"attribute vec2 pos;\n"
"attribute vec2 texcoord;\n"
"varying vec4 v_color;\n"
"varying vec2 v_texcoord;\n"
"\n"
"void main() {\n"
"	gl_Position = vec4(proj * vec3(pos, 1.0), 1.0);\n"
"	v_color = color;\n"
"	v_texcoord = texcoord;\n"
"}\n";

const GLchar quad_fragment_src[] =
"precision mediump float;\n"
"varying vec4 v_color;\n"
"varying vec2 v_texcoord;\n"
"\n"
"void main() {\n"
"	gl_FragColor = v_color;\n"
"}\n";

// Textured quads
const GLchar tex_vertex_src[] =
"uniform mat3 proj;\n"
"uniform bool invert_y;\n"
"attribute vec2 pos;\n"
"attribute vec2 texcoord;\n"
"varying vec2 v_texcoord;\n"
"\n"
"void main() {\n"
"	gl_Position = vec4(proj * vec3(pos, 1.0), 1.0);\n"
"	if (invert_y) {\n"
"		v_texcoord = vec2(texcoord.x, 1.0 - texcoord.y);\n"
"	} else {\n"
"		v_texcoord = texcoord;\n"
"	}\n"
"}\n";

const GLchar tex_fragment_src_rgba[] =
"precision mediump float;\n"
"varying vec2 v_texcoord;\n"
"uniform sampler2D tex;\n"
"uniform float alpha;\n"
"\n"
"void main() {\n"
"	gl_FragColor = texture2D(tex, v_texcoord) * alpha;\n"
"}\n";

const GLchar tex_fragment_src_rgbx[] =
"precision mediump float;\n"
"varying vec2 v_texcoord;\n"
"uniform sampler2D tex;\n"
"uniform float alpha;\n"
"\n"
"void main() {\n"
"	gl_FragColor = vec4(texture2D(tex, v_texcoord).rgb, 1.0) * alpha;\n"
"}\n";

const GLchar tex_fragment_src_external[] =
"#extension GL_OES_EGL_image_external : require\n\n"
"precision mediump float;\n"
"varying vec2 v_texcoord;\n"
"uniform samplerExternalOES texture0;\n"
"uniform float alpha;\n"
"\n"
"void main() {\n"
"	gl_FragColor = texture2D(texture0, v_texcoord) * alpha;\n"
"}\n";





static const struct wlr_renderer_impl renderer_impl;


// Add these function declarations or implementations
static GLuint gl_shader_program_create(const char *vert_src, const char *frag_src) {
    GLuint vert = glCreateShader(GL_VERTEX_SHADER);
    GLuint frag = glCreateShader(GL_FRAGMENT_SHADER);
    
    glShaderSource(vert, 1, &vert_src, NULL);
    glShaderSource(frag, 1, &frag_src, NULL);
    
    glCompileShader(vert);
    glCompileShader(frag);
    
    GLuint prog = glCreateProgram();
    glAttachShader(prog, vert);
    glAttachShader(prog, frag);
    glLinkProgram(prog);
    
    glDeleteShader(vert);
    glDeleteShader(frag);
    
    return prog;
}

bool wlr_renderer_is_gles2(struct wlr_renderer *wlr_renderer) {
	return wlr_renderer->impl == &renderer_impl;
}

struct wlr_gles2_renderer *gles2_get_renderer(
		struct wlr_renderer *wlr_renderer) {
	assert(wlr_renderer_is_gles2(wlr_renderer));
	return (struct wlr_gles2_renderer *)wlr_renderer;
}

static struct wlr_gles2_renderer *gles2_get_renderer_in_context(
		struct wlr_renderer *wlr_renderer) {
	struct wlr_gles2_renderer *renderer = gles2_get_renderer(wlr_renderer);
	assert(wlr_egl_is_current(renderer->egl));
	assert(renderer->current_buffer != NULL);
	return renderer;
}

static void destroy_buffer(struct wlr_gles2_buffer *buffer) {
	wl_list_remove(&buffer->link);
	wlr_addon_finish(&buffer->addon);

	struct wlr_egl_context prev_ctx;
	wlr_egl_save_context(&prev_ctx);
	wlr_egl_make_current(buffer->renderer->egl);

	push_gles2_debug(buffer->renderer);

	glDeleteFramebuffers(1, &buffer->fbo);
	glDeleteRenderbuffers(1, &buffer->rbo);
    glDeleteTextures(1, &buffer->texture); // Explicitly delete texture

	pop_gles2_debug(buffer->renderer);

	wlr_egl_destroy_image(buffer->renderer->egl, buffer->image);

	wlr_egl_restore_context(&prev_ctx);

	free(buffer);
}

static void handle_buffer_destroy(struct wlr_addon *addon) {
	struct wlr_gles2_buffer *buffer =
		wl_container_of(addon, buffer, addon);
	destroy_buffer(buffer);
}

static const struct wlr_addon_interface buffer_addon_impl = {
	.name = "wlr_gles2_buffer",
	.destroy = handle_buffer_destroy,
};

static struct wlr_gles2_buffer *get_buffer(struct wlr_gles2_renderer *renderer,
		struct wlr_buffer *wlr_buffer) {
	struct wlr_addon *addon =
		wlr_addon_find(&wlr_buffer->addons, renderer, &buffer_addon_impl);
	if (addon == NULL) {
		return NULL;
	}
	struct wlr_gles2_buffer *buffer = wl_container_of(addon, buffer, addon);
	return buffer;
}
/*
static struct wlr_gles2_buffer *create_buffer(struct wlr_gles2_renderer *renderer,
        struct wlr_buffer *wlr_buffer) {
    wlr_log(WLR_DEBUG, "Creating GLES2 buffer for %dx%d", 
        wlr_buffer->width, wlr_buffer->height);

    struct wlr_gles2_buffer *buffer = calloc(1, sizeof(*buffer));
    if (!buffer) {
        return NULL;
    }

    buffer->buffer = wlr_buffer;
    buffer->renderer = renderer;

    // Access buffer data
    void *data_ptr;
    uint32_t format;
    size_t stride;  // Changed from uint32_t to size_t
    
    if (!wlr_buffer_begin_data_ptr_access(wlr_buffer, 
            WLR_BUFFER_DATA_PTR_ACCESS_READ, 
            &data_ptr, &format, &stride)) {
        wlr_log(WLR_ERROR, "Failed to access buffer data");
        free(buffer);
        return NULL;
    }

    push_gles2_debug(renderer);

    // Create and upload texture
    glGenTextures(1, &buffer->texture);
    glBindTexture(GL_TEXTURE_2D, buffer->texture);
    
    // Configure texture parameters
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

    // Upload texture data - XRGB8888 format
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 
        wlr_buffer->width, wlr_buffer->height, 0,
        GL_RGBA, GL_UNSIGNED_BYTE, data_ptr);

    // Release buffer access
    wlr_buffer_end_data_ptr_access(wlr_buffer);

    // Create and setup FBO
    glGenFramebuffers(1, &buffer->fbo);
    glBindFramebuffer(GL_FRAMEBUFFER, buffer->fbo);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
        GL_TEXTURE_2D, buffer->texture, 0);

    GLenum status = glCheckFramebufferStatus(GL_FRAMEBUFFER);
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glBindTexture(GL_TEXTURE_2D, 0);

    pop_gles2_debug(renderer);

    if (status != GL_FRAMEBUFFER_COMPLETE) {
        wlr_log(WLR_ERROR, "Failed to create FBO: %x", status);
        glDeleteFramebuffers(1, &buffer->fbo);
        glDeleteTextures(1, &buffer->texture);
        free(buffer);
        return NULL;
    }

    wlr_addon_init(&buffer->addon, &wlr_buffer->addons, renderer,
        &buffer_addon_impl);
    wl_list_insert(&renderer->buffers, &buffer->link);

    return buffer;
}*/
/*
static struct wlr_gles2_buffer *create_buffer(struct wlr_gles2_renderer *renderer,
        struct wlr_buffer *wlr_buffer) {
    wlr_log(WLR_DEBUG, "Creating GLES2 buffer for %dx%d", 
        wlr_buffer->width, wlr_buffer->height);

    // Check for null renderer and log initial list state
    if (!renderer) {
        wlr_log(WLR_ERROR, "Null renderer in create_buffer");
        return NULL;
    }

    wlr_log(WLR_DEBUG, "Initial list state - head: %p, prev: %p, next: %p",
        &renderer->buffers, renderer->buffers.prev, renderer->buffers.next);

    // Create buffer
    struct wlr_gles2_buffer *buffer = calloc(1, sizeof(*buffer));
    if (!buffer) {
        return NULL;
    }

    buffer->buffer = wlr_buffer;
    buffer->renderer = renderer;

    // Access buffer data
    void *data_ptr;
    uint32_t format;
    size_t stride;
    
    if (!wlr_buffer_begin_data_ptr_access(wlr_buffer, 
            WLR_BUFFER_DATA_PTR_ACCESS_READ, 
            &data_ptr, &format, &stride)) {
        wlr_log(WLR_ERROR, "Failed to access buffer data");
        free(buffer);
        return NULL;
    }

    push_gles2_debug(renderer);

    // Create and upload texture
    glGenTextures(1, &buffer->texture);
    glBindTexture(GL_TEXTURE_2D, buffer->texture);
    
    // Configure texture parameters
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

    // Upload texture data - XRGB8888 format
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 
        wlr_buffer->width, wlr_buffer->height, 0,
        GL_RGBA, GL_UNSIGNED_BYTE, data_ptr);

    // Release buffer access
    wlr_buffer_end_data_ptr_access(wlr_buffer);

    // Create and setup FBO
    glGenFramebuffers(1, &buffer->fbo);
    glBindFramebuffer(GL_FRAMEBUFFER, buffer->fbo);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
        GL_TEXTURE_2D, buffer->texture, 0);

    GLenum status = glCheckFramebufferStatus(GL_FRAMEBUFFER);
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glBindTexture(GL_TEXTURE_2D, 0);

    pop_gles2_debug(renderer);

    if (status != GL_FRAMEBUFFER_COMPLETE) {
        wlr_log(WLR_ERROR, "Failed to create FBO: %x", status);
        glDeleteFramebuffers(1, &buffer->fbo);
        glDeleteTextures(1, &buffer->texture);
        free(buffer);
        return NULL;
    }

    // Initialize Wayland resources
    wlr_addon_init(&buffer->addon, &wlr_buffer->addons, renderer,
        &buffer_addon_impl);

    // Check list state and reinitialize if necessary
    if (renderer->buffers.prev == NULL || renderer->buffers.next == NULL) {
        wlr_log(WLR_DEBUG, "List appears corrupted, reinitializing");
        wl_list_init(&renderer->buffers);
    }

    // Verify list state after potential reinitialization
    wlr_log(WLR_DEBUG, "List state after init - head: %p, prev: %p, next: %p",
        &renderer->buffers, renderer->buffers.prev, renderer->buffers.next);

    // Initialize buffer's own list link
    wl_list_init(&buffer->link);

    // Insert into renderer's buffer list
    wl_list_insert(&renderer->buffers, &buffer->link);

    // Verify final state
    wlr_log(WLR_DEBUG, "Final list state - head next: %p, head prev: %p, buffer next: %p, buffer prev: %p",
        renderer->buffers.next, renderer->buffers.prev,
        buffer->link.next, buffer->link.prev);

    return buffer;
}*/

static struct wlr_gles2_buffer *create_buffer(struct wlr_gles2_renderer *renderer,
        struct wlr_buffer *wlr_buffer) {
    // Log entry for debugging
    wlr_log(WLR_DEBUG, "Creating GLES2 buffer for %dx%d", 
            wlr_buffer->width, wlr_buffer->height);

    // Validate inputs
    if (!renderer) {
        wlr_log(WLR_ERROR, "Null renderer in create_buffer");
        return NULL;
    }
    if (!wlr_buffer) {
        wlr_log(WLR_ERROR, "Null wlr_buffer in create_buffer");
        return NULL;
    }

    // Log initial buffer list state
    wlr_log(WLR_DEBUG, "Initial buffer list state - head: %p, prev: %p, next: %p",
            &renderer->buffers, renderer->buffers.prev, renderer->buffers.next);

    // Allocate buffer structure
    struct wlr_gles2_buffer *buffer = calloc(1, sizeof(*buffer));
    if (!buffer) {
        wlr_log(WLR_ERROR, "Failed to allocate wlr_gles2_buffer");
        return NULL;
    }

    // Initialize basic fields
    buffer->buffer = wlr_buffer;
    buffer->renderer = renderer;
    buffer->texture = 0;  // Initialize to 0 for safety
    buffer->fbo = 0;
    buffer->rbo = 0;
    buffer->image = EGL_NO_IMAGE_KHR;

    // Access buffer data
    void *data_ptr;
    uint32_t format;
    size_t stride;
    if (!wlr_buffer_begin_data_ptr_access(wlr_buffer, 
            WLR_BUFFER_DATA_PTR_ACCESS_READ, 
            &data_ptr, &format, &stride)) {
        wlr_log(WLR_ERROR, "Failed to access buffer data");
        free(buffer);
        return NULL;
    }

    // Make EGL context current for OpenGL operations
    struct wlr_egl_context prev_ctx;
    wlr_egl_save_context(&prev_ctx);
    if (!wlr_egl_make_current(renderer->egl)) {
        wlr_log(WLR_ERROR, "Failed to make EGL context current");
        wlr_buffer_end_data_ptr_access(wlr_buffer);
        free(buffer);
        return NULL;
    }

    push_gles2_debug(renderer);

    // Create and configure texture
    glGenTextures(1, &buffer->texture);
    if (buffer->texture == 0) {
        wlr_log(WLR_ERROR, "Failed to generate texture");
        goto error_cleanup;
    }
    glBindTexture(GL_TEXTURE_2D, buffer->texture);
    
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

    // Upload texture data (assuming XRGB8888 format; adjust if needed)
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 
                 wlr_buffer->width, wlr_buffer->height, 0,
                 GL_RGBA, GL_UNSIGNED_BYTE, data_ptr);
    GLenum tex_error = glGetError();
    if (tex_error != GL_NO_ERROR) {
        wlr_log(WLR_ERROR, "glTexImage2D failed with error: 0x%x", tex_error);
        goto error_cleanup;
    }

    // Release buffer access
    wlr_buffer_end_data_ptr_access(wlr_buffer);

    // Create and setup framebuffer
    glGenFramebuffers(1, &buffer->fbo);
    if (buffer->fbo == 0) {
        wlr_log(WLR_ERROR, "Failed to generate framebuffer");
        goto error_cleanup;
    }
    glBindFramebuffer(GL_FRAMEBUFFER, buffer->fbo);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                          GL_TEXTURE_2D, buffer->texture, 0);

    GLenum status = glCheckFramebufferStatus(GL_FRAMEBUFFER);
    if (status != GL_FRAMEBUFFER_COMPLETE) {
        wlr_log(WLR_ERROR, "Framebuffer incomplete, status: 0x%x", status);
        goto error_cleanup;
    }

    // Unbind texture and framebuffer
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glBindTexture(GL_TEXTURE_2D, 0);

    pop_gles2_debug(renderer);

    // Initialize Wayland resources
    wlr_addon_init(&buffer->addon, &wlr_buffer->addons, renderer, &buffer_addon_impl);
    wl_list_init(&buffer->link);

    // Ensure buffer list is valid, reinitialize if corrupted
    if (renderer->buffers.prev == NULL || renderer->buffers.next == NULL) {
        wlr_log(WLR_DEBUG, "Buffer list appears corrupted, reinitializing");
        wl_list_init(&renderer->buffers);
    }

    // Insert buffer into renderer's list
    wl_list_insert(&renderer->buffers, &buffer->link);
    if (buffer->link.prev == NULL || buffer->link.next == NULL) {
        wlr_log(WLR_ERROR, "Failed to insert buffer into renderer->buffers");
        goto error_cleanup_list;
    }

    // Log final state
    wlr_log(WLR_DEBUG, "Buffer created - texture: %u, fbo: %u, list: head next: %p, buffer prev: %p",
            buffer->texture, buffer->fbo, renderer->buffers.next, buffer->link.prev);

    // Restore previous EGL context
    wlr_egl_restore_context(&prev_ctx);

    return buffer;

error_cleanup_list:
    // Cleanup addon and list if insertion failed
    wlr_addon_finish(&buffer->addon);
    wl_list_remove(&buffer->link);

error_cleanup:
    // Cleanup OpenGL resources on error
    push_gles2_debug(renderer);
    if (buffer->fbo != 0) {
        glDeleteFramebuffers(1, &buffer->fbo);
    }
    if (buffer->texture != 0) {
        glDeleteTextures(1, &buffer->texture);
    }
    pop_gles2_debug(renderer);

    // Restore EGL context and free buffer
    wlr_egl_restore_context(&prev_ctx);
    wlr_buffer_end_data_ptr_access(wlr_buffer);
    free(buffer);

    return NULL;
}

/*
static bool gles2_bind_buffer(struct wlr_renderer *wlr_renderer,
		struct wlr_buffer *wlr_buffer) {
	struct wlr_gles2_renderer *renderer = gles2_get_renderer(wlr_renderer);

	if (renderer->current_buffer != NULL) {
		assert(wlr_egl_is_current(renderer->egl));

		push_gles2_debug(renderer);
		glFlush();
		glBindFramebuffer(GL_FRAMEBUFFER, 0);
		pop_gles2_debug(renderer);

		wlr_buffer_unlock(renderer->current_buffer->buffer);
		renderer->current_buffer = NULL;
	}

	if (wlr_buffer == NULL) {
		wlr_egl_unset_current(renderer->egl);
		return true;
	}

	wlr_egl_make_current(renderer->egl);

	struct wlr_gles2_buffer *buffer = get_buffer(renderer, wlr_buffer);
	if (buffer == NULL) {
		buffer = create_buffer(renderer, wlr_buffer);
	}
	if (buffer == NULL) {
		return false;
	}

	wlr_buffer_lock(wlr_buffer);
	renderer->current_buffer = buffer;

	push_gles2_debug(renderer);
	glBindFramebuffer(GL_FRAMEBUFFER, renderer->current_buffer->fbo);
	pop_gles2_debug(renderer);

	return true;
}*/

static bool gles2_bind_buffer(struct wlr_renderer *wlr_renderer,
        struct wlr_buffer *wlr_buffer) {
    struct wlr_gles2_renderer *renderer = gles2_get_renderer(wlr_renderer);

    // Add extensive logging
    wlr_log(WLR_DEBUG, "GLES2 Bind Buffer: Entering function");
    wlr_log(WLR_DEBUG, "  Renderer: %p", (void*)renderer);
    wlr_log(WLR_DEBUG, "  Buffer: %p", (void*)wlr_buffer);

    // If there's a current buffer, handle it first
    if (renderer->current_buffer != NULL) {
        wlr_log(WLR_DEBUG, "  Existing buffer found, unbinding");
        assert(wlr_egl_is_current(renderer->egl));

        push_gles2_debug(renderer);
        glFlush();
        glBindFramebuffer(GL_FRAMEBUFFER, 0);
        pop_gles2_debug(renderer);

        wlr_buffer_unlock(renderer->current_buffer->buffer);
        renderer->current_buffer = NULL;
    }

    // NULL buffer means just unbind
    if (wlr_buffer == NULL) {
        wlr_log(WLR_DEBUG, "  NULL buffer, unsetting EGL context");
        wlr_egl_unset_current(renderer->egl);
        return true;
    }

    // Ensure EGL context is current
    if (!wlr_egl_make_current(renderer->egl)) {
        wlr_log(WLR_ERROR, "  Failed to make EGL context current");
        return false;
    }

    // Try to get or create a buffer
    struct wlr_gles2_buffer *buffer = get_buffer(renderer, wlr_buffer);
    if (buffer == NULL) {
        wlr_log(WLR_DEBUG, "  No existing buffer, attempting to create");
        buffer = create_buffer(renderer, wlr_buffer);
    }

    // Check buffer creation
    if (buffer == NULL) {
        wlr_log(WLR_ERROR, "  Failed to get or create buffer");
        return false;
    }

    // Lock the buffer and set as current
    wlr_buffer_lock(wlr_buffer);
    renderer->current_buffer = buffer;

    // Bind framebuffer
    push_gles2_debug(renderer);
    glBindFramebuffer(GL_FRAMEBUFFER, renderer->current_buffer->fbo);
    
    // Validate framebuffer
    GLenum status = glCheckFramebufferStatus(GL_FRAMEBUFFER);
    if (status != GL_FRAMEBUFFER_COMPLETE) {
        wlr_log(WLR_ERROR, "  Framebuffer is not complete. Status: 0x%x", status);
    }
    
    pop_gles2_debug(renderer);

    wlr_log(WLR_DEBUG, "  Successfully bound buffer");
    return true;
}


static void gles2_begin(struct wlr_renderer *wlr_renderer, uint32_t width,
        uint32_t height) {
    struct wlr_gles2_renderer *renderer =
        gles2_get_renderer_in_context(wlr_renderer);

    push_gles2_debug(renderer);

    glViewport(0, 0, width, height);
    renderer->viewport_width = width;
    renderer->viewport_height = height;

    // Create an orthographic projection matrix
    float projection[9];
    wlr_matrix_identity(projection);
    
    // Scale to fit the viewport
    float sx = 2.0f / width;
    float sy = -2.0f / height;
    wlr_matrix_scale(projection, sx, sy);
    
    // Translate to center
    wlr_matrix_translate(projection, -1.0f, 1.0f);

    struct wlr_box box = {
        .x = 0,
        .y = 0,
        .width = width,
        .height = height
    };
    wlr_matrix_project_box(renderer->projection, &box, 
        WL_OUTPUT_TRANSFORM_NORMAL, 0, projection);

    glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);

    pop_gles2_debug(renderer);
}
static void gles2_end(struct wlr_renderer *wlr_renderer) {
	gles2_get_renderer_in_context(wlr_renderer);
	// no-op
}

static void gles2_clear(struct wlr_renderer *wlr_renderer,
		const float color[static 4]) {
	struct wlr_gles2_renderer *renderer =
		gles2_get_renderer_in_context(wlr_renderer);

	push_gles2_debug(renderer);
	glClearColor(color[0], color[1], color[2], color[3]);
	glClear(GL_COLOR_BUFFER_BIT);
	pop_gles2_debug(renderer);
}

static void gles2_scissor(struct wlr_renderer *wlr_renderer,
		struct wlr_box *box) {
	struct wlr_gles2_renderer *renderer =
		gles2_get_renderer_in_context(wlr_renderer);

	push_gles2_debug(renderer);
	if (box != NULL) {
		glScissor(box->x, box->y, box->width, box->height);
		glEnable(GL_SCISSOR_TEST);
	} else {
		glDisable(GL_SCISSOR_TEST);
	}
	pop_gles2_debug(renderer);
}

static const float flip_180[9] = {
	1.0f, 0.0f, 0.0f,
	0.0f, -1.0f, 0.0f,
	0.0f, 0.0f, 1.0f,
};

static bool gles2_render_subtexture_with_matrix(
		struct wlr_renderer *wlr_renderer, struct wlr_texture *wlr_texture,
		const struct wlr_fbox *box, const float matrix[static 9],
		float alpha) {
	struct wlr_gles2_renderer *renderer =
		gles2_get_renderer_in_context(wlr_renderer);
	struct wlr_gles2_texture *texture =
		gles2_get_texture(wlr_texture);
	assert(texture->renderer == renderer);

	struct wlr_gles2_tex_shader *shader = NULL;

	switch (texture->target) {
	case GL_TEXTURE_2D:
		if (texture->has_alpha) {
			shader = &renderer->shaders.tex_rgba;
		} else {
			shader = &renderer->shaders.tex_rgbx;
		}
		break;
	case GL_TEXTURE_EXTERNAL_OES:
		shader = &renderer->shaders.tex_ext;

		if (!renderer->exts.OES_egl_image_external) {
			wlr_log(WLR_ERROR, "Failed to render texture: "
				"GL_TEXTURE_EXTERNAL_OES not supported");
			return false;
		}
		break;
	default:
		abort();
	}

	float gl_matrix[9];
	wlr_matrix_multiply(gl_matrix, renderer->projection, matrix);
	wlr_matrix_multiply(gl_matrix, flip_180, gl_matrix);

	// OpenGL ES 2 requires the glUniformMatrix3fv transpose parameter to be set
	// to GL_FALSE
	wlr_matrix_transpose(gl_matrix, gl_matrix);

	push_gles2_debug(renderer);

	if (!texture->has_alpha && alpha == 1.0) {
		glDisable(GL_BLEND);
	} else {
		glEnable(GL_BLEND);
	}

	glActiveTexture(GL_TEXTURE0);
	glBindTexture(texture->target, texture->tex);

	glTexParameteri(texture->target, GL_TEXTURE_MIN_FILTER, GL_LINEAR);

	glUseProgram(shader->program);

	glUniformMatrix3fv(shader->proj, 1, GL_FALSE, gl_matrix);
	glUniform1i(shader->invert_y, texture->inverted_y);
	glUniform1i(shader->tex, 0);
	glUniform1f(shader->alpha, alpha);

	const GLfloat x1 = box->x / wlr_texture->width;
	const GLfloat y1 = box->y / wlr_texture->height;
	const GLfloat x2 = (box->x + box->width) / wlr_texture->width;
	const GLfloat y2 = (box->y + box->height) / wlr_texture->height;
	const GLfloat texcoord[] = {
		x2, y1, // top right
		x1, y1, // top left
		x2, y2, // bottom right
		x1, y2, // bottom left
	};

	glVertexAttribPointer(shader->pos_attrib, 2, GL_FLOAT, GL_FALSE, 0, verts);
	glVertexAttribPointer(shader->tex_attrib, 2, GL_FLOAT, GL_FALSE, 0, texcoord);

	glEnableVertexAttribArray(shader->pos_attrib);
	glEnableVertexAttribArray(shader->tex_attrib);

	glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);

	glDisableVertexAttribArray(shader->pos_attrib);
	glDisableVertexAttribArray(shader->tex_attrib);

	glBindTexture(texture->target, 0);

	pop_gles2_debug(renderer);
	return true;
}

static void gles2_render_quad_with_matrix(struct wlr_renderer *wlr_renderer,
		const float color[static 4], const float matrix[static 9]) {
	struct wlr_gles2_renderer *renderer =
		gles2_get_renderer_in_context(wlr_renderer);

	float gl_matrix[9];
	wlr_matrix_multiply(gl_matrix, renderer->projection, matrix);
	wlr_matrix_multiply(gl_matrix, flip_180, gl_matrix);

	// OpenGL ES 2 requires the glUniformMatrix3fv transpose parameter to be set
	// to GL_FALSE
	wlr_matrix_transpose(gl_matrix, gl_matrix);

	push_gles2_debug(renderer);

	if (color[3] == 1.0) {
		glDisable(GL_BLEND);
	} else {
		glEnable(GL_BLEND);
	}

	glUseProgram(renderer->shaders.quad.program);

	glUniformMatrix3fv(renderer->shaders.quad.proj, 1, GL_FALSE, gl_matrix);
	glUniform4f(renderer->shaders.quad.color, color[0], color[1], color[2], color[3]);

	glVertexAttribPointer(renderer->shaders.quad.pos_attrib, 2, GL_FLOAT, GL_FALSE,
			0, verts);

	glEnableVertexAttribArray(renderer->shaders.quad.pos_attrib);

	glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);

	glDisableVertexAttribArray(renderer->shaders.quad.pos_attrib);

	pop_gles2_debug(renderer);
}

static const uint32_t *gles2_get_shm_texture_formats(
        struct wlr_renderer *wlr_renderer, size_t *len) {
   // struct wlr_gles2_renderer *renderer = gles2_get_renderer(wlr_renderer);
    
    // Explicitly include both ARGB8888 and XRGB8888
    static const uint32_t formats[] = {
        WL_SHM_FORMAT_ARGB8888,
        WL_SHM_FORMAT_XRGB8888,
        // Add other formats as needed
    };
    
    *len = sizeof(formats) / sizeof(formats[0]);
    return formats;
}

static const struct wlr_drm_format_set *gles2_get_dmabuf_texture_formats(
		struct wlr_renderer *wlr_renderer) {
	struct wlr_gles2_renderer *renderer = gles2_get_renderer(wlr_renderer);
	return wlr_egl_get_dmabuf_texture_formats(renderer->egl);
}

static const struct wlr_drm_format_set *gles2_get_render_formats(
		struct wlr_renderer *wlr_renderer) {
	struct wlr_gles2_renderer *renderer = gles2_get_renderer(wlr_renderer);
	return wlr_egl_get_dmabuf_render_formats(renderer->egl);
}

static uint32_t gles2_preferred_read_format(
		struct wlr_renderer *wlr_renderer) {
	struct wlr_gles2_renderer *renderer =
		gles2_get_renderer_in_context(wlr_renderer);

	push_gles2_debug(renderer);

	GLint gl_format = -1, gl_type = -1;
	glGetIntegerv(GL_IMPLEMENTATION_COLOR_READ_FORMAT, &gl_format);
	glGetIntegerv(GL_IMPLEMENTATION_COLOR_READ_TYPE, &gl_type);

	EGLint alpha_size = -1;
	glBindRenderbuffer(GL_RENDERBUFFER, renderer->current_buffer->rbo);
	glGetRenderbufferParameteriv(GL_RENDERBUFFER,
		GL_RENDERBUFFER_ALPHA_SIZE, &alpha_size);
	glBindRenderbuffer(GL_RENDERBUFFER, 0);

	pop_gles2_debug(renderer);

	const struct wlr_gles2_pixel_format *fmt =
		get_gles2_format_from_gl(gl_format, gl_type, alpha_size > 0);
	if (fmt != NULL) {
		return fmt->drm_format;
	}

	if (renderer->exts.EXT_read_format_bgra) {
		return DRM_FORMAT_XRGB8888;
	}
	return DRM_FORMAT_XBGR8888;
}

static bool gles2_read_pixels(struct wlr_renderer *wlr_renderer,
    uint32_t drm_format, uint32_t stride, uint32_t width, uint32_t height,
    uint32_t src_x, uint32_t src_y, uint32_t dst_x, uint32_t dst_y, void *data) {
    struct wlr_gles2_renderer *renderer =
        gles2_get_renderer_in_context(wlr_renderer);

    const struct wlr_gles2_pixel_format *fmt =
        get_gles2_format_from_drm(drm_format);
    if (fmt == NULL || !is_gles2_pixel_format_supported(renderer, fmt)) {
        wlr_log(WLR_ERROR, "Cannot read pixels: unsupported pixel format 0x%"PRIX32, drm_format);
        return false;
    }

    const struct wlr_pixel_format_info *drm_fmt =
        drm_get_pixel_format_info(fmt->drm_format);
    assert(drm_fmt);

    push_gles2_debug(renderer);

    // Make sure any pending drawing is finished before we try to read it
    glFinish();

    glGetError(); // Clear the error flag

    unsigned char *p = (unsigned char *)data + dst_y * stride;
    uint32_t pack_stride = width * drm_fmt->bpp / 8;
    if (pack_stride == stride && dst_x == 0) {
        // Under these particular conditions, we can read the pixels with only
        // one glReadPixels call

        glReadPixels(src_x, src_y, width, height, fmt->gl_format, fmt->gl_type, p);
    } else {
        // Unfortunately GLES2 doesn't support GL_PACK_*, so we have to read
        // the lines out row by row
        for (size_t i = 0; i < height; ++i) {
            uint32_t y = src_y + i;
            glReadPixels(src_x, y, width, 1, fmt->gl_format,
                fmt->gl_type, p + i * stride + dst_x * drm_fmt->bpp / 8);
        }
    }

    pop_gles2_debug(renderer);

    return glGetError() == GL_NO_ERROR;
}



static int gles2_get_drm_fd(struct wlr_renderer *wlr_renderer) {
	struct wlr_gles2_renderer *renderer =
		gles2_get_renderer(wlr_renderer);

	if (renderer->drm_fd < 0) {
		renderer->drm_fd = wlr_egl_dup_drm_fd(renderer->egl);
	}

	return renderer->drm_fd;
}

static uint32_t gles2_get_render_buffer_caps(struct wlr_renderer *wlr_renderer) {
	return WLR_BUFFER_CAP_DMABUF;
}

struct wlr_egl *wlr_gles2_renderer_get_egl(struct wlr_renderer *wlr_renderer) {
	struct wlr_gles2_renderer *renderer =
		gles2_get_renderer(wlr_renderer);
	return renderer->egl;
}

static void gles2_destroy(struct wlr_renderer *wlr_renderer) {
	struct wlr_gles2_renderer *renderer = gles2_get_renderer(wlr_renderer);

	wlr_egl_make_current(renderer->egl);

	struct wlr_gles2_buffer *buffer, *buffer_tmp;
	wl_list_for_each_safe(buffer, buffer_tmp, &renderer->buffers, link) {
		destroy_buffer(buffer);
	}

	struct wlr_gles2_texture *tex, *tex_tmp;
	wl_list_for_each_safe(tex, tex_tmp, &renderer->textures, link) {
		gles2_texture_destroy(tex);
	}

	push_gles2_debug(renderer);
	glDeleteProgram(renderer->shaders.quad.program);
	glDeleteProgram(renderer->shaders.tex_rgba.program);
	glDeleteProgram(renderer->shaders.tex_rgbx.program);
	glDeleteProgram(renderer->shaders.tex_ext.program);
	pop_gles2_debug(renderer);

	if (renderer->exts.KHR_debug) {
		glDisable(GL_DEBUG_OUTPUT_KHR);
		renderer->procs.glDebugMessageCallbackKHR(NULL, NULL);
	}

	wlr_egl_unset_current(renderer->egl);
	wlr_egl_destroy(renderer->egl);

	if (renderer->drm_fd >= 0) {
		close(renderer->drm_fd);
	}

	free(renderer);
}

static const struct wlr_renderer_impl renderer_impl = {
	.destroy = gles2_destroy,
	.bind_buffer = gles2_bind_buffer,
	.begin = gles2_begin,
	.end = gles2_end,
	.clear = gles2_clear,
	.scissor = gles2_scissor,
	.render_subtexture_with_matrix = gles2_render_subtexture_with_matrix,
	.render_quad_with_matrix = gles2_render_quad_with_matrix,
	.get_shm_texture_formats = gles2_get_shm_texture_formats,
	.get_dmabuf_texture_formats = gles2_get_dmabuf_texture_formats,
	.get_render_formats = gles2_get_render_formats,
	.preferred_read_format = gles2_preferred_read_format,
	.read_pixels = gles2_read_pixels,
	.get_drm_fd = gles2_get_drm_fd,
	.get_render_buffer_caps = gles2_get_render_buffer_caps,
	.texture_from_buffer = gles2_texture_from_buffer,
};

void push_gles2_debug_(struct wlr_gles2_renderer *renderer,
		const char *file, const char *func) {
	if (!renderer->procs.glPushDebugGroupKHR) {
		return;
	}

	int len = snprintf(NULL, 0, "%s:%s", file, func) + 1;
	char str[len];
	snprintf(str, len, "%s:%s", file, func);
	renderer->procs.glPushDebugGroupKHR(GL_DEBUG_SOURCE_APPLICATION_KHR, 1, -1, str);
}

void pop_gles2_debug(struct wlr_gles2_renderer *renderer) {
	if (renderer->procs.glPopDebugGroupKHR) {
		renderer->procs.glPopDebugGroupKHR();
	}
}
/*
static enum wlr_log_importance gles2_log_importance_to_wlr(GLenum type) {
	switch (type) {
	case GL_DEBUG_TYPE_ERROR_KHR:               return WLR_ERROR;
	case GL_DEBUG_TYPE_DEPRECATED_BEHAVIOR_KHR: return WLR_DEBUG;
	case GL_DEBUG_TYPE_UNDEFINED_BEHAVIOR_KHR:  return WLR_ERROR;
	case GL_DEBUG_TYPE_PORTABILITY_KHR:         return WLR_DEBUG;
	case GL_DEBUG_TYPE_PERFORMANCE_KHR:         return WLR_DEBUG;
	case GL_DEBUG_TYPE_OTHER_KHR:               return WLR_DEBUG;
	case GL_DEBUG_TYPE_MARKER_KHR:              return WLR_DEBUG;
	case GL_DEBUG_TYPE_PUSH_GROUP_KHR:          return WLR_DEBUG;
	case GL_DEBUG_TYPE_POP_GROUP_KHR:           return WLR_DEBUG;
	default:                                    return WLR_DEBUG;
	}
}*/
/*
static void gles2_log(GLenum src, GLenum type, GLuint id, GLenum severity,
		GLsizei len, const GLchar *msg, const void *user) {
	_wlr_log(gles2_log_importance_to_wlr(type), "[GLES2] %s", msg);
}*/
/*
static GLuint compile_shader(struct wlr_gles2_renderer *renderer,
		GLuint type, const GLchar *src) {
	push_gles2_debug(renderer);

	GLuint shader = glCreateShader(type);
	glShaderSource(shader, 1, &src, NULL);
	glCompileShader(shader);

	GLint ok;
	glGetShaderiv(shader, GL_COMPILE_STATUS, &ok);
	if (ok == GL_FALSE) {
		glDeleteShader(shader);
		shader = 0;
	}

	pop_gles2_debug(renderer);
	return shader;
}*/
/*
static GLuint link_program(struct wlr_gles2_renderer *renderer,
		const GLchar *vert_src, const GLchar *frag_src) {
	push_gles2_debug(renderer);

	GLuint vert = compile_shader(renderer, GL_VERTEX_SHADER, vert_src);
	if (!vert) {
		goto error;
	}

	GLuint frag = compile_shader(renderer, GL_FRAGMENT_SHADER, frag_src);
	if (!frag) {
		glDeleteShader(vert);
		goto error;
	}

	GLuint prog = glCreateProgram();
	glAttachShader(prog, vert);
	glAttachShader(prog, frag);
	glLinkProgram(prog);

	glDetachShader(prog, vert);
	glDetachShader(prog, frag);
	glDeleteShader(vert);
	glDeleteShader(frag);

	GLint ok;
	glGetProgramiv(prog, GL_LINK_STATUS, &ok);
	if (ok == GL_FALSE) {
		glDeleteProgram(prog);
		goto error;
	}

	pop_gles2_debug(renderer);
	return prog;

error:
	pop_gles2_debug(renderer);
	return 0;
}*/

static bool check_gl_ext(const char *exts, const char *ext) {
	size_t extlen = strlen(ext);
	const char *end = exts + strlen(exts);

	while (exts < end) {
		if (exts[0] == ' ') {
			exts++;
			continue;
		}
		size_t n = strcspn(exts, " ");
		if (n == extlen && strncmp(ext, exts, n) == 0) {
			return true;
		}
		exts += n;
	}
	return false;
}
/*
static void load_gl_proc(void *proc_ptr, const char *name) {
	void *proc = (void *)eglGetProcAddress(name);
	if (proc == NULL) {
		wlr_log(WLR_ERROR, "eglGetProcAddress(%s) failed", name);
		abort();
	}
	*(void **)proc_ptr = proc;
}*/

extern const GLchar quad_vertex_src[];
extern const GLchar quad_fragment_src[];
extern const GLchar tex_vertex_src[];
extern const GLchar tex_fragment_src_rgba[];
extern const GLchar tex_fragment_src_rgbx[];
extern const GLchar tex_fragment_src_external[];

struct wlr_renderer *wlr_gles2_renderer_create_with_drm_fd(int drm_fd) {
	struct wlr_egl *egl = wlr_egl_create_with_drm_fd(drm_fd);
	if (egl == NULL) {
		wlr_log(WLR_ERROR, "Could not initialize EGL");
		return NULL;
	}

	struct wlr_renderer *renderer = wlr_gles2_renderer_create(egl);
	if (!renderer) {
		wlr_log(WLR_ERROR, "Failed to create GLES2 renderer");
		wlr_egl_destroy(egl);
		return NULL;
	}

	return renderer;
}


bool wlr_gles2_renderer_check_ext(struct wlr_renderer *wlr_renderer,
		const char *ext) {
	struct wlr_gles2_renderer *renderer = gles2_get_renderer(wlr_renderer);
	return check_gl_ext(renderer->exts_str, ext);
}




struct wlr_renderer *wlr_gles2_renderer_create(struct wlr_egl *egl) {
    if (!eglMakeCurrent(egl->display, EGL_NO_SURFACE, EGL_NO_SURFACE, egl->context)) {
        wlr_log(WLR_ERROR, "Failed to make EGL context current");
        return NULL;
    }

    struct wlr_gles2_renderer *renderer = calloc(1, sizeof(struct wlr_gles2_renderer));
    if (renderer == NULL) {
        return NULL;
    }

    renderer->egl = egl;
    renderer->wlr_renderer.impl = &renderer_impl;
    renderer->drm_fd = -1;

    // Initialize lists and verify
    wl_list_init(&renderer->buffers);
    wl_list_init(&renderer->textures);
    
    // Verify list initialization
    if (renderer->buffers.prev == NULL || renderer->buffers.next == NULL) {
        wlr_log(WLR_ERROR, "Buffer list initialization failed");
        free(renderer);
        return NULL;
    }

    wlr_log(WLR_DEBUG, "Buffer list initialized - head: %p, prev: %p, next: %p",
        &renderer->buffers, renderer->buffers.prev, renderer->buffers.next);

    // Let Zink handle GPU acceleration naturally
    const char *driver = getenv("MESA_LOADER_DRIVER_OVERRIDE");
    if (driver && strcmp(driver, "zink") == 0) {
        wlr_log(WLR_INFO, "Using Zink (Vulkan) driver for hardware acceleration");
    }

    // Initialize basic shader programs
    renderer->shaders.quad.program = gl_shader_program_create(
        quad_vertex_src, quad_fragment_src);
    if (!renderer->shaders.quad.program) {
        free(renderer);
        return NULL;
    }

    wlr_renderer_init(&renderer->wlr_renderer, &renderer_impl);
    return &renderer->wlr_renderer;
}
/*
struct wlr_renderer *wlr_gles2_renderer_create_surfaceless(void) {
    wlr_log(WLR_INFO, "Attempting to create surfaceless GLES2 renderer");
    struct wlr_egl *egl = calloc(1, sizeof(struct wlr_egl));
    if (!egl) {
        wlr_log(WLR_ERROR, "Failed to allocate EGL structure");
        return NULL;
    }

    // Log system EGL information
    const char *egl_vendor = eglQueryString(EGL_NO_DISPLAY, EGL_VENDOR);
    const char *egl_version = eglQueryString(EGL_NO_DISPLAY, EGL_VERSION);
    wlr_log(WLR_INFO, "EGL Vendor: %s", egl_vendor ?: "Unknown");
    wlr_log(WLR_INFO, "EGL Version: %s", egl_version ?: "Unknown");

    const char *extensions = eglQueryString(EGL_NO_DISPLAY, EGL_EXTENSIONS);
    wlr_log(WLR_INFO, "Client EGL Extensions: %s", extensions ?: "NULL");

    // Explicitly check for surfaceless support
    bool has_surfaceless = strstr(extensions, "EGL_MESA_platform_surfaceless") != NULL;
    bool has_platform_base = strstr(extensions, "EGL_EXT_platform_base") != NULL;

    wlr_log(WLR_INFO, "Surfaceless platform support: %s", 
            has_surfaceless ? "YES" : "NO");
    wlr_log(WLR_INFO, "Platform base extension: %s", 
            has_platform_base ? "YES" : "NO");

    // Use platform display function if available
    PFNEGLGETPLATFORMDISPLAYEXTPROC get_platform_display = 
        (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");

    if (!get_platform_display) {
        wlr_log(WLR_ERROR, "Platform display function not available");
        free(egl);
        return NULL;
    }

    // Try creating display with surfaceless platform
    EGLDisplay display = get_platform_display(
        EGL_PLATFORM_SURFACELESS_MESA, 
        EGL_DEFAULT_DISPLAY, 
        NULL
    );

    if (display == EGL_NO_DISPLAY) {
        wlr_log(WLR_ERROR, "Failed to create surfaceless display");
        free(egl);
        return NULL;
    }

    // Initialize EGL
    EGLint major, minor;
    if (!eglInitialize(display, &major, &minor)) {
        EGLint error = eglGetError();
        wlr_log(WLR_ERROR, "EGL initialization failed. Error: 0x%x", error);
        free(egl);
        return NULL;
    }

    wlr_log(WLR_INFO, "EGL Version: %d.%d", major, minor);

    // Diagnostic: Get number of EGL configurations
    EGLint num_config_total = 0;
    eglGetConfigs(display, NULL, 0, &num_config_total);
    wlr_log(WLR_INFO, "Total EGL configurations available: %d", num_config_total);

    // Multiple configuration attempts
    const EGLint config_attempts[][20] = {
        {
            EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
            EGL_SURFACE_TYPE, EGL_PBUFFER_BIT | EGL_WINDOW_BIT | EGL_PIXMAP_BIT,
            EGL_RED_SIZE, 1,
            EGL_GREEN_SIZE, 1,
            EGL_BLUE_SIZE, 1,
            EGL_ALPHA_SIZE, EGL_DONT_CARE,
            EGL_DEPTH_SIZE, EGL_DONT_CARE,
            EGL_STENCIL_SIZE, EGL_DONT_CARE,
            EGL_NONE
        },
        {
            EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
            EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
            EGL_RED_SIZE, 1,
            EGL_GREEN_SIZE, 1,
            EGL_BLUE_SIZE, 1,
            EGL_NONE
        }
    };

    EGLConfig config = NULL;
    EGLint num_config = 0;
    EGLint error;

    // Try different configurations
    for (size_t i = 0; i < sizeof(config_attempts)/sizeof(config_attempts[0]); i++) {
        wlr_log(WLR_INFO, "Attempting EGL configuration attempt %zu", i);
        
        if (eglChooseConfig(display, config_attempts[i], &config, 1, &num_config)) {
            if (num_config > 0) {
                wlr_log(WLR_INFO, "Successfully found EGL configuration");
                break;
            }
        } else {
            error = eglGetError();
            wlr_log(WLR_ERROR, "EGL config selection failed. Error code: 0x%x", error);
        }
    }

    if (num_config == 0) {
        wlr_log(WLR_ERROR, "No compatible EGL configurations found after multiple attempts");
        eglTerminate(display);
        free(egl);
        return NULL;
    }

    // Detailed configuration diagnostics
    EGLint red_size, green_size, blue_size, alpha_size;
    eglGetConfigAttrib(display, config, EGL_RED_SIZE, &red_size);
    eglGetConfigAttrib(display, config, EGL_GREEN_SIZE, &green_size);
    eglGetConfigAttrib(display, config, EGL_BLUE_SIZE, &blue_size);
    eglGetConfigAttrib(display, config, EGL_ALPHA_SIZE, &alpha_size);

    wlr_log(WLR_INFO, "Selected EGL Config Details:");
    wlr_log(WLR_INFO, "  Red Size: %d", red_size);
    wlr_log(WLR_INFO, "  Green Size: %d", green_size);
    wlr_log(WLR_INFO, "  Blue Size: %d", blue_size);
    wlr_log(WLR_INFO, "  Alpha Size: %d", alpha_size);

    // Context creation
    EGLint ctx_attribs[] = {
        EGL_CONTEXT_CLIENT_VERSION, 2,
        EGL_NONE
    };

    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, ctx_attribs);
    
    if (context == EGL_NO_CONTEXT) {
        error = eglGetError();
        wlr_log(WLR_ERROR, "Context creation failed. Error: 0x%x", error);
        eglTerminate(display);
        free(egl);
        return NULL;
    }

    // Store in the EGL structure
    egl->display = display;
    egl->context = context;

    struct wlr_gles2_renderer *renderer = calloc(1, sizeof(struct wlr_gles2_renderer));
    if (!renderer) {
        wlr_log(WLR_ERROR, "Failed to allocate renderer");
        eglDestroyContext(display, context);
        eglTerminate(display);
        free(egl);
        return NULL;
    }

    renderer->wlr_renderer.impl = &renderer_impl;
    renderer->egl = egl;
    renderer->drm_fd = -1;

    // Check for Zink driver
    const char *driver = getenv("MESA_LOADER_DRIVER_OVERRIDE");
    if (driver && strcmp(driver, "zink") == 0) {
        wlr_log(WLR_INFO, "Using Zink (Vulkan) driver for hardware acceleration");
    }

    wlr_renderer_init(&renderer->wlr_renderer, &renderer_impl);

    return &renderer->wlr_renderer;
}*/

struct wlr_renderer *wlr_gles2_renderer_create_surfaceless(void) {
    wlr_log(WLR_INFO, "Attempting to create surfaceless GLES2 renderer");

    // Allocate wlr_egl structure
    struct wlr_egl *egl = calloc(1, sizeof(struct wlr_egl));
    if (!egl) {
        wlr_log(WLR_ERROR, "Failed to allocate EGL structure");
        return NULL;
    }

    // Log system EGL information
    const char *egl_vendor = eglQueryString(EGL_NO_DISPLAY, EGL_VENDOR);
    const char *egl_version = eglQueryString(EGL_NO_DISPLAY, EGL_VERSION);
    wlr_log(WLR_INFO, "EGL Vendor: %s", egl_vendor ? egl_vendor : "Unknown");
    wlr_log(WLR_INFO, "EGL Version: %s", egl_version ? egl_version : "Unknown");

    const char *extensions = eglQueryString(EGL_NO_DISPLAY, EGL_EXTENSIONS);
    wlr_log(WLR_INFO, "Client EGL Extensions: %s", extensions ? extensions : "NULL");

    // Check for surfaceless support
    bool has_surfaceless = strstr(extensions, "EGL_MESA_platform_surfaceless") != NULL;
    bool has_platform_base = strstr(extensions, "EGL_EXT_platform_base") != NULL;
    wlr_log(WLR_INFO, "Surfaceless platform support: %s", has_surfaceless ? "YES" : "NO");
    wlr_log(WLR_INFO, "Platform base extension: %s", has_platform_base ? "YES" : "NO");

    // Use platform display function if available
    PFNEGLGETPLATFORMDISPLAYEXTPROC get_platform_display = 
        (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");

    if (!get_platform_display) {
        wlr_log(WLR_ERROR, "Platform display function not available");
        free(egl);
        return NULL;
    }

    // Try creating display with surfaceless platform
    EGLDisplay display = get_platform_display(
        EGL_PLATFORM_SURFACELESS_MESA, 
        EGL_DEFAULT_DISPLAY, 
        NULL
    );

    if (display == EGL_NO_DISPLAY) {
        wlr_log(WLR_ERROR, "Failed to create surfaceless display");
        free(egl);
        return NULL;
    }

    // Initialize EGL
    EGLint major, minor;
    if (!eglInitialize(display, &major, &minor)) {
        wlr_log(WLR_ERROR, "EGL initialization failed. Error: 0x%x", eglGetError());
        eglTerminate(display);
        free(egl);
        return NULL;
    }
    wlr_log(WLR_INFO, "EGL initialized, version: %d.%d", major, minor);

    // Diagnostic: Get number of EGL configurations
    EGLint num_config_total = 0;
    eglGetConfigs(display, NULL, 0, &num_config_total);
    wlr_log(WLR_INFO, "Available EGL configurations: %d", num_config_total);

    // Multiple configuration attempts
    const EGLint config_attempts[][20] = {
        {
            EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
            EGL_SURFACE_TYPE, EGL_PBUFFER_BIT | EGL_WINDOW_BIT | EGL_PIXMAP_BIT,
            EGL_RED_SIZE, 1,
            EGL_GREEN_SIZE, 1,
            EGL_BLUE_SIZE, 1,
            EGL_ALPHA_SIZE, EGL_DONT_CARE,
            EGL_DEPTH_SIZE, EGL_DONT_CARE,
            EGL_STENCIL_SIZE, EGL_DONT_CARE,
            EGL_NONE
        },
        {
            EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
            EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
            EGL_RED_SIZE, 1,
            EGL_GREEN_SIZE, 1,
            EGL_BLUE_SIZE, 1,
            EGL_NONE
        }
    };

    EGLConfig config = NULL;
    EGLint num_config = 0;

    // Try different configurations
    for (size_t i = 0; i < sizeof(config_attempts) / sizeof(config_attempts[0]); i++) {
        wlr_log(WLR_INFO, "Attempting EGL configuration attempt %zu", i);
        
        if (eglChooseConfig(display, config_attempts[i], &config, 1, &num_config)) {
            if (num_config > 0) {
                wlr_log(WLR_INFO, "Successfully found EGL configuration");
                break;
            }
        } else {
            wlr_log(WLR_ERROR, "EGL config selection failed. Error code: 0x%x", eglGetError());
        }
    }

    if (num_config == 0) {
        wlr_log(WLR_ERROR, "No matching EGL configurations found after multiple attempts");
        eglTerminate(display);
        free(egl);
        return NULL;
    }

    // Detailed configuration diagnostics
    EGLint red_size, green_size, blue_size, alpha_size;
    eglGetConfigAttrib(display, config, EGL_RED_SIZE, &red_size);
    eglGetConfigAttrib(display, config, EGL_GREEN_SIZE, &green_size);
    eglGetConfigAttrib(display, config, EGL_BLUE_SIZE, &blue_size);
    eglGetConfigAttrib(display, config, EGL_ALPHA_SIZE, &alpha_size);
    wlr_log(WLR_INFO, "Selected EGL Config Details:");
    wlr_log(WLR_INFO, "  Red Size: %d", red_size);
    wlr_log(WLR_INFO, "  Green Size: %d", green_size);
    wlr_log(WLR_INFO, "  Blue Size: %d", blue_size);
    wlr_log(WLR_INFO, "  Alpha Size: %d", alpha_size);

    // Context creation
    EGLint ctx_attribs[] = {
        EGL_CONTEXT_CLIENT_VERSION, 2,
        EGL_NONE
    };

    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, ctx_attribs);
    if (context == EGL_NO_CONTEXT) {
        wlr_log(WLR_ERROR, "Context creation failed. Error: 0x%x", eglGetError());
        eglTerminate(display);
        free(egl);
        return NULL;
    }

    // Store in the EGL structure
    egl->display = display;
    egl->context = context;

    struct wlr_gles2_renderer *renderer = calloc(1, sizeof(struct wlr_gles2_renderer));
    if (!renderer) {
        wlr_log(WLR_ERROR, "Failed to allocate renderer");
        eglDestroyContext(display, context);
        eglTerminate(display);
        free(egl);
        return NULL;
    }

    renderer->wlr_renderer.impl = &renderer_impl;
    renderer->egl = egl;
    renderer->drm_fd = -1;

    // Check for Zink driver
    const char *driver = getenv("MESA_LOADER_DRIVER_OVERRIDE");
    if (driver && strcmp(driver, "zink") == 0) {
        wlr_log(WLR_INFO, "Using Zink (Vulkan) driver for hardware acceleration");
    }

    wlr_renderer_init(&renderer->wlr_renderer, &renderer_impl);

    return &renderer->wlr_renderer;
}