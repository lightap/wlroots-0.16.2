#include <assert.h>
#include <drm_fourcc.h>
#include <stdlib.h>
#include <wlr/interfaces/wlr_output.h>
#include <wlr/render/interface.h>
#include <wlr/util/log.h>
#include <xf86drm.h>
#include "backend/backend.h"
#include "render/allocator/allocator.h"
#include "render/drm_format_set.h"
#include "render/swapchain.h"
#include "render/wlr_renderer.h"
#include "render/pixel_format.h"
#include "types/wlr_output.h"
#include <unistd.h>

bool wlr_output_init_render(struct wlr_output *output,
		struct wlr_allocator *allocator, struct wlr_renderer *renderer) {
	assert(output->allocator == NULL && allocator != NULL);
	assert(output->renderer == NULL && renderer != NULL);

	uint32_t backend_caps = backend_get_buffer_caps(output->backend);
	uint32_t renderer_caps = renderer_get_render_buffer_caps(renderer);

	if (!(backend_caps & allocator->buffer_caps)) {
		wlr_log(WLR_ERROR, "output backend and allocator buffer capabilities "
			"don't match");
		return false;
	} else if (!(renderer_caps & allocator->buffer_caps)) {
		wlr_log(WLR_ERROR, "renderer and allocator buffer capabilities "
			"don't match");
		return false;
	}

	output->allocator = allocator;
	output->renderer = renderer;

	return true;
}

/**
 * Ensure the output has a suitable swapchain. The swapchain is re-created if
 * necessary.
 *
 * If allow_modifiers is set to true, the swapchain's format may use modifiers.
 * If set to false, the swapchain's format is guaranteed to not use modifiers.
 */
/*
static bool output_create_swapchain(struct wlr_output *output,
		const struct wlr_output_state *state, bool allow_modifiers) {
	int width, height;
	output_pending_resolution(output, state, &width, &height);

	struct wlr_allocator *allocator = output->allocator;
	assert(allocator != NULL);

	const struct wlr_drm_format_set *display_formats =
		wlr_output_get_primary_formats(output, allocator->buffer_caps);
	struct wlr_drm_format *format = output_pick_format(output, display_formats,
		output->render_format);
	if (format == NULL) {
		wlr_log(WLR_ERROR, "Failed to pick primary buffer format for output '%s'",
			output->name);
		return false;
	}

	if (output->swapchain != NULL && output->swapchain->width == width &&
			output->swapchain->height == height &&
			output->swapchain->format->format == format->format &&
			(allow_modifiers || output->swapchain->format->len == 0)) {
		// no change, keep existing swapchain
		free(format);
		return true;
	}

	char *format_name = drmGetFormatName(format->format);
	wlr_log(WLR_DEBUG, "Choosing primary buffer format %s (0x%08"PRIX32") for output '%s'",
		format_name ? format_name : "<unknown>", format->format, output->name);
	free(format_name);

	if (!allow_modifiers && (format->len != 1 || format->modifiers[0] != DRM_FORMAT_MOD_LINEAR)) {
		if (!wlr_drm_format_has(format, DRM_FORMAT_MOD_INVALID)) {
			wlr_log(WLR_DEBUG, "Implicit modifiers not supported");
			free(format);
			return false;
		}

		format->len = 0;
		wlr_drm_format_add(&format, DRM_FORMAT_MOD_INVALID);
	}

	struct wlr_swapchain *swapchain =
		wlr_swapchain_create(allocator, width, height, format);
	free(format);
	if (swapchain == NULL) {
		wlr_log(WLR_ERROR, "Failed to create output swapchain");
		return false;
	}

	wlr_swapchain_destroy(output->swapchain);
	output->swapchain = swapchain;

	return true;
}*/



static bool output_create_swapchain(struct wlr_output *output,
        const struct wlr_output_state *state, bool allow_modifiers) {
    int width, height;
    output_pending_resolution(output, state, &width, &height);

    struct wlr_allocator *allocator = output->allocator;
    assert(allocator != NULL);

    // For surfaceless, create a format explicitly
    struct wlr_drm_format *format = calloc(1, sizeof(struct wlr_drm_format) + sizeof(uint64_t));
    if (!format) {
        wlr_log(WLR_ERROR, "Failed to allocate format for surfaceless swapchain");
        return false;
    }

    // Use the RDP allocator's preferred format
    format->format = DRM_FORMAT_XRGB8888;
    format->modifiers[0] = DRM_FORMAT_MOD_INVALID;
    format->len = 1;
    format->capacity = 1;

    struct wlr_swapchain *swapchain =
        wlr_swapchain_create(allocator, width, height, format);
    
    free(format);

    if (swapchain == NULL) {
        wlr_log(WLR_ERROR, "Failed to create output swapchain in surfaceless mode");
        return false;
    }

    wlr_swapchain_destroy(output->swapchain);
    output->swapchain = swapchain;

    return true;
}


static bool output_attach_back_buffer(struct wlr_output *output,
        const struct wlr_output_state *state, int *buffer_age) {
    assert(output->back_buffer == NULL);

    wlr_log(WLR_DEBUG, "Surfaceless: Attempting to attach back buffer");

    // Verify critical components
    if (!output->allocator) {
        wlr_log(WLR_ERROR, "Surfaceless: No allocator available");
        return false;
    }

    struct wlr_renderer *renderer = output->renderer;
    if (!renderer) {
        wlr_log(WLR_ERROR, "Surfaceless: No renderer available");
        return false;
    }

    // Create swapchain with surfaceless-specific handling
    if (!output_create_swapchain(output, state, true)) {
        wlr_log(WLR_ERROR, "Surfaceless: Failed to create swapchain");
        return false;
    }

    // Verify swapchain
    if (!output->swapchain) {
        wlr_log(WLR_ERROR, "Surfaceless: Swapchain creation failed");
        return false;
    }

    // Acquire buffer from swapchain
    struct wlr_buffer *buffer = 
        wlr_swapchain_acquire(output->swapchain, buffer_age);
    if (!buffer) {
        wlr_log(WLR_ERROR, "Surfaceless: Failed to acquire swapchain buffer");
        return false;
    }

    // Lock the buffer before use
    wlr_buffer_lock(buffer);

    // Attempt renderer-specific buffer binding
    if (!renderer_bind_buffer(renderer, buffer)) {
        wlr_log(WLR_ERROR, "Surfaceless: Renderer-specific buffer binding failed");
        wlr_buffer_unlock(buffer);
        return false;
    }

    output->back_buffer = buffer;
    wlr_log(WLR_DEBUG, "Surfaceless: Successfully attached back buffer");
    return true;
}
/*
void output_clear_back_buffer(struct wlr_output *output) {
	if (output->back_buffer == NULL) {
		return;
	}

	struct wlr_renderer *renderer = output->renderer;
	assert(renderer != NULL);

	renderer_bind_buffer(renderer, NULL);

	wlr_buffer_unlock(output->back_buffer);
	output->back_buffer = NULL;
}*/


void output_clear_back_buffer(struct wlr_output *output) {
    if (output->back_buffer == NULL) {
        return;
    }

    struct wlr_renderer *renderer = output->renderer;
    assert(renderer != NULL);

    // Unbind the buffer from the renderer
    renderer_bind_buffer(renderer, NULL);

    // Unlock the buffer
    wlr_buffer_unlock(output->back_buffer);
    output->back_buffer = NULL;
}

bool wlr_output_attach_render(struct wlr_output *output, int *buffer_age) {
	return output_attach_back_buffer(output, &output->pending, buffer_age);
}
static bool output_attach_empty_back_buffer(struct wlr_output *output,
        const struct wlr_output_state *state) {
    assert(!(state->committed & WLR_OUTPUT_STATE_BUFFER));

    // In surfaceless mode, be more lenient
    if (!output_attach_back_buffer(output, state, NULL)) {
        wlr_log(WLR_ERROR, "Surfaceless: Failed to attach back buffer");
        return false;
    }

    // Sanity check the back buffer
    if (output->back_buffer == NULL) {
        wlr_log(WLR_ERROR, "Surfaceless: Back buffer is NULL after attachment");
        return false;
    }

    int width, height;
    output_pending_resolution(output, state, &width, &height);

    struct wlr_renderer *renderer = output->renderer;
    if (!renderer) {
        wlr_log(WLR_ERROR, "Surfaceless: No renderer available");
        return false;
    }

    // Try to bind the buffer to the renderer
    if (!renderer_bind_buffer(renderer, output->back_buffer)) {
        wlr_log(WLR_ERROR, "Surfaceless: Failed to bind buffer to renderer");
        return false;
    }

    // Perform basic clear operation
    wlr_renderer_begin(renderer, width, height);
    
    // Clear to a neutral color (black with full alpha)
    float clear_color[4] = {0.0f, 0.0f, 0.0f, 1.0f};
    wlr_renderer_clear(renderer, clear_color);
    
    wlr_renderer_end(renderer);

    wlr_log(WLR_DEBUG, "Surfaceless: Successfully attached and initialized back buffer");
    return true;
}
/*
static bool output_attach_empty_back_buffer(struct wlr_output *output,
		const struct wlr_output_state *state) {
	assert(!(state->committed & WLR_OUTPUT_STATE_BUFFER));

	if (!output_attach_back_buffer(output, state, NULL)) {
		return false;
	}

	int width, height;
	output_pending_resolution(output, state, &width, &height);

	struct wlr_renderer *renderer = output->renderer;
	wlr_renderer_begin(renderer, width, height);
	wlr_renderer_clear(renderer, (float[]){0, 0, 0, 0});
	wlr_renderer_end(renderer);

	return true;
}*/
/*
static bool output_test_with_back_buffer(struct wlr_output *output,
		const struct wlr_output_state *state) {
	if (output->impl->test == NULL) {
		return true;
	}

	// Create a shallow copy of the state with the empty back buffer included
	// to pass to the backend.
	struct wlr_output_state copy = *state;
	assert((copy.committed & WLR_OUTPUT_STATE_BUFFER) == 0);
	copy.committed |= WLR_OUTPUT_STATE_BUFFER;
	assert(output->back_buffer != NULL);
	copy.buffer = output->back_buffer;

	return output->impl->test(output, &copy);
}*/

// This function may attach a new, empty back buffer if necessary.
// If so, the new_back_buffer out parameter will be set to true.
/*
bool output_ensure_buffer(struct wlr_output *output,
        const struct wlr_output_state *state,
        bool *new_back_buffer) {
    assert(*new_back_buffer == false);

    // If we already have a buffer, we don't need to allocate a new one
    if (state->committed & WLR_OUTPUT_STATE_BUFFER) {
        return true;
    }

    // If the compositor hasn't called wlr_output_init_render(), they will use
    // their own logic to attach buffers
    if (output->renderer == NULL) {
        return true;
    }

    bool enabled = output->enabled;
    if (state->committed & WLR_OUTPUT_STATE_ENABLED) {
        enabled = state->enabled;
    }

    // Determine if we need a new buffer
    bool needs_new_buffer = false;
    if ((state->committed & WLR_OUTPUT_STATE_ENABLED) && state->enabled) {
        needs_new_buffer = true;
    }
    if (state->committed & WLR_OUTPUT_STATE_MODE) {
        needs_new_buffer = true;
    }
    if (state->committed & WLR_OUTPUT_STATE_RENDER_FORMAT) {
        needs_new_buffer = true;
    }
    if (state->allow_artifacts && output->commit_seq == 0 && enabled) {
        // On first commit, require a new buffer if the compositor called a
        // mode-setting function, even if the mode won't change
        needs_new_buffer = true;
    }

    // For surfaceless mode, be more lenient
    if (output->swapchain == NULL || 
        (output->swapchain->format && output->swapchain->format->len == 0)) {
        wlr_log(WLR_DEBUG, "Surfaceless mode: Forcing new buffer creation");
        needs_new_buffer = true;
    }

    if (!needs_new_buffer) {
        return true;
    }

    wlr_log(WLR_DEBUG, "Attaching empty buffer to output for modeset");

    if (!output_attach_empty_back_buffer(output, state)) {
        return false;
    }

    if (output_test_with_back_buffer(output, state)) {
        *new_back_buffer = true;
        return true;
    }

    output_clear_back_buffer(output);

    // For surfaceless mode, this check might be too restrictive
    if (output->swapchain->format->len == 0) {
        // In surfaceless mode, we might want to proceed anyway
        wlr_log(WLR_DEBUG, "Surfaceless mode: Proceeding with zero-length format");
        *new_back_buffer = true;
        return true;
    }

    // The test failed for a buffer which has modifiers, try disabling
    // modifiers to see if that makes a difference
    wlr_log(WLR_DEBUG, "Output modeset test failed, retrying without modifiers");

    if (!output_create_swapchain(output, state, false)) {
        return false;
    }

    if (!output_attach_empty_back_buffer(output, state)) {
        goto error_destroy_swapchain;
    }

    if (output_test_with_back_buffer(output, state)) {
        *new_back_buffer = true;
        return true;
    }

    output_clear_back_buffer(output);

error_destroy_swapchain:
    // Destroy the modifierless swapchain so that the output does not get stuck
    // without modifiers. A new swapchain with modifiers will be created when
    // needed by output_attach_back_buffer().
    wlr_swapchain_destroy(output->swapchain);
    output->swapchain = NULL;

    return false;
}*/


bool output_ensure_buffer(struct wlr_output *output,
        const struct wlr_output_state *state,
        bool *new_back_buffer) {
    wlr_log(WLR_DEBUG, "Surfaceless: Forcing buffer creation with extensive surfaceless handling");
    
    // Always treat this as creating a new back buffer
    *new_back_buffer = true;

    // In surfaceless mode, we want to be extremely flexible
    wlr_output_set_render_format(output, DRM_FORMAT_XRGB8888);

    // Attempt to attach buffer multiple times with increasing flexibility
    for (int attempt = 0; attempt < 3; attempt++) {
        wlr_log(WLR_DEBUG, "Surfaceless: Buffer attachment attempt %d", attempt);

        // Try attaching empty back buffer
        if (output_attach_empty_back_buffer(output, state)) {
            wlr_log(WLR_DEBUG, "Surfaceless: Successfully attached empty back buffer");
            return true;
        }

        // If standard attachment fails, try alternative methods
        if (attempt > 0) {
            // Create a DRM format explicitly
            struct wlr_drm_format *format = calloc(1, sizeof(struct wlr_drm_format) + sizeof(uint64_t));
            if (!format) {
                wlr_log(WLR_ERROR, "Surfaceless: Failed to allocate format");
                continue;
            }

            format->format = DRM_FORMAT_XRGB8888;
            format->modifiers[0] = DRM_FORMAT_MOD_INVALID;
            format->len = 1;
            format->capacity = 1;

            // Ensure width and height are sane
            int width = output->swapchain ? output->swapchain->width : 1280;
            int height = output->swapchain ? output->swapchain->height : 720;

            struct wlr_buffer *manual_buffer = 
                wlr_allocator_create_buffer(output->allocator, 
                                            width, 
                                            height, 
                                            format);
            
            free(format);

            if (manual_buffer) {
                // Only lock if manual_buffer is valid
                wlr_buffer_lock(manual_buffer);
                
                // Clear any existing back buffer first, ensuring it's properly unlocked
                if (output->back_buffer) {
                    wlr_buffer_unlock(output->back_buffer);
                    output->back_buffer = NULL;
                }

                output->back_buffer = manual_buffer;
                wlr_log(WLR_DEBUG, "Surfaceless: Manually created buffer");
                return true;
            }
        }
    }

    wlr_log(WLR_ERROR, "Surfaceless: Failed to attach buffer after multiple attempts");
    return false;
}
void wlr_output_lock_attach_render(struct wlr_output *output, bool lock) {
	if (lock) {
		++output->attach_render_locks;
	} else {
		assert(output->attach_render_locks > 0);
		--output->attach_render_locks;
	}
	wlr_log(WLR_DEBUG, "%s direct scan-out on output '%s' (locks: %d)",
		lock ? "Disabling" : "Enabling", output->name,
		output->attach_render_locks);
}
/*
struct wlr_drm_format *output_pick_format(struct wlr_output *output,
		const struct wlr_drm_format_set *display_formats,
		uint32_t fmt) {
	struct wlr_renderer *renderer = output->renderer;
	struct wlr_allocator *allocator = output->allocator;
	assert(renderer != NULL && allocator != NULL);

	const struct wlr_drm_format_set *render_formats =
		wlr_renderer_get_render_formats(renderer);
	if (render_formats == NULL) {
		wlr_log(WLR_ERROR, "Failed to get render formats");
		return NULL;
	}

	const struct wlr_drm_format *render_format =
		wlr_drm_format_set_get(render_formats, fmt);
	if (render_format == NULL) {
		wlr_log(WLR_DEBUG, "Renderer doesn't support format 0x%"PRIX32, fmt);
		return NULL;
	}

	struct wlr_drm_format *format = NULL;
	if (display_formats != NULL) {
		const struct wlr_drm_format *display_format =
			wlr_drm_format_set_get(display_formats, fmt);
		if (display_format == NULL) {
			wlr_log(WLR_DEBUG, "Output doesn't support format 0x%"PRIX32, fmt);
			return NULL;
		}
		format = wlr_drm_format_intersect(display_format, render_format);
	} else {
		// The output can display any format
		format = wlr_drm_format_dup(render_format);
	}

	if (format == NULL) {
		wlr_log(WLR_DEBUG, "Failed to intersect display and render "
			"modifiers for format 0x%"PRIX32 " on output %s",
			fmt, output->name);
		return NULL;
	}

	return format;
}*/


struct wlr_drm_format *output_pick_format(struct wlr_output *output,
        const struct wlr_drm_format_set *display_formats,
        uint32_t fmt) {
    struct wlr_renderer *renderer = output->renderer;
    struct wlr_allocator *allocator = output->allocator;
    assert(renderer != NULL && allocator != NULL);

    wlr_log(WLR_DEBUG, "Surfaceless format selection: Creating minimal format");

    // Hardcode a format that matches the EGL config (8-bit RGB, no alpha)
    struct wlr_drm_format *format = calloc(1, sizeof(struct wlr_drm_format) + sizeof(uint64_t));
    if (!format) {
        wlr_log(WLR_ERROR, "Failed to allocate drm format");
        return NULL;
    }

    // Use the format that matches the allocator's request
    format->format = DRM_FORMAT_XRGB8888;  // 0x34325258
    format->modifiers[0] = DRM_FORMAT_MOD_INVALID;
    format->len = 1;
    format->capacity = 1;

    wlr_log(WLR_DEBUG, "Surfaceless: Created format 0x%"PRIX32, format->format);
    return format;
}

uint32_t wlr_output_preferred_read_format(struct wlr_output *output) {
	struct wlr_renderer *renderer = output->renderer;
	assert(renderer != NULL);

	if (!renderer->impl->preferred_read_format || !renderer->impl->read_pixels) {
		return DRM_FORMAT_INVALID;
	}

	if (!output_attach_back_buffer(output, &output->pending, NULL)) {
		return false;
	}

	uint32_t fmt = renderer->impl->preferred_read_format(renderer);

	output_clear_back_buffer(output);

	return fmt;
}

bool output_is_direct_scanout(struct wlr_output *output,
		struct wlr_buffer *buffer) {
	if (output->swapchain == NULL) {
		return true;
	}

	for (size_t i = 0; i < WLR_SWAPCHAIN_CAP; i++) {
		if (output->swapchain->slots[i].buffer == buffer) {
			return false;
		}
	}

	return true;
}
