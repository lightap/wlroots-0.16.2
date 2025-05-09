#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <backend/backend.h>
#include <drm_fourcc.h>
#include <stdlib.h>
#include <wlr/interfaces/wlr_output.h>
#include <wlr/types/wlr_compositor.h>
#include <wlr/types/wlr_matrix.h>
#include <wlr/util/log.h>
#include "render/allocator/allocator.h"
#include "render/swapchain.h"
#include "types/wlr_output.h"
#include "util/env.h"
#include "util/global.h"

#define OUTPUT_VERSION 4

static void send_geometry(struct wl_resource *resource) {
	struct wlr_output *output = wlr_output_from_resource(resource);

	const char *make = output->make;
	if (make == NULL) {
		make = "Unknown";
	}

	const char *model = output->model;
	if (model == NULL) {
		model = "Unknown";
	}

	wl_output_send_geometry(resource, 0, 0,
		output->phys_width, output->phys_height, output->subpixel,
		make, model, output->transform);
}

static void send_current_mode(struct wl_resource *resource) {
	struct wlr_output *output = wlr_output_from_resource(resource);
	if (output->current_mode != NULL) {
		struct wlr_output_mode *mode = output->current_mode;
		wl_output_send_mode(resource, WL_OUTPUT_MODE_CURRENT,
			mode->width, mode->height, mode->refresh);
	} else {
		// Output has no mode
		wl_output_send_mode(resource, WL_OUTPUT_MODE_CURRENT, output->width,
			output->height, output->refresh);
	}
}

static void send_scale(struct wl_resource *resource) {
	struct wlr_output *output = wlr_output_from_resource(resource);
	uint32_t version = wl_resource_get_version(resource);
	if (version >= WL_OUTPUT_SCALE_SINCE_VERSION) {
		wl_output_send_scale(resource, (uint32_t)ceil(output->scale));
	}
}

static void send_name(struct wl_resource *resource) {
	struct wlr_output *output = wlr_output_from_resource(resource);
	uint32_t version = wl_resource_get_version(resource);
	if (version >= WL_OUTPUT_NAME_SINCE_VERSION) {
		wl_output_send_name(resource, output->name);
	}
}

static void send_description(struct wl_resource *resource) {
	struct wlr_output *output = wlr_output_from_resource(resource);
	uint32_t version = wl_resource_get_version(resource);
	if (output->description != NULL &&
			version >= WL_OUTPUT_DESCRIPTION_SINCE_VERSION) {
		wl_output_send_description(resource, output->description);
	}
}

static void send_done(struct wl_resource *resource) {
	uint32_t version = wl_resource_get_version(resource);
	if (version >= WL_OUTPUT_DONE_SINCE_VERSION) {
		wl_output_send_done(resource);
	}
}

static void output_handle_resource_destroy(struct wl_resource *resource) {
	wl_list_remove(wl_resource_get_link(resource));
}

static void output_handle_release(struct wl_client *client,
		struct wl_resource *resource) {
	wl_resource_destroy(resource);
}

static const struct wl_output_interface output_impl = {
	.release = output_handle_release,
};

static void output_bind(struct wl_client *wl_client, void *data,
		uint32_t version, uint32_t id) {
	// `output` can be NULL if the output global is being destroyed
	struct wlr_output *output = data;

	struct wl_resource *resource = wl_resource_create(wl_client,
		&wl_output_interface, version, id);
	if (resource == NULL) {
		wl_client_post_no_memory(wl_client);
		return;
	}
	wl_resource_set_implementation(resource, &output_impl, output,
		output_handle_resource_destroy);

	if (output == NULL) {
		wl_list_init(wl_resource_get_link(resource));
		return;
	}

	wl_list_insert(&output->resources, wl_resource_get_link(resource));

	send_geometry(resource);
	send_current_mode(resource);
	send_scale(resource);
	send_name(resource);
	send_description(resource);
	send_done(resource);

	struct wlr_output_event_bind evt = {
		.output = output,
		.resource = resource,
	};

	wl_signal_emit_mutable(&output->events.bind, &evt);
}

void wlr_output_create_global(struct wlr_output *output) {
	if (output->global != NULL) {
		return;
	}
	output->global = wl_global_create(output->display,
		&wl_output_interface, OUTPUT_VERSION, output, output_bind);
	if (output->global == NULL) {
		wlr_log(WLR_ERROR, "Failed to allocate wl_output global");
	}
}

void wlr_output_destroy_global(struct wlr_output *output) {
	if (output->global == NULL) {
		return;
	}

	// Make all output resources inert
	struct wl_resource *resource, *tmp;
	wl_resource_for_each_safe(resource, tmp, &output->resources) {
		wl_resource_set_user_data(resource, NULL);
		wl_list_remove(wl_resource_get_link(resource));
		wl_list_init(wl_resource_get_link(resource));
	}

	wlr_global_destroy_safe(output->global);
	output->global = NULL;
}

static void schedule_done_handle_idle_timer(void *data) {
	struct wlr_output *output = data;
	output->idle_done = NULL;

	struct wl_resource *resource;
	wl_resource_for_each(resource, &output->resources) {
		send_done(resource);
	}
}

void wlr_output_schedule_done(struct wlr_output *output) {
	if (output->idle_done != NULL) {
		return; // Already scheduled
	}

	struct wl_event_loop *ev = wl_display_get_event_loop(output->display);
	output->idle_done =
		wl_event_loop_add_idle(ev, schedule_done_handle_idle_timer, output);
}

struct wlr_output *wlr_output_from_resource(struct wl_resource *resource) {
	assert(wl_resource_instance_of(resource, &wl_output_interface,
		&output_impl));
	return wl_resource_get_user_data(resource);
}

void wlr_output_update_enabled(struct wlr_output *output, bool enabled) {
	if (output->enabled == enabled) {
		return;
	}

	output->enabled = enabled;
	wl_signal_emit_mutable(&output->events.enable, output);
}

static void output_update_matrix(struct wlr_output *output) {
	wlr_matrix_identity(output->transform_matrix);
	if (output->transform != WL_OUTPUT_TRANSFORM_NORMAL) {
		int tr_width, tr_height;
		wlr_output_transformed_resolution(output, &tr_width, &tr_height);

		wlr_matrix_translate(output->transform_matrix,
			output->width / 2.0, output->height / 2.0);
		wlr_matrix_transform(output->transform_matrix, output->transform);
		wlr_matrix_translate(output->transform_matrix,
			- tr_width / 2.0, - tr_height / 2.0);
	}
}

void wlr_output_enable(struct wlr_output *output, bool enable) {
	wlr_output_state_set_enabled(&output->pending, enable);
}

void wlr_output_set_mode(struct wlr_output *output,
		struct wlr_output_mode *mode) {
	wlr_output_state_set_mode(&output->pending, mode);
}

void wlr_output_set_custom_mode(struct wlr_output *output, int32_t width,
		int32_t height, int32_t refresh) {
	// If there is a fixed mode which matches what the user wants, use that
	struct wlr_output_mode *mode;
	wl_list_for_each(mode, &output->modes, link) {
		if (mode->width == width && mode->height == height &&
				mode->refresh == refresh) {
			wlr_output_set_mode(output, mode);
			return;
		}
	}

	wlr_output_state_set_custom_mode(&output->pending, width, height, refresh);
}

void wlr_output_update_mode(struct wlr_output *output,
		struct wlr_output_mode *mode) {
	output->current_mode = mode;
	if (mode != NULL) {
		wlr_output_update_custom_mode(output, mode->width, mode->height,
			mode->refresh);
	} else {
		wlr_output_update_custom_mode(output, 0, 0, 0);
	}
}

void wlr_output_update_custom_mode(struct wlr_output *output, int32_t width,
		int32_t height, int32_t refresh) {
	if (output->width == width && output->height == height &&
			output->refresh == refresh) {
		return;
	}

	output->width = width;
	output->height = height;
	output_update_matrix(output);

	output->refresh = refresh;

	if (output->swapchain != NULL &&
			(output->swapchain->width != output->width ||
			output->swapchain->height != output->height)) {
		wlr_swapchain_destroy(output->swapchain);
		output->swapchain = NULL;
	}

	struct wl_resource *resource;
	wl_resource_for_each(resource, &output->resources) {
		send_current_mode(resource);
	}
	wlr_output_schedule_done(output);

	wl_signal_emit_mutable(&output->events.mode, output);
}

void wlr_output_set_transform(struct wlr_output *output,
		enum wl_output_transform transform) {
	wlr_output_state_set_transform(&output->pending, transform);
}

void wlr_output_set_scale(struct wlr_output *output, float scale) {
	wlr_output_state_set_scale(&output->pending, scale);
}

void wlr_output_enable_adaptive_sync(struct wlr_output *output, bool enabled) {
	wlr_output_state_set_adaptive_sync_enabled(&output->pending, enabled);
}

void wlr_output_set_render_format(struct wlr_output *output, uint32_t format) {
	wlr_output_state_set_render_format(&output->pending, format);
}

void wlr_output_set_subpixel(struct wlr_output *output,
		enum wl_output_subpixel subpixel) {
	wlr_output_state_set_subpixel(&output->pending, subpixel);
}

void wlr_output_set_name(struct wlr_output *output, const char *name) {
	assert(output->global == NULL);

	free(output->name);
	output->name = strdup(name);
}

void wlr_output_set_description(struct wlr_output *output, const char *desc) {
	if (output->description != NULL && desc != NULL &&
			strcmp(output->description, desc) == 0) {
		return;
	}

	free(output->description);
	if (desc != NULL) {
		output->description = strdup(desc);
	} else {
		output->description = NULL;
	}

	struct wl_resource *resource;
	wl_resource_for_each(resource, &output->resources) {
		send_description(resource);
	}
	wlr_output_schedule_done(output);

	wl_signal_emit_mutable(&output->events.description, output);
}

static void handle_display_destroy(struct wl_listener *listener, void *data) {
	struct wlr_output *output =
		wl_container_of(listener, output, display_destroy);
	wlr_output_destroy_global(output);
}

static void output_state_init(struct wlr_output_state *state) {
	memset(state, 0, sizeof(*state));
	pixman_region32_init(&state->damage);
}

static void output_state_finish(struct wlr_output_state *state) {
	wlr_buffer_unlock(state->buffer);
	// struct wlr_buffer is ref'counted, so the pointer may remain valid after
	// wlr_buffer_unlock(). Reset the field to NULL to ensure nobody mistakenly
	// reads it after output_state_finish().
	state->buffer = NULL;
	pixman_region32_fini(&state->damage);
	free(state->gamma_lut);
}

static void output_state_move(struct wlr_output_state *dst,
		struct wlr_output_state *src) {
	*dst = *src;
	output_state_init(src);
}

void wlr_output_init(struct wlr_output *output, struct wlr_backend *backend,
		const struct wlr_output_impl *impl, struct wl_display *display) {
	assert(impl->commit);
	if (impl->set_cursor || impl->move_cursor) {
		assert(impl->set_cursor && impl->move_cursor);
	}

	memset(output, 0, sizeof(*output));
	output->backend = backend;
	output->impl = impl;
	output->display = display;
	wl_list_init(&output->modes);
	output->render_format = DRM_FORMAT_XRGB8888;
	output->transform = WL_OUTPUT_TRANSFORM_NORMAL;
	output->scale = 1;
	output->commit_seq = 0;
	wl_list_init(&output->cursors);
	wl_list_init(&output->resources);
	wl_signal_init(&output->events.frame);
	wl_signal_init(&output->events.damage);
	wl_signal_init(&output->events.needs_frame);
	wl_signal_init(&output->events.precommit);
	wl_signal_init(&output->events.commit);
	wl_signal_init(&output->events.present);
	wl_signal_init(&output->events.bind);
	wl_signal_init(&output->events.enable);
	wl_signal_init(&output->events.mode);
	wl_signal_init(&output->events.description);
	wl_signal_init(&output->events.destroy);
	output_state_init(&output->pending);

	output->software_cursor_locks = env_parse_bool("WLR_NO_HARDWARE_CURSORS");
	if (output->software_cursor_locks) {
		wlr_log(WLR_DEBUG, "WLR_NO_HARDWARE_CURSORS set, forcing software cursors");
	}

	wlr_addon_set_init(&output->addons);

	output->display_destroy.notify = handle_display_destroy;
	wl_display_add_destroy_listener(display, &output->display_destroy);
}

void wlr_output_destroy(struct wlr_output *output) {
	if (!output) {
		return;
	}

	wl_list_remove(&output->display_destroy.link);
	wlr_output_destroy_global(output);
	output_clear_back_buffer(output);

	wl_signal_emit_mutable(&output->events.destroy, output);
	wlr_addon_set_finish(&output->addons);

	// The backend is responsible for free-ing the list of modes

	struct wlr_output_cursor *cursor, *tmp_cursor;
	wl_list_for_each_safe(cursor, tmp_cursor, &output->cursors, link) {
		wlr_output_cursor_destroy(cursor);
	}

	wlr_swapchain_destroy(output->cursor_swapchain);
	wlr_buffer_unlock(output->cursor_front_buffer);

	wlr_swapchain_destroy(output->swapchain);

	if (output->idle_frame != NULL) {
		wl_event_source_remove(output->idle_frame);
	}

	if (output->idle_done != NULL) {
		wl_event_source_remove(output->idle_done);
	}

	free(output->name);
	free(output->description);
	free(output->make);
	free(output->model);
	free(output->serial);

	output_state_finish(&output->pending);

	if (output->impl && output->impl->destroy) {
		output->impl->destroy(output);
	} else {
		free(output);
	}
}

void wlr_output_transformed_resolution(struct wlr_output *output,
		int *width, int *height) {
	if (output->transform % 2 == 0) {
		*width = output->width;
		*height = output->height;
	} else {
		*width = output->height;
		*height = output->width;
	}
}

void wlr_output_effective_resolution(struct wlr_output *output,
		int *width, int *height) {
	wlr_output_transformed_resolution(output, width, height);
	*width /= output->scale;
	*height /= output->scale;
}

struct wlr_output_mode *wlr_output_preferred_mode(struct wlr_output *output) {
	if (wl_list_empty(&output->modes)) {
		return NULL;
	}

	struct wlr_output_mode *mode;
	wl_list_for_each(mode, &output->modes, link) {
		if (mode->preferred) {
			return mode;
		}
	}

	// No preferred mode, choose the first one
	return wl_container_of(output->modes.next, mode, link);
}

static void output_state_clear_buffer(struct wlr_output_state *state) {
	if (!(state->committed & WLR_OUTPUT_STATE_BUFFER)) {
		return;
	}

	wlr_buffer_unlock(state->buffer);
	state->buffer = NULL;

	state->committed &= ~WLR_OUTPUT_STATE_BUFFER;
}

void wlr_output_set_damage(struct wlr_output *output,
		pixman_region32_t *damage) {
	pixman_region32_intersect_rect(&output->pending.damage, damage,
		0, 0, output->width, output->height);
	output->pending.committed |= WLR_OUTPUT_STATE_DAMAGE;
}

static void output_state_clear_gamma_lut(struct wlr_output_state *state) {
	free(state->gamma_lut);
	state->gamma_lut = NULL;
	state->committed &= ~WLR_OUTPUT_STATE_GAMMA_LUT;
}

static void output_state_clear(struct wlr_output_state *state) {
	output_state_clear_buffer(state);
	output_state_clear_gamma_lut(state);
	pixman_region32_clear(&state->damage);
	state->committed = 0;
}

void output_pending_resolution(struct wlr_output *output,
		const struct wlr_output_state *state, int *width, int *height) {
	if (state->committed & WLR_OUTPUT_STATE_MODE) {
		switch (state->mode_type) {
		case WLR_OUTPUT_STATE_MODE_FIXED:
			*width = state->mode->width;
			*height = state->mode->height;
			return;
		case WLR_OUTPUT_STATE_MODE_CUSTOM:
			*width = state->custom_mode.width;
			*height = state->custom_mode.height;
			return;
		}
		abort();
	} else {
		*width = output->width;
		*height = output->height;
	}
}

/**
 * Compare a struct wlr_output_state with the current state of a struct
 * wlr_output.
 *
 * Returns a bitfield of the unchanged fields.
 *
 * Some fields are not checked: damage always changes in-between frames, the
 * gamma LUT is too expensive to check, the contents of the buffer might have
 * changed, etc.
 */
static uint32_t output_compare_state(struct wlr_output *output,
		const struct wlr_output_state *state) {
	uint32_t fields = 0;
	if (state->committed & WLR_OUTPUT_STATE_MODE) {
		bool unchanged = false;
		switch (state->mode_type) {
		case WLR_OUTPUT_STATE_MODE_FIXED:
			unchanged = output->current_mode == state->mode;
			break;
		case WLR_OUTPUT_STATE_MODE_CUSTOM:
			unchanged = output->width == state->custom_mode.width &&
				output->height == state->custom_mode.height &&
				output->refresh == state->custom_mode.refresh;
			break;
		}
		if (unchanged) {
			fields |= WLR_OUTPUT_STATE_MODE;
		}
	}
	if ((state->committed & WLR_OUTPUT_STATE_ENABLED) && output->enabled == state->enabled) {
		fields |= WLR_OUTPUT_STATE_ENABLED;
	}
	if ((state->committed & WLR_OUTPUT_STATE_SCALE) && output->scale == state->scale) {
		fields |= WLR_OUTPUT_STATE_SCALE;
	}
	if ((state->committed & WLR_OUTPUT_STATE_TRANSFORM) &&
			output->transform == state->transform) {
		fields |= WLR_OUTPUT_STATE_TRANSFORM;
	}
	if (state->committed & WLR_OUTPUT_STATE_ADAPTIVE_SYNC_ENABLED) {
		bool enabled =
			output->adaptive_sync_status != WLR_OUTPUT_ADAPTIVE_SYNC_DISABLED;
		if (enabled == state->adaptive_sync_enabled) {
			fields |= WLR_OUTPUT_STATE_ADAPTIVE_SYNC_ENABLED;
		}
	}
	if ((state->committed & WLR_OUTPUT_STATE_RENDER_FORMAT) &&
			output->render_format == state->render_format) {
		fields |= WLR_OUTPUT_STATE_RENDER_FORMAT;
	}
	if ((state->committed & WLR_OUTPUT_STATE_SUBPIXEL) &&
			output->subpixel == state->subpixel) {
		fields |= WLR_OUTPUT_STATE_SUBPIXEL;
	}
	return fields;
}

static bool output_basic_test(struct wlr_output *output,
		const struct wlr_output_state *state) {
	if (state->committed & WLR_OUTPUT_STATE_BUFFER) {
		if (output->frame_pending) {
			wlr_log(WLR_DEBUG, "Tried to commit a buffer while a frame is pending");
			return false;
		}

		if (output_is_direct_scanout(output, state->buffer)) {
			if (output->attach_render_locks > 0) {
				wlr_log(WLR_DEBUG, "Direct scan-out disabled by lock");
				return false;
			}

			// If the output has at least one software cursor, refuse to attach the
			// buffer
			struct wlr_output_cursor *cursor;
			wl_list_for_each(cursor, &output->cursors, link) {
				if (cursor->enabled && cursor->visible &&
						cursor != output->hardware_cursor) {
					wlr_log(WLR_DEBUG,
						"Direct scan-out disabled by software cursor");
					return false;
				}
			}

			// If the size doesn't match, reject buffer (scaling is not
			// supported)
			int pending_width, pending_height;
			output_pending_resolution(output, state,
				&pending_width, &pending_height);
			if (state->buffer->width != pending_width ||
					state->buffer->height != pending_height) {
				wlr_log(WLR_DEBUG, "Direct scan-out buffer size mismatch");
				return false;
			}
		}
	}

	if (state->committed & WLR_OUTPUT_STATE_RENDER_FORMAT) {
		struct wlr_allocator *allocator = output->allocator;
		assert(allocator != NULL);

		const struct wlr_drm_format_set *display_formats =
			wlr_output_get_primary_formats(output, allocator->buffer_caps);
		struct wlr_drm_format *format = output_pick_format(output, display_formats,
			state->render_format);
		if (format == NULL) {
			wlr_log(WLR_ERROR, "Failed to pick primary buffer format for output");
			return false;
		}

		free(format);
	}

	bool enabled = output->enabled;
	if (state->committed & WLR_OUTPUT_STATE_ENABLED) {
		enabled = state->enabled;
	}

	if (enabled && (state->committed & (WLR_OUTPUT_STATE_ENABLED |
			WLR_OUTPUT_STATE_MODE))) {
		int pending_width, pending_height;
		output_pending_resolution(output, state,
			&pending_width, &pending_height);
		if (pending_width == 0 || pending_height == 0) {
			wlr_log(WLR_DEBUG, "Tried to enable an output with a zero mode");
			return false;
		}
	}

	if (!enabled && state->committed & WLR_OUTPUT_STATE_BUFFER) {
		wlr_log(WLR_DEBUG, "Tried to commit a buffer on a disabled output");
		return false;
	}
	if (!enabled && state->committed & WLR_OUTPUT_STATE_MODE) {
		wlr_log(WLR_DEBUG, "Tried to modeset a disabled output");
		return false;
	}
	if (!enabled && state->committed & WLR_OUTPUT_STATE_ADAPTIVE_SYNC_ENABLED) {
		wlr_log(WLR_DEBUG, "Tried to enable adaptive sync on a disabled output");
		return false;
	}
	if (!enabled && state->committed & WLR_OUTPUT_STATE_RENDER_FORMAT) {
		wlr_log(WLR_DEBUG, "Tried to set format for a disabled output");
		return false;
	}
	if (!enabled && state->committed & WLR_OUTPUT_STATE_GAMMA_LUT) {
		wlr_log(WLR_DEBUG, "Tried to set the gamma lut on a disabled output");
		return false;
	}
	if (!enabled && state->committed & WLR_OUTPUT_STATE_SUBPIXEL) {
		wlr_log(WLR_DEBUG, "Tried to set the subpixel layout on a disabled output");
		return false;
	}

	return true;
}

bool wlr_output_test_state(struct wlr_output *output,
		const struct wlr_output_state *state) {
	uint32_t unchanged = output_compare_state(output, state);

	// Create a shallow copy of the state with only the fields which have been
	// changed and potentially a new buffer.
	struct wlr_output_state copy = *state;
	copy.committed &= ~unchanged;

	if (!output_basic_test(output, &copy)) {
		return false;
	}
	if (!output->impl->test) {
		return true;
	}

	bool new_back_buffer = false;
	if (!output_ensure_buffer(output, &copy, &new_back_buffer)) {
		return false;
	}
	if (new_back_buffer) {
		assert((copy.committed & WLR_OUTPUT_STATE_BUFFER) == 0);
		copy.committed |= WLR_OUTPUT_STATE_BUFFER;
		copy.buffer = output->back_buffer;
	}

	bool success = output->impl->test(output, &copy);
	if (new_back_buffer) {
		output_clear_back_buffer(output);
	}
	return success;
}

bool wlr_output_test(struct wlr_output *output) {
	struct wlr_output_state state = output->pending;

	if (output->back_buffer != NULL) {
		assert((state.committed & WLR_OUTPUT_STATE_BUFFER) == 0);
		state.committed |= WLR_OUTPUT_STATE_BUFFER;
		state.buffer = output->back_buffer;
	}

	return wlr_output_test_state(output, &state);
}
/*
bool wlr_output_commit_state(struct wlr_output *output,
		const struct wlr_output_state *state) {
	uint32_t unchanged = output_compare_state(output, state);

	// Create a shallow copy of the state with only the fields which have been
	// changed and potentially a new buffer.
	struct wlr_output_state pending = *state;
	pending.committed &= ~unchanged;

	if (!output_basic_test(output, &pending)) {
		wlr_log(WLR_ERROR, "Basic output test failed for %s", output->name);
		return false;
	}

	bool new_back_buffer = false;
	if (!output_ensure_buffer(output, &pending, &new_back_buffer)) {
		return false;
	}
	// Debug state before assertion
	wlr_log(WLR_DEBUG, "Committing state - pending.committed: 0x%x", pending.committed);
	if (new_back_buffer) {
		assert((pending.committed & WLR_OUTPUT_STATE_BUFFER) == 0);
		output_state_attach_buffer(&pending, output->back_buffer);
		output_clear_back_buffer(output);
	}

	if ((pending.committed & WLR_OUTPUT_STATE_BUFFER) &&
			output->idle_frame != NULL) {
		wl_event_source_remove(output->idle_frame);
		output->idle_frame = NULL;
	}

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	struct wlr_output_event_precommit pre_event = {
		.output = output,
		.when = &now,
		.state = &pending,
	};
	wl_signal_emit_mutable(&output->events.precommit, &pre_event);

	if (!output->impl->commit(output, &pending)) {
		if (new_back_buffer) {
			wlr_buffer_unlock(pending.buffer);
		}
		return false;
	}

	if (pending.committed & WLR_OUTPUT_STATE_BUFFER) {
		struct wlr_output_cursor *cursor;
		wl_list_for_each(cursor, &output->cursors, link) {
			if (!cursor->enabled || !cursor->visible || cursor->surface == NULL) {
				continue;
			}
			wlr_surface_send_frame_done(cursor->surface, &now);
		}
	}

	if (pending.committed & WLR_OUTPUT_STATE_RENDER_FORMAT) {
		output->render_format = pending.render_format;
	}

	if (pending.committed & WLR_OUTPUT_STATE_SUBPIXEL) {
		output->subpixel = pending.subpixel;
	}

	output->commit_seq++;

	bool scale_updated = pending.committed & WLR_OUTPUT_STATE_SCALE;
	if (scale_updated) {
		output->scale = pending.scale;
	}

	if (pending.committed & WLR_OUTPUT_STATE_TRANSFORM) {
		output->transform = pending.transform;
		output_update_matrix(output);
	}

	bool geometry_updated = pending.committed &
		(WLR_OUTPUT_STATE_MODE | WLR_OUTPUT_STATE_TRANSFORM |
		WLR_OUTPUT_STATE_SUBPIXEL);
	if (geometry_updated || scale_updated) {
		struct wl_resource *resource;
		wl_resource_for_each(resource, &output->resources) {
			if (geometry_updated) {
				send_geometry(resource);
			}
			if (scale_updated) {
				send_scale(resource);
			}
		}
		wlr_output_schedule_done(output);
	}

	// Destroy the swapchains when an output is disabled
	if ((pending.committed & WLR_OUTPUT_STATE_ENABLED) && !pending.enabled) {
		wlr_swapchain_destroy(output->swapchain);
		output->swapchain = NULL;
		wlr_swapchain_destroy(output->cursor_swapchain);
		output->cursor_swapchain = NULL;
	}

	if (pending.committed & WLR_OUTPUT_STATE_BUFFER) {
		output->frame_pending = true;
		output->needs_frame = false;
	}

	if ((pending.committed & WLR_OUTPUT_STATE_BUFFER) &&
			output->swapchain != NULL) {
		wlr_swapchain_set_buffer_submitted(output->swapchain, pending.buffer);
	}

	struct wlr_output_event_commit event = {
		.output = output,
		.committed = pending.committed,
		.when = &now,
		.buffer = (pending.committed & WLR_OUTPUT_STATE_BUFFER) ? pending.buffer : NULL,
	};
	wl_signal_emit_mutable(&output->events.commit, &event);

	if (new_back_buffer) {
		wlr_buffer_unlock(pending.buffer);
	}

	return true;
}*/
bool wlr_output_commit_state(struct wlr_output *output,
		const struct wlr_output_state *state) {
	uint32_t unchanged = output_compare_state(output, state);

	// Create a shallow copy of the state with only the fields which have been
	// changed and potentially a new buffer.
	struct wlr_output_state pending = *state;
	pending.committed &= ~unchanged;

	if (!output_basic_test(output, &pending)) {
		wlr_log(WLR_ERROR, "Basic output test failed for %s", output->name);
		return false;
	}

	// Debug state before buffer operations
	wlr_log(WLR_DEBUG, "Committing state before ensure_buffer - pending.committed: 0x%x", pending.committed);

	bool new_back_buffer = false;
	if (!output_ensure_buffer(output, &pending, &new_back_buffer)) {
		return false;
	}

	// Handle new back buffer case
	if (new_back_buffer) {
		if (pending.committed & WLR_OUTPUT_STATE_BUFFER) {
			wlr_log(WLR_DEBUG, "New back buffer attached but WLR_OUTPUT_STATE_BUFFER is set (0x%x), clearing it",
					pending.committed);
			pending.committed &= ~WLR_OUTPUT_STATE_BUFFER;
			pending.buffer = NULL;
		}
		output_state_attach_buffer(&pending, output->back_buffer);
		output_clear_back_buffer(output);
	}

	if ((pending.committed & WLR_OUTPUT_STATE_BUFFER) &&
			output->idle_frame != NULL) {
		wl_event_source_remove(output->idle_frame);
		output->idle_frame = NULL;
	}

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	struct wlr_output_event_precommit pre_event = {
		.output = output,
		.when = &now,
		.state = &pending,
	};
	wl_signal_emit_mutable(&output->events.precommit, &pre_event);

	if (!output->impl->commit(output, &pending)) {
		if (new_back_buffer) {
			wlr_buffer_unlock(pending.buffer);
		}
		return false;
	}

	if (pending.committed & WLR_OUTPUT_STATE_BUFFER) {
		struct wlr_output_cursor *cursor;
		wl_list_for_each(cursor, &output->cursors, link) {
			if (!cursor->enabled || !cursor->visible || cursor->surface == NULL) {
				continue;
			}
			wlr_surface_send_frame_done(cursor->surface, &now);
		}
	}

	if (pending.committed & WLR_OUTPUT_STATE_RENDER_FORMAT) {
		output->render_format = pending.render_format;
	}

	if (pending.committed & WLR_OUTPUT_STATE_SUBPIXEL) {
		output->subpixel = pending.subpixel;
	}

	output->commit_seq++;

	bool scale_updated = pending.committed & WLR_OUTPUT_STATE_SCALE;
	if (scale_updated) {
		output->scale = pending.scale;
	}

	if (pending.committed & WLR_OUTPUT_STATE_TRANSFORM) {
		output->transform = pending.transform;
		output_update_matrix(output);
	}

	bool geometry_updated = pending.committed &
		(WLR_OUTPUT_STATE_MODE | WLR_OUTPUT_STATE_TRANSFORM |
		WLR_OUTPUT_STATE_SUBPIXEL);
	if (geometry_updated || scale_updated) {
		struct wl_resource *resource;
		wl_resource_for_each(resource, &output->resources) {
			if (geometry_updated) {
				send_geometry(resource);
			}
			if (scale_updated) {
				send_scale(resource);
			}
		}
		wlr_output_schedule_done(output);
	}

	// Destroy the swapchains when an output is disabled
	if ((pending.committed & WLR_OUTPUT_STATE_ENABLED) && !pending.enabled) {
		wlr_swapchain_destroy(output->swapchain);
		output->swapchain = NULL;
		wlr_swapchain_destroy(output->cursor_swapchain);
		output->cursor_swapchain = NULL;
	}

	if (pending.committed & WLR_OUTPUT_STATE_BUFFER) {
		output->frame_pending = true;
		output->needs_frame = false;
	}

	if ((pending.committed & WLR_OUTPUT_STATE_BUFFER) &&
			output->swapchain != NULL) {
		wlr_swapchain_set_buffer_submitted(output->swapchain, pending.buffer);
	}

	struct wlr_output_event_commit event = {
		.output = output,
		.committed = pending.committed,
		.when = &now,
		.buffer = (pending.committed & WLR_OUTPUT_STATE_BUFFER) ? pending.buffer : NULL,
	};
	wl_signal_emit_mutable(&output->events.commit, &event);

	if (new_back_buffer) {
		wlr_buffer_unlock(pending.buffer);
	}

	return true;
}

/*
bool wlr_output_commit_state(struct wlr_output *output,
		const struct wlr_output_state *state) {
	uint32_t unchanged = output_compare_state(output, state);

	// Create a shallow copy of the state with only the fields which have been
	// changed and potentially a new buffer.
	struct wlr_output_state pending = *state;
	pending.committed &= ~unchanged;

	if (!output_basic_test(output, &pending)) {
		wlr_log(WLR_ERROR, "Basic output test failed for %s", output->name);
		return false;
	}

	bool new_back_buffer = false;
	if (!output_ensure_buffer(output, &pending, &new_back_buffer)) {
		return false;
	}
	if (new_back_buffer) {
		assert((pending.committed & WLR_OUTPUT_STATE_BUFFER) == 0);
		output_state_attach_buffer(&pending, output->back_buffer);
		output_clear_back_buffer(output);
	}

	if ((pending.committed & WLR_OUTPUT_STATE_BUFFER) &&
			output->idle_frame != NULL) {
		wl_event_source_remove(output->idle_frame);
		output->idle_frame = NULL;
	}

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	struct wlr_output_event_precommit pre_event = {
		.output = output,
		.when = &now,
		.state = &pending,
	};
	wl_signal_emit_mutable(&output->events.precommit, &pre_event);

	if (!output->impl->commit(output, &pending)) {
		if (new_back_buffer) {
			wlr_buffer_unlock(pending.buffer);
		}
		return false;
	}

	if (pending.committed & WLR_OUTPUT_STATE_BUFFER) {
		struct wlr_output_cursor *cursor;
		wl_list_for_each(cursor, &output->cursors, link) {
			if (!cursor->enabled || !cursor->visible || cursor->surface == NULL) {
				continue;
			}
			wlr_surface_send_frame_done(cursor->surface, &now);
		}
	}

	if (pending.committed & WLR_OUTPUT_STATE_RENDER_FORMAT) {
		output->render_format = pending.render_format;
	}

	if (pending.committed & WLR_OUTPUT_STATE_SUBPIXEL) {
		output->subpixel = pending.subpixel;
	}

	output->commit_seq++;

	bool scale_updated = pending.committed & WLR_OUTPUT_STATE_SCALE;
	if (scale_updated) {
		output->scale = pending.scale;
	}

	if (pending.committed & WLR_OUTPUT_STATE_TRANSFORM) {
		output->transform = pending.transform;
		output_update_matrix(output);
	}

	bool geometry_updated = pending.committed &
		(WLR_OUTPUT_STATE_MODE | WLR_OUTPUT_STATE_TRANSFORM |
		WLR_OUTPUT_STATE_SUBPIXEL);
	if (geometry_updated || scale_updated) {
		struct wl_resource *resource;
		wl_resource_for_each(resource, &output->resources) {
			if (geometry_updated) {
				send_geometry(resource);
			}
			if (scale_updated) {
				send_scale(resource);
			}
		}
		wlr_output_schedule_done(output);
	}

	// Destroy the swapchains when an output is disabled
	if ((pending.committed & WLR_OUTPUT_STATE_ENABLED) && !pending.enabled) {
		wlr_swapchain_destroy(output->swapchain);
		output->swapchain = NULL;
		wlr_swapchain_destroy(output->cursor_swapchain);
		output->cursor_swapchain = NULL;
	}

	if (pending.committed & WLR_OUTPUT_STATE_BUFFER) {
		output->frame_pending = true;
		output->needs_frame = false;
	}

	if ((pending.committed & WLR_OUTPUT_STATE_BUFFER) &&
			output->swapchain != NULL) {
		wlr_swapchain_set_buffer_submitted(output->swapchain, pending.buffer);
	}

	struct wlr_output_event_commit event = {
		.output = output,
		.committed = pending.committed,
		.when = &now,
		.buffer = (pending.committed & WLR_OUTPUT_STATE_BUFFER) ? pending.buffer : NULL,
	};
	wl_signal_emit_mutable(&output->events.commit, &event);

	if (new_back_buffer) {
		wlr_buffer_unlock(pending.buffer);
	}

	return true;
}*/

bool wlr_output_commit(struct wlr_output *output) {
	// Make sure the pending state is cleared before the output is committed
	struct wlr_output_state state = {0};
	output_state_move(&state, &output->pending);

	// output_clear_back_buffer detaches the buffer from the renderer. This is
	// important to do before calling impl->commit(), because this marks an
	// implicit rendering synchronization point. The backend needs it to avoid
	// displaying a buffer when asynchronous GPU work isn't finished.
	if (output->back_buffer != NULL) {
		output_state_attach_buffer(&state, output->back_buffer);
		output_clear_back_buffer(output);
	}

	bool ok = wlr_output_commit_state(output, &state);
	output_state_finish(&state);
	return ok;
}

void wlr_output_rollback(struct wlr_output *output) {
	output_clear_back_buffer(output);
	output_state_clear(&output->pending);
}

void output_state_attach_buffer(struct wlr_output_state *state,
		struct wlr_buffer *buffer) {
	output_state_clear_buffer(state);
	state->committed |= WLR_OUTPUT_STATE_BUFFER;
	state->buffer = wlr_buffer_lock(buffer);
}

void wlr_output_attach_buffer(struct wlr_output *output,
		struct wlr_buffer *buffer) {
	output_state_attach_buffer(&output->pending, buffer);
}

void wlr_output_send_frame(struct wlr_output *output) {
	output->frame_pending = false;
	if (output->enabled) {
		wl_signal_emit_mutable(&output->events.frame, output);
	}
}

static void schedule_frame_handle_idle_timer(void *data) {
	struct wlr_output *output = data;
	output->idle_frame = NULL;
	if (!output->frame_pending) {
		wlr_output_send_frame(output);
	}
}

void wlr_output_schedule_frame(struct wlr_output *output) {
	// Make sure the compositor commits a new frame. This is necessary to make
	// clients which ask for frame callbacks without submitting a new buffer
	// work.
	wlr_output_update_needs_frame(output);

	if (output->frame_pending || output->idle_frame != NULL) {
		return;
	}

	// We're using an idle timer here in case a buffer swap happens right after
	// this function is called
	struct wl_event_loop *ev = wl_display_get_event_loop(output->display);
	output->idle_frame =
		wl_event_loop_add_idle(ev, schedule_frame_handle_idle_timer, output);
}

void wlr_output_send_present(struct wlr_output *output,
		struct wlr_output_event_present *event) {
	assert(event);
	event->output = output;

	struct timespec now;
	if (event->presented && event->when == NULL) {
		clockid_t clock = wlr_backend_get_presentation_clock(output->backend);
		errno = 0;
		if (clock_gettime(clock, &now) != 0) {
			wlr_log_errno(WLR_ERROR, "failed to send output present event: "
				"failed to read clock");
			return;
		}
		event->when = &now;
	}

	wl_signal_emit_mutable(&output->events.present, event);
}

void wlr_output_set_gamma(struct wlr_output *output, size_t size,
		const uint16_t *r, const uint16_t *g, const uint16_t *b) {
	uint16_t *gamma_lut = NULL;
	if (size > 0) {
		gamma_lut = malloc(3 * size * sizeof(uint16_t));
		if (gamma_lut == NULL) {
			wlr_log_errno(WLR_ERROR, "Allocation failed");
			return;
		}
		memcpy(gamma_lut, r, size * sizeof(uint16_t));
		memcpy(gamma_lut + size, g, size * sizeof(uint16_t));
		memcpy(gamma_lut + 2 * size, b, size * sizeof(uint16_t));
	}

	output_state_clear_gamma_lut(&output->pending);

	output->pending.gamma_lut_size = size;
	output->pending.gamma_lut = gamma_lut;
	output->pending.committed |= WLR_OUTPUT_STATE_GAMMA_LUT;
}

size_t wlr_output_get_gamma_size(struct wlr_output *output) {
	if (!output->impl->get_gamma_size) {
		return 0;
	}
	return output->impl->get_gamma_size(output);
}

void wlr_output_update_needs_frame(struct wlr_output *output) {
	if (output->needs_frame) {
		return;
	}
	output->needs_frame = true;
	wl_signal_emit_mutable(&output->events.needs_frame, output);
}

void wlr_output_damage_whole(struct wlr_output *output) {
	int width, height;
	wlr_output_transformed_resolution(output, &width, &height);

	pixman_region32_t damage;
	pixman_region32_init_rect(&damage, 0, 0, width, height);

	struct wlr_output_event_damage event = {
		.output = output,
		.damage = &damage,
	};
	wl_signal_emit_mutable(&output->events.damage, &event);

	pixman_region32_fini(&damage);
}

const struct wlr_drm_format_set *wlr_output_get_primary_formats(
		struct wlr_output *output, uint32_t buffer_caps) {
	if (!output->impl->get_primary_formats) {
		return NULL;
	}

	const struct wlr_drm_format_set *formats =
		output->impl->get_primary_formats(output, buffer_caps);
	if (formats == NULL) {
		wlr_log(WLR_ERROR, "Failed to get primary display formats");

		static const struct wlr_drm_format_set empty_format_set = {0};
		return &empty_format_set;
	}

	return formats;
}
