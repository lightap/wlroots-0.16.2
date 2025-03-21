#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include <drm_fourcc.h>
#include <xcb/dri3.h>
#include <xcb/present.h>
#include <xcb/render.h>
#include <xcb/shm.h>
#include <xcb/xcb.h>
#include <xcb/xinput.h>

#include <wlr/interfaces/wlr_output.h>
#include <wlr/interfaces/wlr_pointer.h>
#include <wlr/interfaces/wlr_touch.h>
#include <wlr/render/wlr_renderer.h>
#include <wlr/types/wlr_matrix.h>
#include <wlr/util/log.h>

#include "backend/RDP.h"
#include "util/signal.h"
#include "util/time.h"

static const uint32_t SUPPORTED_OUTPUT_STATE =
	WLR_OUTPUT_STATE_BACKEND_OPTIONAL |
	WLR_OUTPUT_STATE_BUFFER |
	WLR_OUTPUT_STATE_MODE;

static void parse_xcb_setup(struct wlr_output *output,
		xcb_connection_t *xcb) {
	const xcb_setup_t *xcb_setup = xcb_get_setup(xcb);

	snprintf(output->make, sizeof(output->make), "%.*s",
			xcb_setup_vendor_length(xcb_setup),
			xcb_setup_vendor(xcb_setup));
	snprintf(output->model, sizeof(output->model), "%"PRIu16".%"PRIu16,
			xcb_setup->protocol_major_version,
			xcb_setup->protocol_minor_version);
}

static struct wlr_RDP_output *get_RDP_output_from_output(
		struct wlr_output *wlr_output) {
	assert(wlr_output_is_RDP(wlr_output));
	return (struct wlr_RDP_output *)wlr_output;
}

static bool output_set_custom_mode(struct wlr_output *wlr_output,
		int32_t width, int32_t height, int32_t refresh) {
	struct wlr_RDP_output *output = get_RDP_output_from_output(wlr_output);
	struct wlr_RDP_backend *RDP = output->RDP;

	const uint32_t values[] = { width, height };
	xcb_void_cookie_t cookie = xcb_configure_window_checked(
		RDP->xcb, output->win,
		XCB_CONFIG_WINDOW_WIDTH | XCB_CONFIG_WINDOW_HEIGHT, values);

	xcb_generic_error_t *error;
	if ((error = xcb_request_check(RDP->xcb, cookie))) {
		wlr_log(WLR_ERROR, "Could not set window size to %dx%d\n",
			width, height);
		free(error);
		return false;
	}

	return true;
}

static void destroy_RDP_buffer(struct wlr_RDP_buffer *buffer);

static void output_destroy(struct wlr_output *wlr_output) {
	struct wlr_RDP_output *output = get_RDP_output_from_output(wlr_output);
	struct wlr_RDP_backend *RDP = output->RDP;

	pixman_region32_fini(&output->exposed);

	wlr_input_device_destroy(&output->pointer_dev);
	wlr_input_device_destroy(&output->touch_dev);

	struct wlr_RDP_buffer *buffer, *buffer_tmp;
	wl_list_for_each_safe(buffer, buffer_tmp, &output->buffers, link) {
		destroy_RDP_buffer(buffer);
	}

	wl_list_remove(&output->link);

	if (output->cursor.pic != XCB_NONE) {
		xcb_render_free_picture(RDP->xcb, output->cursor.pic);
	}

	// A zero event mask deletes the event context
	xcb_present_select_input(RDP->xcb, output->present_event_id, output->win, 0);
	xcb_destroy_window(RDP->xcb, output->win);
	xcb_flush(RDP->xcb);
	free(output);
}

static bool output_test(struct wlr_output *wlr_output) {
	uint32_t unsupported =
		wlr_output->pending.committed & ~SUPPORTED_OUTPUT_STATE;
	if (unsupported != 0) {
		wlr_log(WLR_DEBUG, "Unsupported output state fields: 0x%"PRIx32,
			unsupported);
		return false;
	}

	if (wlr_output->pending.committed & WLR_OUTPUT_STATE_MODE) {
		assert(wlr_output->pending.mode_type == WLR_OUTPUT_STATE_MODE_CUSTOM);
	}

	return true;
}

static void destroy_RDP_buffer(struct wlr_RDP_buffer *buffer) {
	if (!buffer) {
		return;
	}
	wl_list_remove(&buffer->buffer_destroy.link);
	wl_list_remove(&buffer->link);
	xcb_free_pixmap(buffer->RDP->xcb, buffer->pixmap);
	free(buffer);
}

static void buffer_handle_buffer_destroy(struct wl_listener *listener,
		void *data) {
	struct wlr_RDP_buffer *buffer =
		wl_container_of(listener, buffer, buffer_destroy);
	destroy_RDP_buffer(buffer);
}

static xcb_pixmap_t import_dmabuf(struct wlr_RDP_output *output,
		struct wlr_dmabuf_attributes *dmabuf) {
	struct wlr_RDP_backend *RDP = output->RDP;

	if (dmabuf->format != RDP->RDP_format->drm) {
		// The pixmap's depth must match the window's depth, otherwise Present
		// will throw a Match error
		return XCB_PIXMAP_NONE;
	}

	if (dmabuf->flags != 0) {
		return XCB_PIXMAP_NONE;
	}

	// xcb closes the FDs after sending them, so we need to dup them here
	struct wlr_dmabuf_attributes dup_attrs = {0};
	if (!wlr_dmabuf_attributes_copy(&dup_attrs, dmabuf)) {
		return XCB_PIXMAP_NONE;
	}

	const struct wlr_RDP_format *RDP_fmt = RDP->RDP_format;
	xcb_pixmap_t pixmap = xcb_generate_id(RDP->xcb);

	if (RDP->dri3_major_version > 1 || RDP->dri3_minor_version >= 2) {
		if (dmabuf->n_planes > 4) {
			wlr_dmabuf_attributes_finish(&dup_attrs);
			return XCB_PIXMAP_NONE;
		}
		xcb_dri3_pixmap_from_buffers(RDP->xcb, pixmap, output->win,
			dmabuf->n_planes, dmabuf->width, dmabuf->height, dmabuf->stride[0],
			dmabuf->offset[0], dmabuf->stride[1], dmabuf->offset[1],
			dmabuf->stride[2], dmabuf->offset[2], dmabuf->stride[3],
			dmabuf->offset[3], RDP_fmt->depth, RDP_fmt->bpp, dmabuf->modifier,
			dup_attrs.fd);
	} else {
		// PixmapFromBuffers requires DRI3 1.2
		if (dmabuf->n_planes != 1
				|| dmabuf->modifier != DRM_FORMAT_MOD_INVALID) {
			wlr_dmabuf_attributes_finish(&dup_attrs);
			return XCB_PIXMAP_NONE;
		}
		xcb_dri3_pixmap_from_buffer(RDP->xcb, pixmap, output->win,
			dmabuf->height * dmabuf->stride[0], dmabuf->width, dmabuf->height,
			dmabuf->stride[0], RDP_fmt->depth, RDP_fmt->bpp, dup_attrs.fd[0]);
	}

	return pixmap;
}

static xcb_pixmap_t import_shm(struct wlr_RDP_output *output,
		struct wlr_shm_attributes *shm) {
	struct wlr_RDP_backend *RDP = output->RDP;

	if (shm->format != RDP->RDP_format->drm) {
		// The pixmap's depth must match the window's depth, otherwise Present
		// will throw a Match error
		return XCB_PIXMAP_NONE;
	}

	// xcb closes the FD after sending it
	int fd = fcntl(shm->fd, F_DUPFD_CLOEXEC, 0);
	if (fd < 0) {
		wlr_log_errno(WLR_ERROR, "fcntl(F_DUPFD_CLOEXEC) failed");
		return XCB_PIXMAP_NONE;
	}

	xcb_shm_seg_t seg = xcb_generate_id(RDP->xcb);
	xcb_shm_attach_fd(RDP->xcb, seg, fd, false);

	xcb_pixmap_t pixmap = xcb_generate_id(RDP->xcb);
	xcb_shm_create_pixmap(RDP->xcb, pixmap, output->win, shm->width,
		shm->height, RDP->RDP_format->depth, seg, shm->offset);

	xcb_shm_detach(RDP->xcb, seg);

	return pixmap;
}

static struct wlr_RDP_buffer *create_RDP_buffer(struct wlr_RDP_output *output,
		struct wlr_buffer *wlr_buffer) {
	struct wlr_RDP_backend *RDP = output->RDP;
	xcb_pixmap_t pixmap = XCB_PIXMAP_NONE;

	struct wlr_dmabuf_attributes dmabuf_attrs;
	struct wlr_shm_attributes shm_attrs;
	if (wlr_buffer_get_dmabuf(wlr_buffer, &dmabuf_attrs)) {
		pixmap = import_dmabuf(output, &dmabuf_attrs);
	} else if (wlr_buffer_get_shm(wlr_buffer, &shm_attrs)) {
		pixmap = import_shm(output, &shm_attrs);
	}

	if (pixmap == XCB_PIXMAP_NONE) {
		return NULL;
	}

	struct wlr_RDP_buffer *buffer = calloc(1, sizeof(struct wlr_RDP_buffer));
	if (!buffer) {
		xcb_free_pixmap(RDP->xcb, pixmap);
		return NULL;
	}
	buffer->buffer = wlr_buffer_lock(wlr_buffer);
	buffer->pixmap = pixmap;
	buffer->RDP = RDP;
	wl_list_insert(&output->buffers, &buffer->link);

	buffer->buffer_destroy.notify = buffer_handle_buffer_destroy;
	wl_signal_add(&wlr_buffer->events.destroy, &buffer->buffer_destroy);

	return buffer;
}

static struct wlr_RDP_buffer *get_or_create_RDP_buffer(
		struct wlr_RDP_output *output, struct wlr_buffer *wlr_buffer) {
	struct wlr_RDP_buffer *buffer;
	wl_list_for_each(buffer, &output->buffers, link) {
		if (buffer->buffer == wlr_buffer) {
			wlr_buffer_lock(buffer->buffer);
			return buffer;
		}
	}

	return create_RDP_buffer(output, wlr_buffer);
}

static bool output_commit_buffer(struct wlr_RDP_output *output) {
	struct wlr_RDP_backend *RDP = output->RDP;

	struct wlr_buffer *buffer = output->wlr_output.pending.buffer;
	struct wlr_RDP_buffer *RDP_buffer =
		get_or_create_RDP_buffer(output, buffer);
	if (!RDP_buffer) {
		goto error;
	}

	xcb_xfixes_region_t region = XCB_NONE;
	if (output->wlr_output.pending.committed & WLR_OUTPUT_STATE_DAMAGE) {
		pixman_region32_union(&output->exposed, &output->exposed, &output->wlr_output.pending.damage);

		int rects_len = 0;
		pixman_box32_t *rects = pixman_region32_rectangles(&output->exposed, &rects_len);

		xcb_rectangle_t *xcb_rects = calloc(rects_len, sizeof(xcb_rectangle_t));
		if (!xcb_rects) {
			goto error;
		}

		for (int i = 0; i < rects_len; i++) {
			pixman_box32_t *box = &rects[i];
			xcb_rects[i] = (struct xcb_rectangle_t){
				.x = box->x1,
				.y = box->y1,
				.width = box->x2 - box->x1,
				.height = box->y2 - box->y1,
			};
		}

		region = xcb_generate_id(RDP->xcb);
		xcb_xfixes_create_region(RDP->xcb, region, rects_len, xcb_rects);

		free(xcb_rects);
	}

	pixman_region32_clear(&output->exposed);

	uint32_t serial = output->wlr_output.commit_seq;
	uint32_t options = 0;
	uint64_t target_msc = output->last_msc ? output->last_msc + 1 : 0;
	xcb_present_pixmap(RDP->xcb, output->win, RDP_buffer->pixmap, serial,
		0, region, 0, 0, XCB_NONE, XCB_NONE, XCB_NONE, options, target_msc,
		0, 0, 0, NULL);

	if (region != XCB_NONE) {
		xcb_xfixes_destroy_region(RDP->xcb, region);
	}

	return true;

error:
	destroy_RDP_buffer(RDP_buffer);
	return false;
}

static bool output_commit(struct wlr_output *wlr_output) {
	struct wlr_RDP_output *output = get_RDP_output_from_output(wlr_output);
	struct wlr_RDP_backend *RDP = output->RDP;

	if (!output_test(wlr_output)) {
		return false;
	}

	if (wlr_output->pending.committed & WLR_OUTPUT_STATE_MODE) {
		if (!output_set_custom_mode(wlr_output,
				wlr_output->pending.custom_mode.width,
				wlr_output->pending.custom_mode.height,
				wlr_output->pending.custom_mode.refresh)) {
			return false;
		}
	}

	if (wlr_output->pending.committed & WLR_OUTPUT_STATE_ADAPTIVE_SYNC_ENABLED &&
			RDP->atoms.variable_refresh != XCB_ATOM_NONE) {
		if (wlr_output->pending.adaptive_sync_enabled) {
			uint32_t enabled = 1;
			xcb_change_property(RDP->xcb, XCB_PROP_MODE_REPLACE, output->win,
				RDP->atoms.variable_refresh, XCB_ATOM_CARDINAL, 32, 1,
				&enabled);
			wlr_output->adaptive_sync_status = WLR_OUTPUT_ADAPTIVE_SYNC_UNKNOWN;
		} else {
			xcb_delete_property(RDP->xcb, output->win,
				RDP->atoms.variable_refresh);
			wlr_output->adaptive_sync_status = WLR_OUTPUT_ADAPTIVE_SYNC_DISABLED;
		}
	}

	if (wlr_output->pending.committed & WLR_OUTPUT_STATE_BUFFER) {
		if (!output_commit_buffer(output)) {
			return false;
		}
	}

	xcb_flush(RDP->xcb);

	return true;
}

static void update_RDP_output_cursor(struct wlr_RDP_output *output,
		int32_t hotspot_x, int32_t hotspot_y) {
	struct wlr_RDP_backend *RDP = output->RDP;

	xcb_cursor_t cursor = RDP->transparent_cursor;

	if (output->cursor.pic != XCB_NONE) {
		cursor = xcb_generate_id(RDP->xcb);
		xcb_render_create_cursor(RDP->xcb, cursor, output->cursor.pic,
			hotspot_x, hotspot_y);
	}

	uint32_t values[] = {cursor};
	xcb_change_window_attributes(RDP->xcb, output->win,
		XCB_CW_CURSOR, values);
	xcb_flush(RDP->xcb);

	if (cursor != RDP->transparent_cursor) {
		xcb_free_cursor(RDP->xcb, cursor);
	}
}

static bool output_cursor_to_picture(struct wlr_RDP_output *output,
		struct wlr_buffer *buffer) {
	struct wlr_RDP_backend *RDP = output->RDP;
	struct wlr_renderer *renderer = wlr_backend_get_renderer(&RDP->backend);

	if (output->cursor.pic != XCB_NONE) {
		xcb_render_free_picture(RDP->xcb, output->cursor.pic);
	}
	output->cursor.pic = XCB_NONE;

	if (buffer == NULL) {
		return true;
	}

	int depth = 32;
	int stride = buffer->width * 4;

	uint8_t *data = malloc(buffer->height * stride);
	if (data == NULL) {
		return false;
	}

	if (!wlr_renderer_begin_with_buffer(renderer, buffer)) {
		free(data);
		return false;
	}

	bool result = wlr_renderer_read_pixels(
		renderer, DRM_FORMAT_ARGB8888, NULL,
		stride, buffer->width, buffer->height, 0, 0, 0, 0,
		data);

	wlr_renderer_end(renderer);

	if (!result) {
		free(data);
		return false;
	}

	xcb_pixmap_t pix = xcb_generate_id(RDP->xcb);
	xcb_create_pixmap(RDP->xcb, depth, pix, output->win,
		buffer->width, buffer->height);

	output->cursor.pic = xcb_generate_id(RDP->xcb);
	xcb_render_create_picture(RDP->xcb, output->cursor.pic,
		pix, RDP->argb32, 0, 0);

	xcb_gcontext_t gc = xcb_generate_id(RDP->xcb);
	xcb_create_gc(RDP->xcb, gc, pix, 0, NULL);

	xcb_put_image(RDP->xcb, XCB_IMAGE_FORMAT_Z_PIXMAP,
		pix, gc, buffer->width, buffer->height, 0, 0, 0, depth,
		stride * buffer->height * sizeof(uint8_t), data);
	free(data);
	xcb_free_gc(RDP->xcb, gc);
	xcb_free_pixmap(RDP->xcb, pix);

	return true;
}

static bool output_set_cursor(struct wlr_output *wlr_output,
		struct wlr_buffer *buffer, int32_t hotspot_x, int32_t hotspot_y) {
	struct wlr_RDP_output *output = get_RDP_output_from_output(wlr_output);
	struct wlr_RDP_backend *RDP = output->RDP;

	if (RDP->argb32 == XCB_NONE) {
		return false;
	}

	if (buffer != NULL) {
		if (hotspot_x < 0) {
			hotspot_x = 0;
		}
		if (hotspot_x > buffer->width) {
			hotspot_x = buffer->width;
		}
		if (hotspot_y < 0) {
			hotspot_y = 0;
		}
		if (hotspot_y > buffer->height) {
			hotspot_y = buffer->height;
		}
	}

	bool success = output_cursor_to_picture(output, buffer);

	update_RDP_output_cursor(output, hotspot_x, hotspot_y);

	return success;
}

static bool output_move_cursor(struct wlr_output *_output, int x, int y) {
	// TODO: only return true if x == current x and y == current y
	return true;
}

static const struct wlr_drm_format_set *output_get_primary_formats(
		struct wlr_output *wlr_output, uint32_t buffer_caps) {
	struct wlr_RDP_output *output = get_RDP_output_from_output(wlr_output);
	struct wlr_RDP_backend *RDP = output->RDP;

	if (RDP->have_dri3 && (buffer_caps & WLR_BUFFER_CAP_DMABUF)) {
		return &output->RDP->primary_dri3_formats;
	} else if (RDP->have_shm && (buffer_caps & WLR_BUFFER_CAP_SHM)) {
		return &output->RDP->primary_shm_formats;
	}
	return NULL;
}

static const struct wlr_output_impl output_impl = {
	.destroy = output_destroy,
	.test = output_test,
	.commit = output_commit,
	.set_cursor = output_set_cursor,
	.move_cursor = output_move_cursor,
	.get_primary_formats = output_get_primary_formats,
};

struct wlr_output *wlr_RDP_output_create(struct wlr_backend *backend) {
	struct wlr_RDP_backend *RDP = get_RDP_backend_from_backend(backend);

	if (!RDP->started) {
		++RDP->requested_outputs;
		return NULL;
	}

	struct wlr_RDP_output *output = calloc(1, sizeof(struct wlr_RDP_output));
	if (output == NULL) {
		return NULL;
	}
	output->RDP = RDP;
	wl_list_init(&output->buffers);
	pixman_region32_init(&output->exposed);

	struct wlr_output *wlr_output = &output->wlr_output;
	wlr_output_init(wlr_output, &RDP->backend, &output_impl, RDP->wl_display);

	wlr_output_update_custom_mode(wlr_output, 1024, 768, 0);

	snprintf(wlr_output->name, sizeof(wlr_output->name), "RDP-%zd",
		++RDP->last_output_num);
	parse_xcb_setup(wlr_output, RDP->xcb);

	char description[128];
	snprintf(description, sizeof(description),
		"RDP output %zd", RDP->last_output_num);
	wlr_output_set_description(wlr_output, description);

	// The RDP protocol requires us to set a colormap and border pixel if the
	// depth doesn't match the root window's
	uint32_t mask = XCB_CW_BORDER_PIXEL | XCB_CW_EVENT_MASK |
		XCB_CW_COLORMAP | XCB_CW_CURSOR;
	uint32_t values[] = {
		0,
		XCB_EVENT_MASK_EXPOSURE | XCB_EVENT_MASK_STRUCTURE_NOTIFY,
		RDP->colormap,
		RDP->transparent_cursor,
	};
	output->win = xcb_generate_id(RDP->xcb);
	xcb_create_window(RDP->xcb, RDP->depth->depth, output->win,
		RDP->screen->root, 0, 0, wlr_output->width, wlr_output->height, 0,
		XCB_WINDOW_CLASS_INPUT_OUTPUT, RDP->visualid, mask, values);

	struct {
		xcb_input_event_mask_t head;
		xcb_input_xi_event_mask_t mask;
	} xinput_mask = {
		.head = { .deviceid = XCB_INPUT_DEVICE_ALL_MASTER, .mask_len = 1 },
		.mask = XCB_INPUT_XI_EVENT_MASK_KEY_PRESS |
			XCB_INPUT_XI_EVENT_MASK_KEY_RELEASE |
			XCB_INPUT_XI_EVENT_MASK_BUTTON_PRESS |
			XCB_INPUT_XI_EVENT_MASK_BUTTON_RELEASE |
			XCB_INPUT_XI_EVENT_MASK_MOTION |
			XCB_INPUT_XI_EVENT_MASK_TOUCH_BEGIN |
			XCB_INPUT_XI_EVENT_MASK_TOUCH_END |
			XCB_INPUT_XI_EVENT_MASK_TOUCH_UPDATE,
	};
	xcb_input_xi_select_events(RDP->xcb, output->win, 1, &xinput_mask.head);

	uint32_t present_mask = XCB_PRESENT_EVENT_MASK_IDLE_NOTIFY |
		XCB_PRESENT_EVENT_MASK_COMPLETE_NOTIFY;
	output->present_event_id = xcb_generate_id(RDP->xcb);
	xcb_present_select_input(RDP->xcb, output->present_event_id, output->win,
		present_mask);

	xcb_change_property(RDP->xcb, XCB_PROP_MODE_REPLACE, output->win,
		RDP->atoms.wm_protocols, XCB_ATOM_ATOM, 32, 1,
		&RDP->atoms.wm_delete_window);

	wlr_RDP_output_set_title(wlr_output, NULL);

	xcb_map_window(RDP->xcb, output->win);
	xcb_flush(RDP->xcb);

	wl_list_insert(&RDP->outputs, &output->link);

	wlr_output_update_enabled(wlr_output, true);

	wlr_input_device_init(&output->pointer_dev, WLR_INPUT_DEVICE_POINTER,
		&input_device_impl, "RDP pointer", 0, 0);
	wlr_pointer_init(&output->pointer, &pointer_impl);
	output->pointer_dev.pointer = &output->pointer;
	output->pointer_dev.output_name = strdup(wlr_output->name);

	wlr_input_device_init(&output->touch_dev, WLR_INPUT_DEVICE_TOUCH,
		&input_device_impl, "RDP touch", 0, 0);
	wlr_touch_init(&output->touch, &touch_impl);
	output->touch_dev.touch = &output->touch;
	output->touch_dev.output_name = strdup(wlr_output->name);
	wl_list_init(&output->touchpoints);

	wlr_signal_emit_safe(&RDP->backend.events.new_output, wlr_output);
	wlr_signal_emit_safe(&RDP->backend.events.new_input, &output->pointer_dev);
	wlr_signal_emit_safe(&RDP->backend.events.new_input, &output->touch_dev);

	// Start the rendering loop by requesting the compositor to render a frame
	wlr_output_schedule_frame(wlr_output);

	return wlr_output;
}

void handle_RDP_configure_notify(struct wlr_RDP_output *output,
		xcb_configure_notify_event_t *ev) {
	// ignore events that set an invalid size:
	if (ev->width == 0 || ev->height == 0) {
		wlr_log(WLR_DEBUG,
			"Ignoring RDP configure event for height=%d, width=%d",
			ev->width, ev->height);
		return;
	}

	wlr_output_update_custom_mode(&output->wlr_output, ev->width,
		ev->height, 0);

	// Move the pointer to its new location
	update_RDP_pointer_position(output, output->RDP->time);
}

bool wlr_output_is_RDP(struct wlr_output *wlr_output) {
	return wlr_output->impl == &output_impl;
}

void wlr_RDP_output_set_title(struct wlr_output *output, const char *title) {
	struct wlr_RDP_output *RDP_output = get_RDP_output_from_output(output);

	char wl_title[32];
	if (title == NULL) {
		if (snprintf(wl_title, sizeof(wl_title), "wlroots - %s", output->name) <= 0) {
			return;
		}
		title = wl_title;
	}

	xcb_change_property(RDP_output->RDP->xcb, XCB_PROP_MODE_REPLACE, RDP_output->win,
		RDP_output->RDP->atoms.net_wm_name, RDP_output->RDP->atoms.utf8_string, 8,
		strlen(title), title);
}

static struct wlr_RDP_buffer *get_RDP_buffer(struct wlr_RDP_output *output,
		xcb_pixmap_t pixmap) {
	struct wlr_RDP_buffer *buffer;
	wl_list_for_each(buffer, &output->buffers, link) {
		if (buffer->pixmap == pixmap) {
			return buffer;
		}
	}
	return NULL;
}

void handle_RDP_present_event(struct wlr_RDP_backend *RDP,
		xcb_ge_generic_event_t *event) {
	struct wlr_RDP_output *output;

	switch (event->event_type) {
	case XCB_PRESENT_EVENT_IDLE_NOTIFY:;
		xcb_present_idle_notify_event_t *idle_notify =
			(xcb_present_idle_notify_event_t *)event;

		output = get_RDP_output_from_window_id(RDP, idle_notify->window);
		if (!output) {
			wlr_log(WLR_DEBUG, "Got PresentIdleNotify event for unknown window");
			return;
		}

		struct wlr_RDP_buffer *buffer =
			get_RDP_buffer(output, idle_notify->pixmap);
		if (!buffer) {
			wlr_log(WLR_DEBUG, "Got PresentIdleNotify event for unknown buffer");
			return;
		}

		wlr_buffer_unlock(buffer->buffer); // may destroy buffer
		break;
	case XCB_PRESENT_COMPLETE_NOTIFY:;
		xcb_present_complete_notify_event_t *complete_notify =
			(xcb_present_complete_notify_event_t *)event;

		output = get_RDP_output_from_window_id(RDP, complete_notify->window);
		if (!output) {
			wlr_log(WLR_DEBUG, "Got PresentCompleteNotify event for unknown window");
			return;
		}

		output->last_msc = complete_notify->msc;

		struct timespec t;
		timespec_from_nsec(&t, complete_notify->ust * 1000);

		uint32_t flags = 0;
		if (complete_notify->mode == XCB_PRESENT_COMPLETE_MODE_FLIP) {
			flags |= WLR_OUTPUT_PRESENT_ZERO_COPY;
		}

		bool presented = complete_notify->mode != XCB_PRESENT_COMPLETE_MODE_SKIP;
		struct wlr_output_event_present present_event = {
			.output = &output->wlr_output,
			.commit_seq = complete_notify->serial,
			.presented = presented,
			.when = &t,
			.seq = complete_notify->msc,
			.flags = flags,
		};
		wlr_output_send_present(&output->wlr_output, &present_event);

		wlr_output_send_frame(&output->wlr_output);
		break;
	default:
		wlr_log(WLR_DEBUG, "Unhandled Present event %"PRIu16, event->event_type);
	}
}
