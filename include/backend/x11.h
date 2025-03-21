#ifndef BACKEND_RDP_H
#define BACKEND_RDP_H

#include <wlr/config.h>

#include <stdbool.h>

#include <wayland-server-core.h>
#include <xcb/xcb.h>
#include <xcb/present.h>

#if HAS_XCB_ERRORS
#include <xcb/xcb_errors.h>
#endif

#include <pixman.h>
#include <wlr/backend/RDP.h>
#include <wlr/interfaces/wlr_keyboard.h>
#include <wlr/interfaces/wlr_output.h>
#include <wlr/interfaces/wlr_touch.h>
#include <wlr/types/wlr_pointer.h>
#include <wlr/render/drm_format_set.h>

#define XCB_EVENT_RESPONSE_TYPE_MASK 0x7f

struct wlr_RDP_backend;

struct wlr_RDP_output {
	struct wlr_output wlr_output;
	struct wlr_RDP_backend *RDP;
	struct wl_list link; // wlr_RDP_backend::outputs

	xcb_window_t win;
	xcb_present_event_t present_event_id;

	struct wlr_pointer pointer;

	struct wlr_touch touch;
	struct wl_list touchpoints; // wlr_RDP_touchpoint::link

	struct wl_list buffers; // wlr_RDP_buffer::link

	pixman_region32_t exposed;

	uint64_t last_msc;

	struct {
		struct wlr_swapchain *swapchain;
		xcb_render_picture_t pic;
	} cursor;
};

struct wlr_RDP_touchpoint {
	uint32_t RDP_id;
	int wayland_id;
	struct wl_list link; // wlr_RDP_output::touch_points
};

struct wlr_RDP_backend {
	struct wlr_backend backend;
	struct wl_display *wl_display;
	bool started;

	xcb_connection_t *xcb;
	xcb_screen_t *screen;
	xcb_depth_t *depth;
	xcb_visualid_t visualid;
	xcb_colormap_t colormap;
	xcb_cursor_t transparent_cursor;
	xcb_render_pictformat_t argb32;

	bool have_shm;
	bool have_dri3;
	uint32_t dri3_major_version, dri3_minor_version;

	size_t requested_outputs;
	struct wl_list outputs; // wlr_RDP_output::link

	struct wlr_keyboard keyboard;

	int drm_fd;
	struct wlr_drm_format_set dri3_formats;
	struct wlr_drm_format_set shm_formats;
	const struct wlr_RDP_format *RDP_format;
	struct wlr_drm_format_set primary_dri3_formats;
	struct wlr_drm_format_set primary_shm_formats;
	struct wl_event_source *event_source;

	struct {
		xcb_atom_t wm_protocols;
		xcb_atom_t wm_delete_window;
		xcb_atom_t net_wm_name;
		xcb_atom_t utf8_string;
		xcb_atom_t variable_refresh;
	} atoms;

	// The time we last received an event
	xcb_timestamp_t time;

#if HAS_XCB_ERRORS
	xcb_errors_context_t *errors_context;
#endif

	uint8_t present_opcode;
	uint8_t xinput_opcode;

	struct wl_listener display_destroy;
};

struct wlr_RDP_buffer {
	struct wlr_RDP_backend *RDP;
	struct wlr_buffer *buffer;
	xcb_pixmap_t pixmap;
	struct wl_list link; // wlr_RDP_output::buffers
	struct wl_listener buffer_destroy;
	size_t n_busy;
};

struct wlr_RDP_format {
	uint32_t drm;
	uint8_t depth, bpp;
};

struct wlr_RDP_backend *get_RDP_backend_from_backend(
	struct wlr_backend *wlr_backend);
struct wlr_RDP_output *get_RDP_output_from_window_id(
	struct wlr_RDP_backend *RDP, xcb_window_t window);

extern const struct wlr_keyboard_impl RDP_keyboard_impl;
extern const struct wlr_pointer_impl RDP_pointer_impl;
extern const struct wlr_touch_impl RDP_touch_impl;

void handle_RDP_xinput_event(struct wlr_RDP_backend *RDP,
		xcb_ge_generic_event_t *event);
void update_RDP_pointer_position(struct wlr_RDP_output *output,
	xcb_timestamp_t time);

void handle_RDP_configure_notify(struct wlr_RDP_output *output,
	xcb_configure_notify_event_t *event);
void handle_RDP_present_event(struct wlr_RDP_backend *RDP,
	xcb_ge_generic_event_t *event);

#endif
