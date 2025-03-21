#ifndef WLR_BACKEND_RDP_H
#define WLR_BACKEND_RDP_H

#include <stdbool.h>

#include <wayland-server-core.h>

#include <wlr/backend.h>
#include <wlr/types/wlr_output.h>

struct wlr_input_device;

/**
 * Creates a new RDP backend. This backend will be created with no outputs;
 * you must use wlr_RDP_output_create() to add them.
 *
 * The `RDP_display` argument is the name of the X Display socket. Set
 * to NULL for the default behaviour of XOpenDisplay().
 */
struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display,
	const char *RDP_display);

/**
 * Adds a new output to this backend. You may remove outputs by destroying them.
 * Note that if called before initializing the backend, this will return NULL
 * and your outputs will be created during initialization (and given to you via
 * the new_output signal).
 */
struct wlr_output *wlr_RDP_output_create(struct wlr_backend *backend);

/**
 * Check whether this backend is an RDP backend.
 */
bool wlr_backend_is_RDP(struct wlr_backend *backend);

/**
 * Check whether this input device is an RDP input device.
 */
bool wlr_input_device_is_RDP(struct wlr_input_device *device);

/**
 * Check whether this output device is an RDP output device.
 */
bool wlr_output_is_RDP(struct wlr_output *output);

/**
 * Sets the title of a struct wlr_output which is an RDP window.
 */
void wlr_RDP_output_set_title(struct wlr_output *output, const char *title);

#endif
