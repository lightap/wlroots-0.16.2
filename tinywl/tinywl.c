#define _POSIX_C_SOURCE 200112L
#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <wayland-server-core.h>
#include <wlr/backend.h>
#include <wlr/render/allocator.h>
#include <wlr/render/wlr_renderer.h>
#include <wlr/types/wlr_cursor.h>
#include <wlr/types/wlr_compositor.h>
#include <wlr/types/wlr_data_device.h>
#include <wlr/types/wlr_input_device.h>
#include <wlr/types/wlr_keyboard.h>
#include <wlr/types/wlr_output.h>
#include <wlr/types/wlr_output_layout.h>
#include <wlr/types/wlr_pointer.h>
#include <wlr/types/wlr_scene.h>
#include <wlr/types/wlr_seat.h>
#include <wlr/types/wlr_subcompositor.h>
#include <wlr/types/wlr_xcursor_manager.h>
#include <wlr/types/wlr_xdg_shell.h>
#include <wlr/util/log.h>
#include <xkbcommon/xkbcommon.h>
// Add this with other function declarations or near the include statements

struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display);
#include <wlr/render/gles2.h>
#include <wlr/render/allocator.h>
#include <wlr/util/log.h>
#include <wlr/render/drm_format_set.h>
#include <wayland-server-protocol.h>
#include <wlr/backend/RDP.h>


// Handle DRM format definitions for WSL2

// Add this function declaration with other include statements
struct wlr_allocator *wlr_allocator_autocreate(struct wlr_backend *backend, 
                                               struct wlr_renderer *renderer);

// Add this declaration
struct wlr_renderer *wlr_gles2_renderer_create_surfaceless(void);
// Add these with other function declarations
struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display);
struct wlr_renderer *wlr_gles2_renderer_create_surfaceless(void);
struct wlr_allocator *wlr_allocator_autocreate(struct wlr_backend *backend, 
                                               struct wlr_renderer *renderer);
struct wlr_egl *wlr_gles2_renderer_get_egl(struct wlr_renderer *renderer);

struct wlr_allocator *wlr_rdp_allocator_create(struct wlr_renderer *renderer);

bool wlr_egl_make_current(struct wlr_egl *egl);
/* For brevity's sake, struct members are annotated where they are used. */
enum tinywl_cursor_mode {
	TINYWL_CURSOR_PASSTHROUGH,
	TINYWL_CURSOR_MOVE,
	TINYWL_CURSOR_RESIZE,
};

struct tinywl_server {
	struct wl_display *wl_display;
	struct wlr_backend *backend;
	struct wlr_renderer *renderer;
	struct wlr_allocator *allocator;
	struct wlr_scene *scene;

	struct wlr_xdg_shell *xdg_shell;
	struct wl_listener new_xdg_surface;
	struct wl_list views;

	struct wlr_cursor *cursor;
	struct wlr_xcursor_manager *cursor_mgr;
	struct wl_listener cursor_motion;
	struct wl_listener cursor_motion_absolute;
	struct wl_listener cursor_button;
	struct wl_listener cursor_axis;
	struct wl_listener cursor_frame;

	struct wlr_seat *seat;
	struct wl_listener new_input;
	struct wl_listener request_cursor;
	struct wl_listener request_set_selection;
	struct wl_list keyboards;
	enum tinywl_cursor_mode cursor_mode;
	struct tinywl_view *grabbed_view;
	double grab_x, grab_y;
	struct wlr_box grab_geobox;
	uint32_t resize_edges;

	struct wlr_output_layout *output_layout;
	struct wl_list outputs;
	struct wl_listener new_output;
};

struct tinywl_output {
	struct wl_list link;
	struct tinywl_server *server;
	struct wlr_output *wlr_output;
	struct wl_listener frame;
	struct wl_listener destroy;
};

struct tinywl_view {
	struct wl_list link;
	struct tinywl_server *server;
	struct wlr_xdg_toplevel *xdg_toplevel;
	struct wlr_scene_tree *scene_tree;
	struct wl_listener map;
	struct wl_listener unmap;
	struct wl_listener destroy;
	struct wl_listener request_move;
	struct wl_listener request_resize;
	struct wl_listener request_maximize;
	struct wl_listener request_fullscreen;
	int x, y;
};

struct tinywl_keyboard {
	struct wl_list link;
	struct tinywl_server *server;
	struct wlr_keyboard *wlr_keyboard;

	struct wl_listener modifiers;
	struct wl_listener key;
	struct wl_listener destroy;
};

static void focus_view(struct tinywl_view *view, struct wlr_surface *surface) {
	/* Note: this function only deals with keyboard focus. */
	if (view == NULL) {
		return;
	}
	struct tinywl_server *server = view->server;
	struct wlr_seat *seat = server->seat;
	struct wlr_surface *prev_surface = seat->keyboard_state.focused_surface;
	if (prev_surface == surface) {
		/* Don't re-focus an already focused surface. */
		return;
	}
	if (prev_surface) {
		/*
		 * Deactivate the previously focused surface. This lets the client know
		 * it no longer has focus and the client will repaint accordingly, e.g.
		 * stop displaying a caret.
		 */
		struct wlr_xdg_surface *previous = wlr_xdg_surface_from_wlr_surface(
					seat->keyboard_state.focused_surface);
		assert(previous->role == WLR_XDG_SURFACE_ROLE_TOPLEVEL);
		wlr_xdg_toplevel_set_activated(previous->toplevel, false);
	}
	struct wlr_keyboard *keyboard = wlr_seat_get_keyboard(seat);
	/* Move the view to the front */
	wlr_scene_node_raise_to_top(&view->scene_tree->node);
	wl_list_remove(&view->link);
	wl_list_insert(&server->views, &view->link);
	/* Activate the new surface */
	wlr_xdg_toplevel_set_activated(view->xdg_toplevel, true);
	/*
	 * Tell the seat to have the keyboard enter this surface. wlroots will keep
	 * track of this and automatically send key events to the appropriate
	 * clients without additional work on your part.
	 */
	if (keyboard != NULL) {
		wlr_seat_keyboard_notify_enter(seat, view->xdg_toplevel->base->surface,
			keyboard->keycodes, keyboard->num_keycodes, &keyboard->modifiers);
	}
}

static void keyboard_handle_modifiers(
		struct wl_listener *listener, void *data) {
	/* This event is raised when a modifier key, such as shift or alt, is
	 * pressed. We simply communicate this to the client. */
	struct tinywl_keyboard *keyboard =
		wl_container_of(listener, keyboard, modifiers);
	/*
	 * A seat can only have one keyboard, but this is a limitation of the
	 * Wayland protocol - not wlroots. We assign all connected keyboards to the
	 * same seat. You can swap out the underlying wlr_keyboard like this and
	 * wlr_seat handles this transparently.
	 */
	wlr_seat_set_keyboard(keyboard->server->seat, keyboard->wlr_keyboard);
	/* Send modifiers to the client. */
	wlr_seat_keyboard_notify_modifiers(keyboard->server->seat,
		&keyboard->wlr_keyboard->modifiers);
}

static bool handle_keybinding(struct tinywl_server *server, xkb_keysym_t sym) {
	/*
	 * Here we handle compositor keybindings. This is when the compositor is
	 * processing keys, rather than passing them on to the client for its own
	 * processing.
	 *
	 * This function assumes Alt is held down.
	 */
	switch (sym) {
	case XKB_KEY_Escape:
		wl_display_terminate(server->wl_display);
		break;
	case XKB_KEY_F1:
		/* Cycle to the next view */
		if (wl_list_length(&server->views) < 2) {
			break;
		}
		struct tinywl_view *next_view = wl_container_of(
			server->views.prev, next_view, link);
		focus_view(next_view, next_view->xdg_toplevel->base->surface);
		break;
	default:
		return false;
	}
	return true;
}

static void keyboard_handle_key(
		struct wl_listener *listener, void *data) {
	/* This event is raised when a key is pressed or released. */
	struct tinywl_keyboard *keyboard =
		wl_container_of(listener, keyboard, key);
	struct tinywl_server *server = keyboard->server;
	struct wlr_keyboard_key_event *event = data;
	struct wlr_seat *seat = server->seat;

	/* Translate libinput keycode -> xkbcommon */
	uint32_t keycode = event->keycode + 8;
	/* Get a list of keysyms based on the keymap for this keyboard */
	const xkb_keysym_t *syms;
	int nsyms = xkb_state_key_get_syms(
			keyboard->wlr_keyboard->xkb_state, keycode, &syms);

	bool handled = false;
	uint32_t modifiers = wlr_keyboard_get_modifiers(keyboard->wlr_keyboard);
	if ((modifiers & WLR_MODIFIER_ALT) &&
			event->state == WL_KEYBOARD_KEY_STATE_PRESSED) {
		/* If alt is held down and this button was _pressed_, we attempt to
		 * process it as a compositor keybinding. */
		for (int i = 0; i < nsyms; i++) {
			handled = handle_keybinding(server, syms[i]);
		}
	}

	if (!handled) {
		/* Otherwise, we pass it along to the client. */
		wlr_seat_set_keyboard(seat, keyboard->wlr_keyboard);
		wlr_seat_keyboard_notify_key(seat, event->time_msec,
			event->keycode, event->state);
	}
}

static void keyboard_handle_destroy(struct wl_listener *listener, void *data) {
	/* This event is raised by the keyboard base wlr_input_device to signal
	 * the destruction of the wlr_keyboard. It will no longer receive events
	 * and should be destroyed.
	 */
	struct tinywl_keyboard *keyboard =
		wl_container_of(listener, keyboard, destroy);
	wl_list_remove(&keyboard->modifiers.link);
	wl_list_remove(&keyboard->key.link);
	wl_list_remove(&keyboard->destroy.link);
	wl_list_remove(&keyboard->link);
	free(keyboard);
}

static void server_new_keyboard(struct tinywl_server *server,
		struct wlr_input_device *device) {
	struct wlr_keyboard *wlr_keyboard = wlr_keyboard_from_input_device(device);

	struct tinywl_keyboard *keyboard =
		calloc(1, sizeof(struct tinywl_keyboard));
	keyboard->server = server;
	keyboard->wlr_keyboard = wlr_keyboard;

	/* We need to prepare an XKB keymap and assign it to the keyboard. This
	 * assumes the defaults (e.g. layout = "us"). */
	struct xkb_context *context = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
	struct xkb_keymap *keymap = xkb_keymap_new_from_names(context, NULL,
		XKB_KEYMAP_COMPILE_NO_FLAGS);

	wlr_keyboard_set_keymap(wlr_keyboard, keymap);
	xkb_keymap_unref(keymap);
	xkb_context_unref(context);
	wlr_keyboard_set_repeat_info(wlr_keyboard, 25, 600);

	/* Here we set up listeners for keyboard events. */
	keyboard->modifiers.notify = keyboard_handle_modifiers;
	wl_signal_add(&wlr_keyboard->events.modifiers, &keyboard->modifiers);
	keyboard->key.notify = keyboard_handle_key;
	wl_signal_add(&wlr_keyboard->events.key, &keyboard->key);
	keyboard->destroy.notify = keyboard_handle_destroy;
	wl_signal_add(&device->events.destroy, &keyboard->destroy);

	wlr_seat_set_keyboard(server->seat, keyboard->wlr_keyboard);

	/* And add the keyboard to our list of keyboards */
	wl_list_insert(&server->keyboards, &keyboard->link);
}

static void server_new_pointer(struct tinywl_server *server,
		struct wlr_input_device *device) {
	/* We don't do anything special with pointers. All of our pointer handling
	 * is proxied through wlr_cursor. On another compositor, you might take this
	 * opportunity to do libinput configuration on the device to set
	 * acceleration, etc. */
	wlr_cursor_attach_input_device(server->cursor, device);
}

static void server_new_input(struct wl_listener *listener, void *data) {
	/* This event is raised by the backend when a new input device becomes
	 * available. */
	struct tinywl_server *server =
		wl_container_of(listener, server, new_input);
	struct wlr_input_device *device = data;
	switch (device->type) {
	case WLR_INPUT_DEVICE_KEYBOARD:
		server_new_keyboard(server, device);
		break;
	case WLR_INPUT_DEVICE_POINTER:
		server_new_pointer(server, device);
		break;
	default:
		break;
	}
	/* We need to let the wlr_seat know what our capabilities are, which is
	 * communiciated to the client. In TinyWL we always have a cursor, even if
	 * there are no pointer devices, so we always include that capability. */
	uint32_t caps = WL_SEAT_CAPABILITY_POINTER;
	if (!wl_list_empty(&server->keyboards)) {
		caps |= WL_SEAT_CAPABILITY_KEYBOARD;
	}
	wlr_seat_set_capabilities(server->seat, caps);
}

static void seat_request_cursor(struct wl_listener *listener, void *data) {
	struct tinywl_server *server = wl_container_of(
			listener, server, request_cursor);
	/* This event is raised by the seat when a client provides a cursor image */
	struct wlr_seat_pointer_request_set_cursor_event *event = data;
	struct wlr_seat_client *focused_client =
		server->seat->pointer_state.focused_client;
	/* This can be sent by any client, so we check to make sure this one is
	 * actually has pointer focus first. */
	if (focused_client == event->seat_client) {
		/* Once we've vetted the client, we can tell the cursor to use the
		 * provided surface as the cursor image. It will set the hardware cursor
		 * on the output that it's currently on and continue to do so as the
		 * cursor moves between outputs. */
		wlr_cursor_set_surface(server->cursor, event->surface,
				event->hotspot_x, event->hotspot_y);
	}
}

static void seat_request_set_selection(struct wl_listener *listener, void *data) {
	/* This event is raised by the seat when a client wants to set the selection,
	 * usually when the user copies something. wlroots allows compositors to
	 * ignore such requests if they so choose, but in tinywl we always honor
	 */
	struct tinywl_server *server = wl_container_of(
			listener, server, request_set_selection);
	struct wlr_seat_request_set_selection_event *event = data;
	wlr_seat_set_selection(server->seat, event->source, event->serial);
}

static struct tinywl_view *desktop_view_at(
		struct tinywl_server *server, double lx, double ly,
		struct wlr_surface **surface, double *sx, double *sy) {
	/* This returns the topmost node in the scene at the given layout coords.
	 * we only care about surface nodes as we are specifically looking for a
	 * surface in the surface tree of a tinywl_view. */
	struct wlr_scene_node *node = wlr_scene_node_at(
		&server->scene->tree.node, lx, ly, sx, sy);
	if (node == NULL || node->type != WLR_SCENE_NODE_BUFFER) {
		return NULL;
	}
	struct wlr_scene_buffer *scene_buffer = wlr_scene_buffer_from_node(node);
	struct wlr_scene_surface *scene_surface =
		wlr_scene_surface_from_buffer(scene_buffer);
	if (!scene_surface) {
		return NULL;
	}

	*surface = scene_surface->surface;
	/* Find the node corresponding to the tinywl_view at the root of this
	 * surface tree, it is the only one for which we set the data field. */
	struct wlr_scene_tree *tree = node->parent;
	while (tree != NULL && tree->node.data == NULL) {
		tree = tree->node.parent;
	}
	return tree->node.data;
}

static void reset_cursor_mode(struct tinywl_server *server) {
	/* Reset the cursor mode to passthrough. */
	server->cursor_mode = TINYWL_CURSOR_PASSTHROUGH;
	server->grabbed_view = NULL;
}

static void process_cursor_move(struct tinywl_server *server, uint32_t time) {
	/* Move the grabbed view to the new position. */
	struct tinywl_view *view = server->grabbed_view;
	view->x = server->cursor->x - server->grab_x;
	view->y = server->cursor->y - server->grab_y;
	wlr_scene_node_set_position(&view->scene_tree->node, view->x, view->y);
}

static void process_cursor_resize(struct tinywl_server *server, uint32_t time) {
	/*
	 * Resizing the grabbed view can be a little bit complicated, because we
	 * could be resizing from any corner or edge. This not only resizes the view
	 * on one or two axes, but can also move the view if you resize from the top
	 * or left edges (or top-left corner).
	 *
	 * Note that I took some shortcuts here. In a more fleshed-out compositor,
	 * you'd wait for the client to prepare a buffer at the new size, then
	 * commit any movement that was prepared.
	 */
	struct tinywl_view *view = server->grabbed_view;
	double border_x = server->cursor->x - server->grab_x;
	double border_y = server->cursor->y - server->grab_y;
	int new_left = server->grab_geobox.x;
	int new_right = server->grab_geobox.x + server->grab_geobox.width;
	int new_top = server->grab_geobox.y;
	int new_bottom = server->grab_geobox.y + server->grab_geobox.height;

	if (server->resize_edges & WLR_EDGE_TOP) {
		new_top = border_y;
		if (new_top >= new_bottom) {
			new_top = new_bottom - 1;
		}
	} else if (server->resize_edges & WLR_EDGE_BOTTOM) {
		new_bottom = border_y;
		if (new_bottom <= new_top) {
			new_bottom = new_top + 1;
		}
	}
	if (server->resize_edges & WLR_EDGE_LEFT) {
		new_left = border_x;
		if (new_left >= new_right) {
			new_left = new_right - 1;
		}
	} else if (server->resize_edges & WLR_EDGE_RIGHT) {
		new_right = border_x;
		if (new_right <= new_left) {
			new_right = new_left + 1;
		}
	}

	struct wlr_box geo_box;
	wlr_xdg_surface_get_geometry(view->xdg_toplevel->base, &geo_box);
	view->x = new_left - geo_box.x;
	view->y = new_top - geo_box.y;
	wlr_scene_node_set_position(&view->scene_tree->node, view->x, view->y);

	int new_width = new_right - new_left;
	int new_height = new_bottom - new_top;
	wlr_xdg_toplevel_set_size(view->xdg_toplevel, new_width, new_height);
}

static void process_cursor_motion(struct tinywl_server *server, uint32_t time) {
	/* If the mode is non-passthrough, delegate to those functions. */
	if (server->cursor_mode == TINYWL_CURSOR_MOVE) {
		process_cursor_move(server, time);
		return;
	} else if (server->cursor_mode == TINYWL_CURSOR_RESIZE) {
		process_cursor_resize(server, time);
		return;
	}

	/* Otherwise, find the view under the pointer and send the event along. */
	double sx, sy;
	struct wlr_seat *seat = server->seat;
	struct wlr_surface *surface = NULL;
	struct tinywl_view *view = desktop_view_at(server,
			server->cursor->x, server->cursor->y, &surface, &sx, &sy);
	if (!view) {
		/* If there's no view under the cursor, set the cursor image to a
		 * default. This is what makes the cursor image appear when you move it
		 * around the screen, not over any views. */
		wlr_xcursor_manager_set_cursor_image(
				server->cursor_mgr, "left_ptr", server->cursor);
	}
	if (surface) {
		/*
		 * Send pointer enter and motion events.
		 *
		 * The enter event gives the surface "pointer focus", which is distinct
		 * from keyboard focus. You get pointer focus by moving the pointer over
		 * a window.
		 *
		 * Note that wlroots will avoid sending duplicate enter/motion events if
		 * the surface has already has pointer focus or if the client is already
		 * aware of the coordinates passed.
		 */
		wlr_seat_pointer_notify_enter(seat, surface, sx, sy);
		wlr_seat_pointer_notify_motion(seat, time, sx, sy);
	} else {
		/* Clear pointer focus so future button events and such are not sent to
		 * the last client to have the cursor over it. */
		wlr_seat_pointer_clear_focus(seat);
	}
}

static void server_cursor_motion(struct wl_listener *listener, void *data) {
	/* This event is forwarded by the cursor when a pointer emits a _relative_
	 * pointer motion event (i.e. a delta) */
	struct tinywl_server *server =
		wl_container_of(listener, server, cursor_motion);
	struct wlr_pointer_motion_event *event = data;
	/* The cursor doesn't move unless we tell it to. The cursor automatically
	 * handles constraining the motion to the output layout, as well as any
	 * special configuration applied for the specific input device which
	 * generated the event. You can pass NULL for the device if you want to move
	 * the cursor around without any input. */
	wlr_cursor_move(server->cursor, &event->pointer->base,
			event->delta_x, event->delta_y);
	process_cursor_motion(server, event->time_msec);
}

static void server_cursor_motion_absolute(
		struct wl_listener *listener, void *data) {
	/* This event is forwarded by the cursor when a pointer emits an _absolute_
	 * motion event, from 0..1 on each axis. This happens, for example, when
	 * wlroots is running under a Wayland window rather than KMS+DRM, and you
	 * move the mouse over the window. You could enter the window from any edge,
	 * so we have to warp the mouse there. There is also some hardware which
	 * emits these events. */
	struct tinywl_server *server =
		wl_container_of(listener, server, cursor_motion_absolute);
	struct wlr_pointer_motion_absolute_event *event = data;
	wlr_cursor_warp_absolute(server->cursor, &event->pointer->base, event->x,
		event->y);
	process_cursor_motion(server, event->time_msec);
}

static void server_cursor_button(struct wl_listener *listener, void *data) {
	/* This event is forwarded by the cursor when a pointer emits a button
	 * event. */
	struct tinywl_server *server =
		wl_container_of(listener, server, cursor_button);
	struct wlr_pointer_button_event *event = data;
	/* Notify the client with pointer focus that a button press has occurred */
	wlr_seat_pointer_notify_button(server->seat,
			event->time_msec, event->button, event->state);
	double sx, sy;
	struct wlr_surface *surface = NULL;
	struct tinywl_view *view = desktop_view_at(server,
			server->cursor->x, server->cursor->y, &surface, &sx, &sy);
	if (event->state == WLR_BUTTON_RELEASED) {
		/* If you released any buttons, we exit interactive move/resize mode. */
		reset_cursor_mode(server);
	} else {
		/* Focus that client if the button was _pressed_ */
		focus_view(view, surface);
	}
}

static void server_cursor_axis(struct wl_listener *listener, void *data) {
	/* This event is forwarded by the cursor when a pointer emits an axis event,
	 * for example when you move the scroll wheel. */
	struct tinywl_server *server =
		wl_container_of(listener, server, cursor_axis);
	struct wlr_pointer_axis_event *event = data;
	/* Notify the client with pointer focus of the axis event. */
	wlr_seat_pointer_notify_axis(server->seat,
			event->time_msec, event->orientation, event->delta,
			event->delta_discrete, event->source);
}

static void server_cursor_frame(struct wl_listener *listener, void *data) {
	/* This event is forwarded by the cursor when a pointer emits an frame
	 * event. Frame events are sent after regular pointer events to group
	 * multiple events together. For instance, two axis events may happen at the
	 * same time, in which case a frame event won't be sent in between. */
	struct tinywl_server *server =
		wl_container_of(listener, server, cursor_frame);
	/* Notify the client with pointer focus of the frame event. */
	wlr_seat_pointer_notify_frame(server->seat);
}
/*
static void output_frame(struct wl_listener *listener, void *data) {
	// This function is called every time an output is ready to display a frame,
	 // generally at the output's refresh rate (e.g. 60Hz). 
	struct tinywl_output *output = wl_container_of(listener, output, frame);
	struct wlr_scene *scene = output->server->scene;

	struct wlr_scene_output *scene_output = wlr_scene_get_scene_output(
		scene, output->wlr_output);

	// Render the scene if needed and commit the output 
	wlr_scene_output_commit(scene_output);

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	wlr_scene_output_send_frame_done(scene_output, &now);
}*/

// Implement minimal placeholder functions to avoid unused warnings
/*
static void output_frame(struct wl_listener *listener, void *data) {
    struct tinywl_output *output = wl_container_of(listener, output, frame);
    wlr_log(WLR_DEBUG, "Output frame event");
}*/

static void output_frame(struct wl_listener *listener, void *data) {
    struct tinywl_output *output = wl_container_of(listener, output, frame);
    struct tinywl_server *server = output->server;

    // Get the scene output for this specific output
    struct wlr_scene_output *scene_output = wlr_scene_get_scene_output(
        server->scene, output->wlr_output);

    if (!scene_output) {
        wlr_log(WLR_ERROR, "Failed to get scene output");
        return;
    }

    // Send frame done event with current time
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    
    // Simply send frame done without forcing any commits
    wlr_scene_output_send_frame_done(scene_output, &now);

    wlr_log(WLR_DEBUG, "Frame update");
}
/*
static void output_destroy(struct wl_listener *listener, void *data) {
	struct tinywl_output *output = wl_container_of(listener, output, destroy);

	wl_list_remove(&output->frame.link);
	wl_list_remove(&output->destroy.link);
	wl_list_remove(&output->link);
	free(output);
}*/

static void output_destroy(struct wl_listener *listener, void *data) {
    struct tinywl_output *output = wl_container_of(listener, output, destroy);
    wlr_log(WLR_DEBUG, "Output destroy event");
    
    wl_list_remove(&output->frame.link);
    wl_list_remove(&output->destroy.link);
    wl_list_remove(&output->link);
    free(output);
}
/*
static void server_new_output(struct wl_listener *listener, void *data) {
	// This event is raised by the backend when a new output (aka a display or
	 // monitor) becomes available. 
	struct tinywl_server *server =
		wl_container_of(listener, server, new_output);
	struct wlr_output *wlr_output = data;

	// Configures the output created by the backend to use our allocator
	 // and our renderer. Must be done once, before commiting the output 
	wlr_output_init_render(wlr_output, server->allocator, server->renderer);

	//Some backends don't have modes. DRM+KMS does, and we need to set a mode
	 // before we can use the output. The mode is a tuple of (width, height,
	 // refresh rate), and each monitor supports only a specific set of modes. We
	// just pick the monitor's preferred mode, a more sophisticated compositor
	 // would let the user configure it. 
	if (!wl_list_empty(&wlr_output->modes)) {
		struct wlr_output_mode *mode = wlr_output_preferred_mode(wlr_output);
		wlr_output_set_mode(wlr_output, mode);
		wlr_output_enable(wlr_output, true);
		if (!wlr_output_commit(wlr_output)) {
			return;
		}
	}

	// Allocates and configures our state for this output 
	struct tinywl_output *output =
		calloc(1, sizeof(struct tinywl_output));
	output->wlr_output = wlr_output;
	output->server = server;
	// Sets up a listener for the frame notify event. 
	output->frame.notify = output_frame;
	wl_signal_add(&wlr_output->events.frame, &output->frame);

	//Sets up a listener for the destroy notify event. 
	output->destroy.notify = output_destroy;
	wl_signal_add(&wlr_output->events.destroy, &output->destroy);

	wl_list_insert(&server->outputs, &output->link);

	// Adds this to the output layout. The add_auto function arranges outputs
	// from left-to-right in the order they appear. A more sophisticated
	 // compositor would let the user configure the arrangement of outputs in the
	 // layout.
	 //
	 // The output layout utility automatically adds a wl_output global to the
	 // display, which Wayland clients can see to find out information about the
	// output (such as DPI, scale factor, manufacturer, etc).
	 //
	wlr_output_layout_add_auto(server->output_layout, wlr_output);
}*/
/*
static void server_new_output(struct wl_listener *listener, void *data) {
    struct tinywl_server *server =
        wl_container_of(listener, server, new_output);
    struct wlr_output *wlr_output = data;

    wlr_log(WLR_INFO, "Initializing new output");

    // Explicitly check if we have a renderer and allocator 
    if (!server->renderer) {
        wlr_log(WLR_ERROR, "No renderer available for output");
        return;
    }

    if (!server->allocator) {
        wlr_log(WLR_ERROR, "No allocator available for output");
        return;
    }

    wlr_log(WLR_DEBUG, "Renderer: %p, Allocator: %p", 
            (void*)server->renderer, (void*)server->allocator);

    // Attempt to create a compatible allocator 
    struct wlr_allocator *compatible_allocator = NULL;
    
    // Try multiple ways to create a compatible allocator
    const uint32_t cap_attempts[] = {
        WLR_BUFFER_CAP_DATA_PTR | WLR_BUFFER_CAP_SHM,
        WLR_BUFFER_CAP_DATA_PTR,
        WLR_BUFFER_CAP_SHM
    };

    for (size_t i = 0; i < sizeof(cap_attempts) / sizeof(cap_attempts[0]); i++) {
        wlr_log(WLR_DEBUG, "Attempting allocator creation with caps: 0x%x", cap_attempts[i]);
        
        // For RDP, we might need a custom allocator creation approach
        compatible_allocator = wlr_rdp_allocator_create(server->renderer);
        
        if (compatible_allocator) {
            wlr_log(WLR_DEBUG, "Created RDP allocator with caps: 0x%x", 
                    compatible_allocator->buffer_caps);
            break;
        }
    }

    if (!compatible_allocator) {
        wlr_log(WLR_ERROR, "Failed to create compatible allocator");
        return;
    }

    // Attempt to initialize output rendering 
    if (!wlr_output_init_render(wlr_output, compatible_allocator, server->renderer)) {
        wlr_log(WLR_ERROR, "Failed to initialize output rendering");
        wlr_allocator_destroy(compatible_allocator);
        return;
    }

    // Replace the original allocator if needed 
    if (server->allocator != compatible_allocator) {
        wlr_allocator_destroy(server->allocator);
        server->allocator = compatible_allocator;
    }

    // Set output parameters explicitly 
    wlr_output_set_custom_mode(wlr_output, 1280, 720, 60000);
    wlr_output_enable(wlr_output, true);

    // Commit output 
    if (!wlr_output_commit(wlr_output)) {
        wlr_log(WLR_ERROR, "Failed to commit output");
        return;
    }

    // Allocate and configure output state 
    struct tinywl_output *output = calloc(1, sizeof(struct tinywl_output));
    if (!output) {
        wlr_log(WLR_ERROR, "Failed to allocate output structure");
        return;
    }

    output->wlr_output = wlr_output;
    output->server = server;

    // Set up frame listener 
    output->frame.notify = output_frame;
    wl_signal_add(&wlr_output->events.frame, &output->frame);

    // Set up destroy listener
    output->destroy.notify = output_destroy;
    wl_signal_add(&wlr_output->events.destroy, &output->destroy);

    // Add to server's outputs list 
    wl_list_insert(&server->outputs, &output->link);

    // Add to output layout 
    wlr_output_layout_add_auto(server->output_layout, wlr_output);

    wlr_log(WLR_INFO, "Output initialized successfully: %dx%d @ %d Hz", 
            wlr_output->width, wlr_output->height, wlr_output->refresh / 1000);
}*/
#define WLR_BUFFER_CAP_DATA_PTR (1 << 0)
#define WLR_BUFFER_CAP_DMABUF   (1 << 1)
#define WLR_BUFFER_CAP_SHM      (1 << 2)

#include <wlr/render/wlr_renderer.h>

#include <wlr/types/wlr_output.h>
#include <wlr/render/wlr_renderer.h>

// Add this function prototype with other function declarations
const struct wlr_drm_format_set *wlr_renderer_get_render_formats(struct wlr_renderer *renderer);
/*
static void server_new_output(struct wl_listener *listener, void *data) {
    struct tinywl_server *server =
        wl_container_of(listener, server, new_output);
    struct wlr_output *wlr_output = data;

    wlr_log(WLR_INFO, "Initializing new RDP output with surfaceless EGL/Zink");

    // Verify renderer and allocator existence 
    if (!server->renderer || !server->allocator) {
        wlr_log(WLR_ERROR, "No renderer or allocator available");
        return;
    }

    // Configure output mode first 
    wlr_output_set_custom_mode(wlr_output, 1280, 720, 60000);
    wlr_output_enable(wlr_output, true);

    // Create RDP-specific allocator 
    struct wlr_allocator *new_allocator = wlr_rdp_allocator_create(server->renderer);
    if (!new_allocator) {
        wlr_log(WLR_ERROR, "Failed to create allocator");
        return;
    }

    // Initialize output rendering 
    if (!wlr_output_init_render(wlr_output, new_allocator, server->renderer)) {
        wlr_log(WLR_ERROR, "Failed to initialize output rendering");
        wlr_allocator_destroy(new_allocator);
        return;
    }

    // Replace old allocator 
    if (server->allocator) {
        wlr_allocator_destroy(server->allocator);
    }
    server->allocator = new_allocator;

    // Try to let renderer pick its preferred format 
    if (!wlr_output_test(wlr_output)) {
        wlr_log(WLR_DEBUG, "Default format test failed, trying explicit formats");
        
        // Simple format attempt matching EGL config: RGB888 
        const uint32_t formats[] = {
            0x34325258,  // XR24 (XRGB8888)
            0x34324152,  // AR24 (ARGB8888)
            0x34324258,  // XB24 (XBGR8888)
        };

        bool format_found = false;
        for (size_t i = 0; i < sizeof(formats)/sizeof(formats[0]); i++) {
            wlr_output_set_render_format(wlr_output, formats[i]);
            if (wlr_output_test(wlr_output)) {
                format_found = true;
                wlr_log(WLR_INFO, "Found compatible format: 0x%x", formats[i]);
                break;
            }
        }

        if (!format_found) {
            wlr_log(WLR_ERROR, "No compatible format found");
            return;
        }
    }

    // Commit output configuration 
    if (!wlr_output_commit(wlr_output)) {
        wlr_log(WLR_ERROR, "Failed to commit output configuration");
        return;
    }

    // Setup output structure 
    struct tinywl_output *output = calloc(1, sizeof(struct tinywl_output));
    if (!output) {
        wlr_log(WLR_ERROR, "Failed to allocate output structure");
        return;
    }

    output->wlr_output = wlr_output;
    output->server = server;

    output->frame.notify = output_frame;
    wl_signal_add(&wlr_output->events.frame, &output->frame);

    output->destroy.notify = output_destroy;
    wl_signal_add(&wlr_output->events.destroy, &output->destroy);

    wl_list_insert(&server->outputs, &output->link);
    wlr_output_layout_add_auto(server->output_layout, wlr_output);

    wlr_log(WLR_INFO, "RDP output initialized successfully with Zink surfaceless renderer");
}*/
static void server_new_output(struct wl_listener *listener, void *data) {
    struct tinywl_server *server = wl_container_of(listener, server, new_output);
    struct wlr_output *wlr_output = data;

    wlr_log(WLR_INFO, "Initializing RDP output with surfaceless EGL/Zink");

    // Diagnostic logging of renderer and backend
    wlr_log(WLR_DEBUG, "Backend: %p, Renderer: %p", 
            (void*)wlr_output->backend, (void*)server->renderer);

    // Create RDP-specific allocator with full capabilities
    struct wlr_allocator *new_allocator = wlr_rdp_allocator_create(server->renderer);
    if (!new_allocator) {
        wlr_log(WLR_ERROR, "Failed to create RDP allocator");
        return;
    }

    // Verify allocator capabilities
    uint32_t buffer_caps = new_allocator->buffer_caps;
    wlr_log(WLR_DEBUG, "Allocator buffer capabilities: 0x%x", buffer_caps);

    // Initialize output rendering
    if (!wlr_output_init_render(wlr_output, new_allocator, server->renderer)) {
        wlr_log(WLR_ERROR, "Failed to initialize output rendering");
        wlr_allocator_destroy(new_allocator);
        return;
    }

    // Replace old allocator
    if (server->allocator) {
        wlr_allocator_destroy(server->allocator);
    }
    server->allocator = new_allocator;

    // Try multiple formats with comprehensive logging
    const uint32_t formats[] = {
        0x34325258,  // XRGB8888 (XR24)
        0x34324152,  // ARGB8888 (AR24)
        0x34324258,  // XBGR8888 (XB24)
        WL_SHM_FORMAT_XRGB8888,
        WL_SHM_FORMAT_ARGB8888
    };

    bool output_initialized = false;
    for (size_t i = 0; i < sizeof(formats)/sizeof(formats[0]); i++) {
        wlr_log(WLR_DEBUG, "Attempting format: 0x%x", formats[i]);

        // Reset output configuration
        wlr_output_set_custom_mode(wlr_output, 1280, 720, 60000);
        wlr_output_enable(wlr_output, true);
        wlr_output_set_render_format(wlr_output, formats[i]);

        // Multiple test attempts
        int test_attempts = 2;
        while (test_attempts-- > 0) {
            // Attempt output test
            if (wlr_output_test(wlr_output)) {
                wlr_log(WLR_INFO, "Output test passed for format 0x%x", formats[i]);
                
                // Attempt commit
                if (wlr_output_commit(wlr_output)) {
                    wlr_log(WLR_INFO, "Successfully committed output with format 0x%x", formats[i]);
                    output_initialized = true;
                    break;
                }
            }
        }

        if (output_initialized) break;
    }

    // If no format worked, log detailed diagnostics
    if (!output_initialized) {
        wlr_log(WLR_ERROR, "Failed to initialize output with any format");
        wlr_log(WLR_DEBUG, "Renderer details:");
        wlr_log(WLR_DEBUG, "  Renderer pointer: %p", (void*)server->renderer);
        wlr_log(WLR_DEBUG, "  Allocator pointer: %p", (void*)new_allocator);
      //  return;
    }

    // Create output structure
    struct tinywl_output *output = calloc(1, sizeof(struct tinywl_output));
    if (!output) {
        wlr_log(WLR_ERROR, "Failed to allocate output structure");
        return;
    }

    output->wlr_output = wlr_output;
    output->server = server;

    // Set up listeners
    output->frame.notify = output_frame;
    wl_signal_add(&wlr_output->events.frame, &output->frame);

    output->destroy.notify = output_destroy;
    wl_signal_add(&wlr_output->events.destroy, &output->destroy);

    // Add to lists
    wl_list_insert(&server->outputs, &output->link);
    wlr_output_layout_add_auto(server->output_layout, wlr_output);

    wlr_log(WLR_INFO, "RDP output initialized successfully");
}
/*
static void xdg_toplevel_map(struct wl_listener *listener, void *data) {
	// Called when the surface is mapped, or ready to display on-screen. 
	struct tinywl_view *view = wl_container_of(listener, view, map);

	wl_list_insert(&view->server->views, &view->link);

	focus_view(view, view->xdg_toplevel->base->surface);
}*/

static void xdg_toplevel_map(struct wl_listener *listener, void *data) {
    /* Called when the surface is mapped, or ready to display on-screen. */
    struct tinywl_view *view = wl_container_of(listener, view, map);

    wl_list_insert(&view->server->views, &view->link);

    focus_view(view, view->xdg_toplevel->base->surface);

    // Send frame done with a valid timespec
    struct wlr_surface *surface = view->xdg_toplevel->base->surface;
    if (surface) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        wlr_surface_send_frame_done(surface, &now);
        
        wlr_log(WLR_ERROR, "Sent frame done for surface %p", (void*)surface);
    }
}
static void xdg_toplevel_unmap(struct wl_listener *listener, void *data) {
	/* Called when the surface is unmapped, and should no longer be shown. */
	struct tinywl_view *view = wl_container_of(listener, view, unmap);

	/* Reset the cursor mode if the grabbed view was unmapped. */
	if (view == view->server->grabbed_view) {
		reset_cursor_mode(view->server);
	}

	wl_list_remove(&view->link);
}

static void xdg_toplevel_destroy(struct wl_listener *listener, void *data) {
	/* Called when the surface is destroyed and should never be shown again. */
	struct tinywl_view *view = wl_container_of(listener, view, destroy);

	wl_list_remove(&view->map.link);
	wl_list_remove(&view->unmap.link);
	wl_list_remove(&view->destroy.link);
	wl_list_remove(&view->request_move.link);
	wl_list_remove(&view->request_resize.link);
	wl_list_remove(&view->request_maximize.link);
	wl_list_remove(&view->request_fullscreen.link);

	free(view);
}

static void begin_interactive(struct tinywl_view *view,
		enum tinywl_cursor_mode mode, uint32_t edges) {
	/* This function sets up an interactive move or resize operation, where the
	 * compositor stops propegating pointer events to clients and instead
	 * consumes them itself, to move or resize windows. */
	struct tinywl_server *server = view->server;
	struct wlr_surface *focused_surface =
		server->seat->pointer_state.focused_surface;
	if (view->xdg_toplevel->base->surface !=
			wlr_surface_get_root_surface(focused_surface)) {
		/* Deny move/resize requests from unfocused clients. */
		return;
	}
	server->grabbed_view = view;
	server->cursor_mode = mode;

	if (mode == TINYWL_CURSOR_MOVE) {
		server->grab_x = server->cursor->x - view->x;
		server->grab_y = server->cursor->y - view->y;
	} else {
		struct wlr_box geo_box;
		wlr_xdg_surface_get_geometry(view->xdg_toplevel->base, &geo_box);

		double border_x = (view->x + geo_box.x) +
			((edges & WLR_EDGE_RIGHT) ? geo_box.width : 0);
		double border_y = (view->y + geo_box.y) +
			((edges & WLR_EDGE_BOTTOM) ? geo_box.height : 0);
		server->grab_x = server->cursor->x - border_x;
		server->grab_y = server->cursor->y - border_y;

		server->grab_geobox = geo_box;
		server->grab_geobox.x += view->x;
		server->grab_geobox.y += view->y;

		server->resize_edges = edges;
	}
}

static void xdg_toplevel_request_move(
		struct wl_listener *listener, void *data) {
	/* This event is raised when a client would like to begin an interactive
	 * move, typically because the user clicked on their client-side
	 * decorations. Note that a more sophisticated compositor should check the
	 * provided serial against a list of button press serials sent to this
	 * client, to prevent the client from requesting this whenever they want. */
	struct tinywl_view *view = wl_container_of(listener, view, request_move);
	begin_interactive(view, TINYWL_CURSOR_MOVE, 0);
}

static void xdg_toplevel_request_resize(
		struct wl_listener *listener, void *data) {
	/* This event is raised when a client would like to begin an interactive
	 * resize, typically because the user clicked on their client-side
	 * decorations. Note that a more sophisticated compositor should check the
	 * provided serial against a list of button press serials sent to this
	 * client, to prevent the client from requesting this whenever they want. */
	struct wlr_xdg_toplevel_resize_event *event = data;
	struct tinywl_view *view = wl_container_of(listener, view, request_resize);
	begin_interactive(view, TINYWL_CURSOR_RESIZE, event->edges);
}

static void xdg_toplevel_request_maximize(
		struct wl_listener *listener, void *data) {
	/* This event is raised when a client would like to maximize itself,
	 * typically because the user clicked on the maximize button on
	 * client-side decorations. tinywl doesn't support maximization, but
	 * to conform to xdg-shell protocol we still must send a configure.
	 * wlr_xdg_surface_schedule_configure() is used to send an empty reply. */
	struct tinywl_view *view =
		wl_container_of(listener, view, request_maximize);
	wlr_xdg_surface_schedule_configure(view->xdg_toplevel->base);
}

static void xdg_toplevel_request_fullscreen(
		struct wl_listener *listener, void *data) {
	/* Just as with request_maximize, we must send a configure here. */
	struct tinywl_view *view =
		wl_container_of(listener, view, request_fullscreen);
	wlr_xdg_surface_schedule_configure(view->xdg_toplevel->base);
}

static void server_new_xdg_surface(struct wl_listener *listener, void *data) {
	/* This event is raised when wlr_xdg_shell receives a new xdg surface from a
	 * client, either a toplevel (application window) or popup. */
	struct tinywl_server *server =
		wl_container_of(listener, server, new_xdg_surface);
	struct wlr_xdg_surface *xdg_surface = data;

	/* We must add xdg popups to the scene graph so they get rendered. The
	 * wlroots scene graph provides a helper for this, but to use it we must
	 * provide the proper parent scene node of the xdg popup. To enable this,
	 * we always set the user data field of xdg_surfaces to the corresponding
	 * scene node. */
	if (xdg_surface->role == WLR_XDG_SURFACE_ROLE_POPUP) {
		struct wlr_xdg_surface *parent = wlr_xdg_surface_from_wlr_surface(
			xdg_surface->popup->parent);
		struct wlr_scene_tree *parent_tree = parent->data;
		xdg_surface->data = wlr_scene_xdg_surface_create(
			parent_tree, xdg_surface);
		return;
	}
	assert(xdg_surface->role == WLR_XDG_SURFACE_ROLE_TOPLEVEL);

	/* Allocate a tinywl_view for this surface */
	struct tinywl_view *view =
		calloc(1, sizeof(struct tinywl_view));
	view->server = server;
	view->xdg_toplevel = xdg_surface->toplevel;
	view->scene_tree = wlr_scene_xdg_surface_create(
			&view->server->scene->tree, view->xdg_toplevel->base);
	view->scene_tree->node.data = view;
	xdg_surface->data = view->scene_tree;

	/* Listen to the various events it can emit */
	view->map.notify = xdg_toplevel_map;
	wl_signal_add(&xdg_surface->events.map, &view->map);
	view->unmap.notify = xdg_toplevel_unmap;
	wl_signal_add(&xdg_surface->events.unmap, &view->unmap);
	view->destroy.notify = xdg_toplevel_destroy;
	wl_signal_add(&xdg_surface->events.destroy, &view->destroy);

	/* cotd */
	struct wlr_xdg_toplevel *toplevel = xdg_surface->toplevel;
	view->request_move.notify = xdg_toplevel_request_move;
	wl_signal_add(&toplevel->events.request_move, &view->request_move);
	view->request_resize.notify = xdg_toplevel_request_resize;
	wl_signal_add(&toplevel->events.request_resize, &view->request_resize);
	view->request_maximize.notify = xdg_toplevel_request_maximize;
	wl_signal_add(&toplevel->events.request_maximize,
		&view->request_maximize);
	view->request_fullscreen.notify = xdg_toplevel_request_fullscreen;
	wl_signal_add(&toplevel->events.request_fullscreen,
		&view->request_fullscreen);
}
/*
int main(int argc, char *argv[]) {
	wlr_log_init(WLR_DEBUG, NULL);
	char *startup_cmd = NULL;

	int c;
	while ((c = getopt(argc, argv, "s:h")) != -1) {
		switch (c) {
		case 's':
			startup_cmd = optarg;
			break;
		default:
			printf("Usage: %s [-s startup command]\n", argv[0]);
			return 0;
		}
	}
	if (optind < argc) {
		printf("Usage: %s [-s startup command]\n", argv[0]);
		return 0;
	}

	struct tinywl_server server;
	// The Wayland display is managed by libwayland. It handles accepting
	 // clients from the Unix socket, manging Wayland globals, and so on. 
	server.wl_display = wl_display_create();
	// The backend is a wlroots feature which abstracts the underlying input and
	 // output hardware. The autocreate option will choose the most suitable
	 // backend based on the current environment, such as opening an RDP window
	// if an RDP server is running. 
	// The backend is a wlroots feature which abstracts the underlying input and
 // output hardware. The autocreate option will choose the most suitable
 // backend based on the current environment, such as opening an RDP window
 // if an RDP server is running. 
const char *backends_env = getenv("WLR_BACKENDS");
if (backends_env && strcmp(backends_env, "RDP") == 0) {
    // Use RDP-specific backend creation
    server.backend = wlr_RDP_backend_create(server.wl_display);
} else {
    // Default backend autocreation
    server.backend = wlr_backend_autocreate(server.wl_display);
}

if (server.backend == NULL) {
    wlr_log(WLR_ERROR, "failed to create wlr_backend");
    return 1;
}

	// Autocreates a renderer, either Pixman, GLES2 or Vulkan for us. The user
	 // can also specify a renderer using the WLR_RENDERER env var.
	 // The renderer is responsible for defining the various pixel formats it
	 // supports for shared memory, this configures that for clients. 
	// Modify renderer creation for RDP
if (backends_env && strcmp(backends_env, "RDP") == 0) {
    // Use surfaceless renderer specifically for RDP
    server.renderer = wlr_gles2_renderer_create_surfaceless();
} else {
    // Default renderer autocreation
    server.renderer = wlr_renderer_autocreate(server.backend);
}

if (server.renderer == NULL) {
    wlr_log(WLR_ERROR, "failed to create wlr_renderer");
    return 1;
}
	wlr_renderer_init_wl_display(server.renderer, server.wl_display);

	/// Autocreates an allocator for us.
	 // The allocator is the bridge between the renderer and the backend. It
	 // handles the buffer creation, allowing wlroots to render onto the
	 // screen 
	// server.allocator = wlr_allocator_autocreate(server.backend,
		server.renderer);
	if (server.allocator == NULL) {
		wlr_log(WLR_ERROR, "failed to create wlr_allocator");
		return 1;
	}



if (backends_env && strcmp(backends_env, "RDP") == 0) {
    // For RDP backend, use standard allocator creation
    server.allocator = wlr_allocator_autocreate(server.backend, server.renderer);
    
    if (server.allocator == NULL) {
        wlr_log(WLR_ERROR, "Failed to create allocator for RDP backend");
        return 1;
    }
} else {
    // Default backend allocator creation
    server.allocator = wlr_allocator_autocreate(server.backend, server.renderer);
}

if (server.allocator == NULL) {
    wlr_log(WLR_ERROR, "failed to create wlr_allocator");
    return 1;
}
	/// This creates some hands-off wlroots interfaces. The compositor is
	 // necessary for clients to allocate surfaces, the subcompositor allows to
	 // assign the role of subsurfaces to surfaces and the data device manager
	 // handles the clipboard. Each of these wlroots interfaces has room for you
	 // to dig your fingers in and play with their behavior if you want. Note that
	 // the clients cannot set the selection directly without compositor approval,
	 // see the handling of the request_set_selection event below.
	wlr_compositor_create(server.wl_display, server.renderer);
	wlr_subcompositor_create(server.wl_display);
	wlr_data_device_manager_create(server.wl_display);

	// Creates an output layout, which a wlroots utility for working with an
	 // arrangement of screens in a physical layout. 
	server.output_layout = wlr_output_layout_create();

	// Configure a listener to be notified when new outputs are available on the
	 // backend. 
	wl_list_init(&server.outputs);
	server.new_output.notify = server_new_output;
	wl_signal_add(&server.backend->events.new_output, &server.new_output);

	// Create a scene graph. This is a wlroots abstraction that handles all
	 // rendering and damage tracking. All the compositor author needs to do
	 // is add things that should be rendered to the scene graph at the proper
	 // positions and then call wlr_scene_output_commit() to render a frame if
	 // necessary.
	 //
	server.scene = wlr_scene_create();
	wlr_scene_attach_output_layout(server.scene, server.output_layout);

	// Set up xdg-shell version 3. The xdg-shell is a Wayland protocol which is
	 // used for application windows. For more detail on shells, refer to my
	 // article:
	 //
	 // https://drewdevault.com/2018/07/29/Wayland-shells.html
	 //
	wl_list_init(&server.views);
	server.xdg_shell = wlr_xdg_shell_create(server.wl_display, 3);
	server.new_xdg_surface.notify = server_new_xdg_surface;
	wl_signal_add(&server.xdg_shell->events.new_surface,
			&server.new_xdg_surface);

	///
	 // Creates a cursor, which is a wlroots utility for tracking the cursor
	 // image shown on screen.
	 //
	server.cursor = wlr_cursor_create();
	wlr_cursor_attach_output_layout(server.cursor, server.output_layout);

	// Creates an xcursor manager, another wlroots utility which loads up
	 // Xcursor themes to source cursor images from and makes sure that cursor
	 // images are available at all scale factors on the screen (necessary for
	 // HiDPI support). We add a cursor theme at scale factor 1 to begin with. 
	server.cursor_mgr = wlr_xcursor_manager_create(NULL, 24);
	wlr_xcursor_manager_load(server.cursor_mgr, 1);

	//
	 // wlr_cursor *only* displays an image on screen. It does not move around
	 // when the pointer moves. However, we can attach input devices to it, and
	 // it will generate aggregate events for all of them. In these events, we
	 // can choose how we want to process them, forwarding them to clients and
	 // moving the cursor around. More detail on this process is described in my
	 // input handling blog post:
	 //
	 // https://drewdevault.com/2018/07/17/Input-handling-in-wlroots.html
	 //
	 // And more comments are sprinkled throughout the notify functions above.
	 //
	server.cursor_mode = TINYWL_CURSOR_PASSTHROUGH;
	server.cursor_motion.notify = server_cursor_motion;
	wl_signal_add(&server.cursor->events.motion, &server.cursor_motion);
	server.cursor_motion_absolute.notify = server_cursor_motion_absolute;
	wl_signal_add(&server.cursor->events.motion_absolute,
			&server.cursor_motion_absolute);
	server.cursor_button.notify = server_cursor_button;
	wl_signal_add(&server.cursor->events.button, &server.cursor_button);
	server.cursor_axis.notify = server_cursor_axis;
	wl_signal_add(&server.cursor->events.axis, &server.cursor_axis);
	server.cursor_frame.notify = server_cursor_frame;
	wl_signal_add(&server.cursor->events.frame, &server.cursor_frame);

	//
	 // Configures a seat, which is a single "seat" at which a user sits and
	 // operates the computer. This conceptually includes up to one keyboard,
	 // pointer, touch, and drawing tablet device. We also rig up a listener to
	 // let us know when new input devices are available on the backend.
	 //
	wl_list_init(&server.keyboards);
	server.new_input.notify = server_new_input;
	wl_signal_add(&server.backend->events.new_input, &server.new_input);
	server.seat = wlr_seat_create(server.wl_display, "seat0");
	server.request_cursor.notify = seat_request_cursor;
	wl_signal_add(&server.seat->events.request_set_cursor,
			&server.request_cursor);
	server.request_set_selection.notify = seat_request_set_selection;
	wl_signal_add(&server.seat->events.request_set_selection,
			&server.request_set_selection);

	// Add a Unix socket to the Wayland display.
	const char *socket = wl_display_add_socket_auto(server.wl_display);
	if (!socket) {
		wlr_backend_destroy(server.backend);
		return 1;
	}

	// Start the backend. This will enumerate outputs and inputs, become the DRM
	 // master, etc
	if (!wlr_backend_start(server.backend)) {
		wlr_backend_destroy(server.backend);
		wl_display_destroy(server.wl_display);
		return 1;
	}

	// Set the WAYLAND_DISPLAY environment variable to our socket and run the
	 // startup command if requested. 
	setenv("WAYLAND_DISPLAY", socket, true);
	if (startup_cmd) {
		if (fork() == 0) {
			execl("/bin/sh", "/bin/sh", "-c", startup_cmd, (void *)NULL);
		}
	}
	// Run the Wayland event loop. This does not return until you exit the
	 // compositor. Starting the backend rigged up all of the necessary event
	 // loop configuration to listen to libinput events, DRM events, generate
	 // frame events at the refresh rate, and so on. 
	wlr_log(WLR_INFO, "Running Wayland compositor on WAYLAND_DISPLAY=%s",
			socket);
	wl_display_run(server.wl_display);

	// Once wl_display_run returns, we shut down the server. 
	wl_display_destroy_clients(server.wl_display);
	wl_display_destroy(server.wl_display);
	return 0;
}*/


/*
int main(int argc, char *argv[]) {
    wlr_log_init(WLR_DEBUG, NULL);
    char *startup_cmd = NULL;

    // Parse command-line options
    int c;
    while ((c = getopt(argc, argv, "s:h")) != -1) {
        switch (c) {
        case 's':
            startup_cmd = optarg;
            break;
        default:
            printf("Usage: %s [-s startup command]\n", argv[0]);
            return 0;
        }
    }
    if (optind < argc) {
        printf("Usage: %s [-s startup command]\n", argv[0]);
        return 0;
    }

    struct tinywl_server server = {0};  // Zero initialize all fields

    //Create Wayland display first 
    server.wl_display = wl_display_create();
    if (!server.wl_display) {
        wlr_log(WLR_ERROR, "Cannot create Wayland display");
        return 1;
    }

    // Create backend first
    const char *backends_env = getenv("WLR_BACKENDS");
    if (backends_env && strcmp(backends_env, "RDP") == 0) {
        wlr_log(WLR_INFO, "Creating RDP backend");
        // Initialize backend
        server.backend = wlr_RDP_backend_create(server.wl_display);
    } else {
        server.backend = wlr_backend_autocreate(server.wl_display);
    }

    if (!server.backend) {
        wlr_log(WLR_ERROR, "Failed to create backend");
        wl_display_destroy(server.wl_display);
        return 1;
    }

    // Create global renderer 
//    server.renderer = wlr_renderer_autocreate(server.backend);
    server.renderer = wlr_gles2_renderer_create_surfaceless();
    if (!server.renderer) {
        wlr_log(WLR_ERROR, "Failed to create renderer");
        wlr_backend_destroy(server.backend);
        wl_display_destroy(server.wl_display);
        return 1;
    }
    wlr_renderer_init_wl_display(server.renderer, server.wl_display);

    // Assign renderer to RDP backend if applicable 
    if (backends_env && strcmp(backends_env, "RDP") == 0) {
        // No direct renderer assignment; RDP backend retrieves via wlr_backend_get_renderer
        wlr_log(WLR_INFO, "RDP backend will retrieve renderer via wlr_backend_get_renderer");
    }

    // Create allocator 
    server.allocator = wlr_allocator_autocreate(server.backend, server.renderer);
    if (!server.allocator) {
        wlr_log(WLR_ERROR, "Failed to create allocator");
        wlr_renderer_destroy(server.renderer);
        wlr_backend_destroy(server.backend);
        wl_display_destroy(server.wl_display);
        return 1;
    }

    // Initialize wlroots interfaces 
    wlr_compositor_create(server.wl_display, server.renderer);
    wlr_subcompositor_create(server.wl_display);
    wlr_data_device_manager_create(server.wl_display);

    // Create output layout 
    server.output_layout = wlr_output_layout_create();

    // Configure listener for new outputs 
    wl_list_init(&server.outputs);
    server.new_output.notify = server_new_output;
    wl_signal_add(&server.backend->events.new_output, &server.new_output);

    // Create scene graph for rendering 
    server.scene = wlr_scene_create();
    wlr_scene_attach_output_layout(server.scene, server.output_layout);

    // Set up xdg-shell for application windows
    wl_list_init(&server.views);
    server.xdg_shell = wlr_xdg_shell_create(server.wl_display, 3);
    server.new_xdg_surface.notify = server_new_xdg_surface;
    wl_signal_add(&server.xdg_shell->events.new_surface, &server.new_xdg_surface);

    // Create cursor tracking 
    server.cursor = wlr_cursor_create();
    wlr_cursor_attach_output_layout(server.cursor, server.output_layout);

    // Create cursor theme 
    server.cursor_mgr = wlr_xcursor_manager_create(NULL, 24);
    wlr_xcursor_manager_load(server.cursor_mgr, 1);

    // Configure cursor input handling 
    server.cursor_mode = TINYWL_CURSOR_PASSTHROUGH;
    server.cursor_motion.notify = server_cursor_motion;
    wl_signal_add(&server.cursor->events.motion, &server.cursor_motion);
    server.cursor_motion_absolute.notify = server_cursor_motion_absolute;
    wl_signal_add(&server.cursor->events.motion_absolute, &server.cursor_motion_absolute);
    server.cursor_button.notify = server_cursor_button;
    wl_signal_add(&server.cursor->events.button, &server.cursor_button);
    server.cursor_axis.notify = server_cursor_axis;
    wl_signal_add(&server.cursor->events.axis, &server.cursor_axis);
    server.cursor_frame.notify = server_cursor_frame;
    wl_signal_add(&server.cursor->events.frame, &server.cursor_frame);

    // Configure seat for input devices 
    wl_list_init(&server.keyboards);
    server.new_input.notify = server_new_input;
    wl_signal_add(&server.backend->events.new_input, &server.new_input);
    server.seat = wlr_seat_create(server.wl_display, "seat0");
    server.request_cursor.notify = seat_request_cursor;
    wl_signal_add(&server.seat->events.request_set_cursor, &server.request_cursor);
    server.request_set_selection.notify = seat_request_set_selection;
    wl_signal_add(&server.seat->events.request_set_selection, &server.request_set_selection);

    // Add Wayland socket 
//    const char *socket = wl_display_add_socket_auto(server.wl_display);
//    if (!socket) {
//        wlr_log(WLR_ERROR, "Unable to open Wayland socket");
//        if (server.backend) {
//            wlr_backend_destroy(server.backend);
//       }
//        if (server.allocator) {
//            wlr_allocator_destroy(server.allocator);
//        }
//        if (server.renderer) {
//            wlr_renderer_destroy(server.renderer);
//        }
//        wl_display_destroy(server.wl_display);
//        return 1;
//    }
//

    // Add Wayland socket 
const char *socket = wl_display_add_socket_auto(server.wl_display);
if (!socket) {
    wlr_log(WLR_ERROR, "Unable to create wayland socket");
    wlr_backend_destroy(server.backend);
    exit(1);
}

// After socket creation, set the environment variable 
char wayland_display[32];
snprintf(wayland_display, sizeof(wayland_display), "wayland-%d", 1);
setenv("WAYLAND_DISPLAY", wayland_display, 1);
    // Start the backend 
    if (!wlr_backend_start(server.backend)) {
        wlr_log(WLR_ERROR, "Failed to start backend");
        wlr_backend_destroy(server.backend);
        wl_display_destroy(server.wl_display);
        return 1;
    }

    // Set environment and potentially run startup command 
    setenv("WAYLAND_DISPLAY", socket, true);
    if (startup_cmd) {
        if (fork() == 0) {
            execl("/bin/sh", "/bin/sh", "-c", startup_cmd, (void *)NULL);
        }
    }

    // Run Wayland event loop 
    wlr_log(WLR_INFO, "Running Wayland compositor on WAYLAND_DISPLAY=%s", socket);
    wl_display_run(server.wl_display);

    // Shutdown 
    wl_display_destroy_clients(server.wl_display);
    wl_display_destroy(server.wl_display);
    return 0;
}*/


int main(int argc, char *argv[]) {
    wlr_log_init(WLR_DEBUG, NULL);
    char *startup_cmd = NULL;

    int c;
    while ((c = getopt(argc, argv, "s:h")) != -1) {
        switch (c) {
        case 's':
            startup_cmd = optarg;
            break;
        default:
            printf("Usage: %s [-s startup command]\n", argv[0]);
            return 0;
        }
    }
    if (optind < argc) {
        printf("Usage: %s [-s startup command]\n", argv[0]);
        return 0;
    }

    struct tinywl_server server = {0};

    server.wl_display = wl_display_create();
    if (!server.wl_display) {
        wlr_log(WLR_ERROR, "Cannot create Wayland display");
        return 1;
    }

    const char *backends_env = getenv("WLR_BACKENDS");
    if (backends_env && strcmp(backends_env, "RDP") == 0) {
        wlr_log(WLR_INFO, "Creating RDP backend");
        server.backend = wlr_RDP_backend_create(server.wl_display);
    } else {
        server.backend = wlr_backend_autocreate(server.wl_display);
    }
    if (!server.backend) {
        wlr_log(WLR_ERROR, "Failed to create backend");
        wl_display_destroy(server.wl_display);
        return 1;
    }

    server.renderer = wlr_gles2_renderer_create_surfaceless();
    if (!server.renderer) {
        wlr_log(WLR_ERROR, "Failed to create renderer");
        wlr_backend_destroy(server.backend);
        wl_display_destroy(server.wl_display);
        return 1;
    }
    wlr_renderer_init_wl_display(server.renderer, server.wl_display);

    server.allocator = wlr_allocator_autocreate(server.backend, server.renderer);
    if (!server.allocator) {
        wlr_log(WLR_ERROR, "Failed to create allocator");
        wlr_renderer_destroy(server.renderer);
        wlr_backend_destroy(server.backend);
        wl_display_destroy(server.wl_display);
        return 1;
    }

    wlr_compositor_create(server.wl_display, server.renderer);
    wlr_subcompositor_create(server.wl_display);
    wlr_data_device_manager_create(server.wl_display);

    server.output_layout = wlr_output_layout_create();
    wl_list_init(&server.outputs);
    server.new_output.notify = server_new_output;
    wl_signal_add(&server.backend->events.new_output, &server.new_output);

    server.scene = wlr_scene_create();
    wlr_scene_attach_output_layout(server.scene, server.output_layout);

    wl_list_init(&server.views);
    server.xdg_shell = wlr_xdg_shell_create(server.wl_display, 3);
    server.new_xdg_surface.notify = server_new_xdg_surface;
    wl_signal_add(&server.xdg_shell->events.new_surface, &server.new_xdg_surface);

    server.cursor = wlr_cursor_create();
    wlr_cursor_attach_output_layout(server.cursor, server.output_layout);

    server.cursor_mgr = wlr_xcursor_manager_create(NULL, 24);
    wlr_xcursor_manager_load(server.cursor_mgr, 1);

    server.cursor_mode = TINYWL_CURSOR_PASSTHROUGH;
    server.cursor_motion.notify = server_cursor_motion;
    wl_signal_add(&server.cursor->events.motion, &server.cursor_motion);
    server.cursor_motion_absolute.notify = server_cursor_motion_absolute;
    wl_signal_add(&server.cursor->events.motion_absolute, &server.cursor_motion_absolute);
    server.cursor_button.notify = server_cursor_button;
    wl_signal_add(&server.cursor->events.button, &server.cursor_button);
    server.cursor_axis.notify = server_cursor_axis;
    wl_signal_add(&server.cursor->events.axis, &server.cursor_axis);
    server.cursor_frame.notify = server_cursor_frame;
    wl_signal_add(&server.cursor->events.frame, &server.cursor_frame);

    wl_list_init(&server.keyboards);
    server.new_input.notify = server_new_input;
    wl_signal_add(&server.backend->events.new_input, &server.new_input);
    server.seat = wlr_seat_create(server.wl_display, "seat0");
    server.request_cursor.notify = seat_request_cursor;
    wl_signal_add(&server.seat->events.request_set_cursor, &server.request_cursor);
    server.request_set_selection.notify = seat_request_set_selection;
    wl_signal_add(&server.seat->events.request_set_selection, &server.request_set_selection);

    const char *socket = wl_display_add_socket_auto(server.wl_display);
    if (!socket) {
        wlr_log(WLR_ERROR, "Unable to create wayland socket");
        wlr_seat_destroy(server.seat);
        wlr_xcursor_manager_destroy(server.cursor_mgr);
        wlr_cursor_destroy(server.cursor);
        wlr_output_layout_destroy(server.output_layout);
        wlr_allocator_destroy(server.allocator);
        wlr_renderer_destroy(server.renderer);
        wlr_backend_destroy(server.backend);
        wl_display_destroy(server.wl_display);
        return 1;
    }

    if (!wlr_backend_start(server.backend)) {
        wlr_log(WLR_ERROR, "Failed to start backend");
        wlr_seat_destroy(server.seat);
        wlr_xcursor_manager_destroy(server.cursor_mgr);
        wlr_cursor_destroy(server.cursor);
        wlr_output_layout_destroy(server.output_layout);
        wlr_allocator_destroy(server.allocator);
        wlr_renderer_destroy(server.renderer);
        wlr_backend_destroy(server.backend);
        wl_display_destroy(server.wl_display);
        return 1;
    }

    setenv("WAYLAND_DISPLAY", socket, true);
    if (startup_cmd) {
        if (fork() == 0) {
            execl("/bin/sh", "/bin/sh", "-c", startup_cmd, (void *)NULL);
        }
    }

   wlr_log(WLR_INFO, "Running Wayland compositor on WAYLAND_DISPLAY=%s", socket);
    wl_display_run(server.wl_display);

    /* Cleanup */
    // Free views
    struct tinywl_view *view, *view_tmp;
    wl_list_for_each_safe(view, view_tmp, &server.views, link) {
        wl_list_remove(&view->link); // Remove from list
        // Ensure all listeners are removed to prevent double-free
        wl_list_remove(&view->map.link);
        wl_list_remove(&view->unmap.link);
        wl_list_remove(&view->destroy.link);
        wl_list_remove(&view->request_move.link);
        wl_list_remove(&view->request_resize.link);
        wl_list_remove(&view->request_maximize.link);
        wl_list_remove(&view->request_fullscreen.link);
        free(view);
    }

    // Free outputs
    struct tinywl_output *output, *output_tmp;
    wl_list_for_each_safe(output, output_tmp, &server.outputs, link) {
        wlr_output_destroy(output->wlr_output); // Free output resources
        wl_list_remove(&output->link);
        wl_list_remove(&output->frame.link);
        wl_list_remove(&output->destroy.link);
        free(output);
    }

    // Free keyboards
    struct tinywl_keyboard *kb, *kb_tmp;
    wl_list_for_each_safe(kb, kb_tmp, &server.keyboards, link) {
        wl_list_remove(&kb->link);
        wl_list_remove(&kb->modifiers.link);
        wl_list_remove(&kb->key.link);
        wl_list_remove(&kb->destroy.link);
        free(kb);
    }

    wlr_seat_destroy(server.seat);
    wlr_xcursor_manager_destroy(server.cursor_mgr);
    wlr_cursor_destroy(server.cursor);
    wlr_output_layout_destroy(server.output_layout);
    wlr_allocator_destroy(server.allocator);
    wlr_renderer_destroy(server.renderer);
    wlr_backend_destroy(server.backend);
    wl_display_destroy_clients(server.wl_display);
    wl_display_destroy(server.wl_display);

    return 0;
}