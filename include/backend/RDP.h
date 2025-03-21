#ifndef WLR_RDP_BACKEND_H
#define WLR_RDP_BACKEND_H

#include <wayland-server-core.h>
#include <wlr/backend.h>
#include <wlr/interfaces/wlr_output.h>
#include <wlr/util/log.h>
#include <wlr/render/drm_format_set.h>
#include <wlr/render/wlr_renderer.h>
#include <freerdp/freerdp.h>
#include <freerdp/listener.h>  // Added for freerdp_listener type
#include <time.h>

/* Forward declarations */
struct wlr_RDP_output;
struct wlr_buffer;

/**
 * The RDP backend structure, storing global backend state and
 * references to all RDP outputs.
 *//*
struct wlr_RDP_backend {
    struct wlr_backend backend;       // the base "backend" from wlroots
    struct wl_display *display;       // pointer to the main wl_display
    bool started;                     // whether we've called backend start
    struct wl_list outputs;           // list of wlr_RDP_output.link
    struct wl_event_loop *event_loop; // Wayland event loop
    struct wlr_renderer *renderer;    // Renderer for this backend
    freerdp_listener *listener;       // FreeRDP listener
};*/

struct wlr_RDP_backend {
    struct wlr_backend backend;
    struct wl_display *display;
    struct wl_event_loop *event_loop;
    bool started;
    struct wl_list outputs;
    struct wlr_renderer *renderer;
    struct wlr_allocator *allocator;  // Add this line
    // No renderer pointer needed anymore
     // Add FreeRDP listener
    freerdp_listener *listener;
    freerdp_peer *rdp_peer;
    struct wl_list peers;
};

/**
 * Our per-output structure: one RDP "virtual monitor."
 */
struct wlr_RDP_output {
    struct wlr_output wlr_output;     // the wlroots output
    struct wlr_RDP_backend *backend;  // backref to our backend
    struct wl_list link;              // link in backend->outputs
};

/* RDP peer management */
void set_global_rdp_peer(freerdp_peer *peer);
freerdp_peer* get_global_rdp_peer(void);

/* Surface transmission */
void rdp_transmit_surface(struct wlr_buffer *buffer);

/**
 * Entry point: create an RDP backend
 */
struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display);

/** Checks if the given wlr_backend is ours */
bool wlr_backend_is_RDP(struct wlr_backend *backend);

// Function to cast a wlr_backend to wlr_RDP_backend
struct wlr_RDP_backend *RDP_backend_from_backend(struct wlr_backend *backend);


extern freerdp_peer *global_rdp_peer;

#endif