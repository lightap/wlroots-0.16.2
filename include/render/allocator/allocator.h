/*#ifndef RENDER_ALLOCATOR_ALLOCATOR_H
#define RENDER_ALLOCATOR_ALLOCATOR_H

#include <wlr/render/allocator.h>

struct wlr_allocator *allocator_autocreate_with_drm_fd(
	struct wlr_backend *backend, struct wlr_renderer *renderer, int drm_fd);

#endif
*/
/*
#ifndef RENDER_ALLOCATOR_ALLOCATOR_H
#define RENDER_ALLOCATOR_ALLOCATOR_H
*/
/*
#include <wlr/render/allocator.h>
#include <wlr/render/wlr_renderer.h>
#include <drm_fourcc.h>

#ifndef WLR_HAS_GBM_ALLOCATOR
#define WLR_HAS_GBM_ALLOCATOR 0
#endif

// Forward declarations of functions used in allocator_autocreate_with_drm_fd
uint32_t backend_get_buffer_caps(struct wlr_backend *backend);
uint32_t renderer_get_render_buffer_caps(struct wlr_renderer *renderer);
const char *renderer_get_name(struct wlr_renderer *renderer);
struct wlr_allocator *wlr_shm_allocator_create(void);
struct wlr_allocator *wlr_drm_dumb_allocator_create(int drm_fd);
int reopen_drm_node(int drm_fd, bool allow_render_node);
int drmIsMaster(int fd);

struct wlr_allocator *wlr_rdp_allocator_create(struct wlr_renderer *renderer);
struct wlr_allocator *allocator_autocreate_with_drm_fd(
    struct wlr_backend *backend, 
    struct wlr_renderer *renderer, 
    int drm_fd
);
*/

/*
#include <wlr/render/allocator.h>
#include <wlr/render/allocator.h>
#include <wlr/render/wlr_renderer.h>
#include <drm_fourcc.h>
#include <wlr/interfaces/wlr_buffer.h>

// RDP-specific buffer structure
struct rdp_buffer {
    struct wlr_buffer base;
    void *data; // Pointer to pixel data
};
*/
// Function to create RDP allocator
/*
struct wlr_allocator *wlr_rdp_allocator_create(struct wlr_renderer *renderer);
#endif*/


#ifndef RENDER_ALLOCATOR_ALLOCATOR_H
#define RENDER_ALLOCATOR_ALLOCATOR_H

#include <wlr/render/allocator.h>
#include <wlr/render/wlr_renderer.h>
#include <drm_fourcc.h>
#include <wlr/interfaces/wlr_buffer.h>

// RDP-specific buffer structure
struct rdp_buffer {
    struct wlr_buffer base;
    void *data; // Pointer to pixel data
    size_t stride;


    bool in_use;           // Whether the buffer is currently locked/used
    time_t last_used;      // Timestamp of last use for delayed destruction
    struct wl_list link;   // Link in the pool's buffer list
    struct rdp_buffer_pool *pool; // Pointer to owning pool
};

// Function declarations
struct wlr_allocator *wlr_rdp_allocator_create(struct wlr_renderer *renderer);
void wlr_rdp_allocator_cleanup(struct wlr_allocator *alloc);
// Add this function declaration
struct wlr_allocator *allocator_autocreate_with_drm_fd(
    struct wlr_backend *backend,
    struct wlr_renderer *renderer,
    int drm_fd
);

// Helper function declarations needed by allocator_autocreate_with_drm_fd
uint32_t backend_get_buffer_caps(struct wlr_backend *backend);
uint32_t renderer_get_render_buffer_caps(struct wlr_renderer *renderer);
const char *renderer_get_name(struct wlr_renderer *renderer);
struct wlr_allocator *wlr_shm_allocator_create(void);
struct wlr_allocator *wlr_drm_dumb_allocator_create(int drm_fd);
int reopen_drm_node(int drm_fd, bool allow_render_node);
int drmIsMaster(int fd);

#endif