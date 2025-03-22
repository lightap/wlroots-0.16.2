#define _XOPEN_SOURCE 700
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <wayland-server-core.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/tcp.h> 

#include <wlr/backend/interface.h>      // wlr_backend_impl
#include <wlr/interfaces/wlr_output.h>  // wlr_output_impl, wlr_output_init
#include <wlr/render/wlr_renderer.h>    // wlr_renderer_autocreate, wlr_renderer_destroy
#include <wlr/util/log.h>

#include <EGL/egl.h>
#include <EGL/eglext.h> 
#include <GLES2/gl2.h>
#include <wlr/backend/interface.h>
#include <wlr/render/wlr_renderer.h>
#include <wlr/interfaces/wlr_output.h>
#include <wlr/util/log.h>
// Add these near the top of backend.c, with other includes
#include <wlr/render/gles2.h>
#include <wlr/render/egl.h>
#include <drm_fourcc.h>      // Add this line near other includes
#include <wayland-util.h>    // Ensure this is included for WL_SHM_FORMAT_* constants

#include <freerdp/freerdp.h>
#include <freerdp/listener.h>
#include <freerdp/version.h>
#include <winpr/crt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>  // Add this for pthread functions
#include <wlr/types/wlr_compositor.h>
#include <wlr/types/wlr_subcompositor.h>  // For struct wlr_surface definition
#include <wlr/types/wlr_buffer.h>  
#include <pthread.h>
#include <freerdp/codec/nsc.h>
#include <freerdp/codec/color.h>
#include <winpr/stream.h>
#include <wlr/backend/RDP.h>

#define MAX_FREERDP_FDS 32  // Add this definition near the top of the file

#define DEFAULT_PIXEL_FORMAT PIXEL_FORMAT_BGRX32

// Add this near the top of backend.c with other global variables
freerdp_peer *global_rdp_peer = NULL;

static pthread_mutex_t rdp_peer_mutex = PTHREAD_MUTEX_INITIALIZER;
//static freerdp_peer *global_rdp_peer = NULL;
static bool rdp_connection_established = false;

#define RDP_PEER_ACTIVATED 0x0001
#define RDP_PEER_OUTPUT_ENABLED 0x0002

#ifndef DRM_FORMAT_R8G8B8A8_UNORM
#define DRM_FORMAT_R8G8B8A8_UNORM 0x34325258 /* 'XR24' */
#endif

#ifndef DRM_FORMAT_B8G8R8A8_UNORM
#define DRM_FORMAT_B8G8R8A8_UNORM 0x34324258 /* 'XB24' */
#endif

#ifndef DRM_FORMAT_A8B8G8R8_UNORM
#define DRM_FORMAT_A8B8G8R8_UNORM 0x34324142 /* 'AB24' */
#endif

/* ------------------------------------------------------------------------
 * FreedRDP placeholders (fake)
 * ------------------------------------------------------------------------ */
typedef struct fake_peer {
    /* FreedRDP peer object placeholders */
} fake_peer;

typedef struct fake_listener {
    /* FreedRDP listener placeholders */
} fake_listener;

/* ------------------------------------------------------------------------
 * wlroots RDP backend definitions
 * ------------------------------------------------------------------------ */

/* Forward declarations */
struct wlr_RDP_output;
struct wlr_RDP_backend;

// At the top of the file with other includes and defines
struct rdp_peers_item {
    freerdp_peer *peer;
    uint32_t flags;
    struct wl_list link;
    struct weston_seat *seat;
};

struct rdp_peer_context {
    rdpContext context;
    struct wlr_RDP_backend *backend;
    freerdp_peer *peer;
    rdpContext *ctx;
    rdpUpdate *update;
    rdpSettings *settings;
    NSC_CONTEXT* nsc_context;
    wStream* encode_stream;
    
    // Add these missing members
    void *vcm;  // Virtual channel manager
    struct wl_event_source *events[MAX_FREERDP_FDS];
    int loop_task_event_source_fd;
    struct wl_event_source *loop_task_event_source;
    struct wl_list loop_task_list;
    
    struct rdp_peers_item item;

    bool frame_ack_pending;
    struct wl_event_source *frame_timer;
    struct wlr_output *current_output;
};



typedef struct {
    freerdp_peer *peer;
    pthread_mutex_t lock;
    bool initialized;
} RDPPeerManager;


BOOL xf_mouseEvent(rdpInput *input, UINT16 flags, UINT16 x, UINT16 y);
BOOL xf_extendedMouseEvent(rdpInput *input, UINT16 flags, UINT16 x, UINT16 y);
BOOL xf_input_keyboard_event(rdpInput *input, UINT16 flags, UINT16 code);
BOOL xf_input_unicode_keyboard_event(rdpInput *input, UINT16 flags, UINT16 code);

// Add these near the top of the file, before any function definitions
BOOL rdp_peer_context_new(freerdp_peer *client, rdpContext *context);
void rdp_peer_context_free(freerdp_peer *client, rdpContext *ctx);
static BOOL rdp_peer_activate(freerdp_peer *client);
static BOOL xf_peer_adjust_monitor_layout(freerdp_peer *client);
static BOOL xf_input_synchronize_event(rdpInput *input, UINT32 flags);
static BOOL rdp_suppress_output(rdpContext *context, BYTE allow, const RECTANGLE_16 *area);


// Placeholder function prototypes
//static int rdp_initialize_dispatch_task_event_source(struct rdp_peer_context *peerCtx);
//static void rdp_destroy_dispatch_task_event_source(struct rdp_peer_context *peerCtx);
static int rdp_rail_peer_init(freerdp_peer *client, struct rdp_peer_context *peerCtx);

static BOOL xf_input_synchronize_event(rdpInput *input, UINT32 flags);
static BOOL xf_peer_adjust_monitor_layout(freerdp_peer *client);

static BOOL xf_peer_post_connect(freerdp_peer *client);

/* Function prototype for wlr_backend_is_RDP */
bool wlr_backend_is_RDP(struct wlr_backend *backend);
// First, declare the function at the top to prevent unused warnings
void rdp_transmit_surface(struct wlr_buffer *buffer);

/* This is our backend’s public constructor */
//struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display);
struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display); 
struct wlr_allocator *wlr_rdp_allocator_create(struct wlr_renderer *renderer);

// Function declarations
struct wlr_renderer *wlr_gles2_renderer_create_surfaceless(void);
struct wlr_egl *wlr_gles2_renderer_get_egl(struct wlr_renderer *renderer);
bool wlr_egl_make_current(struct wlr_egl *egl);


// Add these with other include statements or function declarations
struct wlr_allocator *wlr_allocator_autocreate(struct wlr_backend *backend, 
                                               struct wlr_renderer *renderer);

// Add these before the implementations
void init_rdp_peer_manager(void);
//static void set_global_rdp_peer(freerdp_peer *peer);


// If this function is used across multiple files
void rdp_transmit_surface(struct wlr_buffer *buffer);

// Add these near the top of the file, with other function declarations
static BOOL rdp_peer_activate(freerdp_peer *client);

//static BOOL rdp_peer_initialize(freerdp_peer *client);

// Declare buffer_is_opaque function or include the appropriate header
bool buffer_is_opaque(struct wlr_buffer *buffer);
 void set_global_rdp_peer(freerdp_peer *peer) ;

/* Backend and Output Implementations */
static const struct wlr_backend_impl rdp_backend_impl;
static const struct wlr_output_impl rdp_output_impl;


int rdp_peer_init(freerdp_peer *client, struct wlr_RDP_backend *b);

/* Per-output struct for our “virtual” RDP outputs */
/*
struct wlr_RDP_output {
    struct wlr_output wlr_output;
    struct wlr_RDP_backend *backend;
    struct wl_list link;
};*/
/*
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
};*/

static bool rdp_backend_start(struct wlr_backend *wlr_backend);
static void rdp_backend_destroy(struct wlr_backend *wlr_backend);
static uint32_t rdp_backend_get_buffer_caps(struct wlr_backend *wlr_backend);
static BOOL rdp_incoming_peer(freerdp_listener *instance, freerdp_peer *client);

// First declare the function prototype at the top with other declarations
static int rdp_listener_activity(int fd, uint32_t mask, void *data);






static RDPPeerManager rdp_peer_manager = {
    .peer = NULL,
    .initialized = false
};
/*
static int rdp_initialize_dispatch_task_event_source(struct rdp_peer_context *peerCtx) {
    // Placeholder implementation
    return 1;
}

static void rdp_destroy_dispatch_task_event_source(struct rdp_peer_context *peerCtx) {
    // Placeholder implementation
}*/

// Initialize the mutex in your backend creation or initialization
void init_rdp_peer_manager(void) {
    if (!rdp_peer_manager.initialized) {
        int result = pthread_mutex_init(&rdp_peer_manager.lock, NULL);
        if (result != 0) {
            wlr_log(WLR_ERROR, "Failed to initialize RDP peer mutex: %s", 
                    strerror(result));
        }
        rdp_peer_manager.initialized = true;
    }
}


void set_global_rdp_peer(freerdp_peer *peer) {
    pthread_mutex_lock(&rdp_peer_mutex);
    
    // More detailed logging
    wlr_log(WLR_ERROR, "Setting global RDP peer: %p (was %p)", 
            (void*)peer, (void*)global_rdp_peer);
    
    // Only set if the peer is not NULL
    if (peer != NULL) {
        global_rdp_peer = peer;
        rdp_connection_established = TRUE;
        wlr_log(WLR_ERROR, "Global RDP peer successfully set and connection established");
    } else {
        // If setting to NULL, be more cautious
        if (global_rdp_peer != NULL) {
            wlr_log(WLR_ERROR, "Clearing global RDP peer");
            global_rdp_peer = NULL;
            rdp_connection_established = FALSE;
        }
    }
    
    pthread_mutex_unlock(&rdp_peer_mutex);
}

// Thread-safe peer getter
freerdp_peer* get_global_rdp_peer(void) {
    pthread_mutex_lock(&rdp_peer_mutex);
    freerdp_peer *peer = global_rdp_peer;
    pthread_mutex_unlock(&rdp_peer_mutex);
    return peer;
}


void rdp_transmit_surface(struct wlr_buffer *buffer) {
    static int transmission_attempts = 0;
    transmission_attempts++;

    freerdp_peer *peer = get_global_rdp_peer();
    
    wlr_log(WLR_ERROR, "RDP Transmission Attempt #%d", transmission_attempts);
    wlr_log(WLR_ERROR, "Transmitting surface: peer=%p", (void*)peer);

    if (!peer || !peer->context || !peer->context->update) {
        wlr_log(WLR_ERROR, "Invalid peer state during surface transmission");
        return;
    }

    struct rdp_peer_context *peerContext = (struct rdp_peer_context *)peer->context;
    rdpSettings *settings = peer->context->settings;
    rdpUpdate *update = peer->context->update;

    void *data = NULL;
    uint32_t format = 0;
    size_t stride = 0;
    
    if (!wlr_buffer_begin_data_ptr_access(buffer, 
                                         WLR_BUFFER_DATA_PTR_ACCESS_READ, 
                                         &data, 
                                         &format, 
                                         &stride)) {
        wlr_log(WLR_ERROR, "Failed to access buffer data");
        return;
    }

    wlr_log(WLR_ERROR, "Transmitting surface details:"
            " width=%d, height=%d, stride=%zu, format=0x%x", 
            buffer->width, buffer->height, stride, format);

    // Configure surface bits command
    SURFACE_BITS_COMMAND cmd = { 0 };
    cmd.cmdType = CMDTYPE_SET_SURFACE_BITS;
    cmd.bmp.bpp = 32;
    cmd.bmp.width = buffer->width;
    cmd.bmp.height = buffer->height;
    cmd.destLeft = 0;
    cmd.destTop = 0;
    cmd.destRight = buffer->width;
    cmd.destBottom = buffer->height;

    // Try NSCodec if available
    if (settings->NSCodec && peerContext->nsc_context && peerContext->encode_stream) {
        wlr_log(WLR_DEBUG, "Using NSCodec compression");
        cmd.bmp.codecID = settings->NSCodecId;
        
        Stream_Clear(peerContext->encode_stream);
        Stream_SetPosition(peerContext->encode_stream, 0);

        wlr_log(WLR_DEBUG, "NSCodec state - context: %p, stream: %p", 
                (void*)peerContext->nsc_context, 
                (void*)peerContext->encode_stream);

        BOOL nsc_result = nsc_compose_message(peerContext->nsc_context,
                                            peerContext->encode_stream,
                                            (BYTE *)data,
                                            buffer->width,
                                            buffer->height,
                                            stride);

        if (!nsc_result) {
            wlr_log(WLR_ERROR, "NSCodec compression failed");
            wlr_buffer_end_data_ptr_access(buffer);
            return;
        }

        size_t stream_pos = Stream_GetPosition(peerContext->encode_stream);
        wlr_log(WLR_DEBUG, "NSCodec compressed size: %zu bytes", stream_pos);

        cmd.bmp.bitmapDataLength = stream_pos;
        cmd.bmp.bitmapData = Stream_Buffer(peerContext->encode_stream);

    } else {
        wlr_log(WLR_DEBUG, "Using raw bitmap transmission (NSCodec not available - settings: %d, context: %p)", 
                settings->NSCodec,
                peerContext->nsc_context);
        // Fall back to raw bitmap if NSCodec not available
        cmd.bmp.codecID = 0;  // Raw bitmap
        cmd.bmp.bitmapDataLength = stride * buffer->height;
        cmd.bmp.bitmapData = (BYTE *)data;
    }

    if (!update->SurfaceBits(update->context, &cmd)) {
        wlr_log(WLR_ERROR, "Failed to send surface bits - codec: %d, length: %u", 
                cmd.bmp.codecID, cmd.bmp.bitmapDataLength);
        wlr_buffer_end_data_ptr_access(buffer);
        return;
    }

    wlr_log(WLR_DEBUG, "Surface bits sent successfully");
    wlr_buffer_end_data_ptr_access(buffer);
}
static int rdp_listener_activity(int fd, uint32_t mask, void *data) {
    freerdp_listener* instance = (freerdp_listener*)data;
    
    wlr_log(WLR_ERROR, "RDP LISTENER ACTIVITY");
    wlr_log(WLR_ERROR, "  Current global_rdp_peer: %p", (void*)global_rdp_peer);
    wlr_log(WLR_ERROR, "  Listener instance: %p", (void*)instance);
    wlr_log(WLR_ERROR, "  File descriptor: %d", fd);
    wlr_log(WLR_ERROR, "  Event mask: 0x%x", mask);
    
    if (!instance) {
        wlr_log(WLR_ERROR, "RDP: null listener instance");
        return 0;
    }

    if (mask & WL_EVENT_READABLE) {
        wlr_log(WLR_ERROR, "RDP: Connection attempt detected on fd %d", fd);
        
        if (instance->CheckFileDescriptor(instance) != TRUE) {
            wlr_log(WLR_ERROR, "RDP: Failed to check file descriptor: %s", strerror(errno));
            return 1;
        }
        
        wlr_log(WLR_ERROR, "RDP: Connection accepted");
        wlr_log(WLR_ERROR, "  Global RDP Peer after connection: %p", (void*)global_rdp_peer);
    }
    
    return 1;
}




static BOOL rdp_peer_activate(freerdp_peer *client) {
    wlr_log(WLR_ERROR, "RDP: Peer Activation");

    // Ensure global peer is set
    set_global_rdp_peer(client);

    // Validate client
    if (!client || !client->settings) {
        wlr_log(WLR_ERROR, "RDP: Invalid client during activation");
        set_global_rdp_peer(NULL);
        return FALSE;
    }

    // Ensure surface commands are enabled
    client->settings->SurfaceCommandsEnabled = TRUE;

    wlr_log(WLR_ERROR, "RDP: Peer Activated Successfully");
    return TRUE;
}
/*
struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display) {
    wlr_log(WLR_INFO, "Creating RDP backend with FreeRDP");

    // Initialize FreeRDP
    //
#if FREERDP_VERSION_MAJOR >= 2
    winpr_InitializeSSL(0);
#endif//

    struct wlr_RDP_backend *backend = calloc(1, sizeof(*backend));
    if (!backend) {
        wlr_log(WLR_ERROR, "Failed to allocate wlr_RDP_backend");
        return NULL;
    }

    wlr_backend_init(&backend->backend, &rdp_backend_impl);
    backend->display = display;
    wl_list_init(&backend->outputs);

    // Create FreeRDP listener
    backend->listener = freerdp_listener_new();
    if (!backend->listener) {
        wlr_log(WLR_ERROR, "Failed to create FreeRDP listener");
        free(backend);
        return NULL;
    }

    // Set up listener configuration
    int port = 3389;  // Default RDP port
    const char *bind_address = NULL;  // Bind to all interfaces

    // Open the listener
    if (!backend->listener->Open(backend->listener, bind_address, port)) {
        wlr_log(WLR_ERROR, "Failed to open RDP listener on port %d", port);
        freerdp_listener_free(backend->listener);
        free(backend);
        return NULL;
    }

    // Optional: Set up peer accepted callback
    backend->listener->PeerAccepted = rdp_incoming_peer;
    backend->listener->param4 = backend;  // Pass backend as context

    wlr_log(WLR_INFO, "RDP backend created successfully on port %d", port);
    return &backend->backend;
}*/

/*
static void surface_apply_damage(struct wlr_surface *surface) {
    // Handle NULL buffer commit scenario
    if (surface->current.buffer == NULL) {
        if (surface->buffer != NULL) {
            wlr_buffer_unlock(&surface->buffer->base);
        }
        surface->buffer = NULL;
        surface->opaque = false;
        return;
    }

    // Additional logging for RDP transmission
    wlr_log(WLR_DEBUG, "Applying surface damage: buffer=%p", 
            (void*)surface->current.buffer);

    // Attempt RDP transmission for every surface with a buffer
    if (surface->current.buffer != NULL) {
        freerdp_peer *current_peer = get_global_rdp_peer();
        
        wlr_log(WLR_DEBUG, "Current RDP peer for transmission: %p", 
                (void*)current_peer);
        
        if (current_peer) {
            rdp_transmit_surface(surface->current.buffer);
        } else {
            wlr_log(WLR_ERROR, "No RDP peer available for surface transmission");
        }
    }

    // Determine surface opacity
    surface->opaque = buffer_is_opaque(surface->current.buffer);

    // Handle existing buffer
    if (surface->buffer != NULL) {
        if (wlr_client_buffer_apply_damage(surface->buffer,
                surface->current.buffer, &surface->buffer_damage)) {
            wlr_buffer_unlock(surface->current.buffer);
            surface->current.buffer = NULL;
            return;
        }
    }

    // Create new client buffer
    struct wlr_client_buffer *buffer = wlr_client_buffer_create(
            surface->current.buffer, surface->renderer);

    wlr_buffer_unlock(surface->current.buffer);
    surface->current.buffer = NULL;

    if (buffer == NULL) {
        wlr_log(WLR_ERROR, "Failed to create client buffer");
        return;
    }

    // Replace existing buffer
    if (surface->buffer != NULL) {
        wlr_buffer_unlock(&surface->buffer->base);
    }
    surface->buffer = buffer;

    // Log successful buffer creation and damage application
    wlr_log(WLR_DEBUG, "Surface damage applied successfully");
}*/
/*//last one good but may have bug
struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display) {
    wlr_log(WLR_ERROR, "RDP Backend Creation - START");

    // Reset global peer state
    set_global_rdp_peer(NULL);
    rdp_connection_established = false;
    init_rdp_peer_manager();

    struct wlr_RDP_backend *backend = calloc(1, sizeof(*backend));
    if (!backend) {
        wlr_log(WLR_ERROR, "RDP Backend: Failed to allocate memory");
        return NULL;
    }

    wlr_backend_init(&backend->backend, &rdp_backend_impl);
    backend->display = display;
     wl_list_init(&backend->outputs);
    wl_list_init(&backend->peers);  // Explicitly initialize peers list

    // Get event loop
    backend->event_loop = wl_display_get_event_loop(display);
    if (!backend->event_loop) {
        wlr_log(WLR_ERROR, "Failed to get event loop");
        free(backend);
        return NULL;
    }

    // Create FreeRDP listener
    backend->listener = freerdp_listener_new();
    if (!backend->listener) {
        wlr_log(WLR_ERROR, "RDP Backend: Failed to create listener");
        free(backend);
        return NULL;
    }

    // Configure listener
    backend->listener->info = backend;
    backend->listener->PeerAccepted = rdp_incoming_peer;

    // Open RDP listener
    if (!backend->listener->Open(backend->listener, NULL, 3389)) {
        wlr_log(WLR_ERROR, "RDP Backend: Failed to open listener");
        freerdp_listener_free(backend->listener);
        free(backend);
        return NULL;
    }

    // Get socket descriptors
    void* rfds[32] = { 0 };
    int rcount = 0;
    
    if (!backend->listener->GetFileDescriptor(backend->listener, rfds, &rcount)) {
        wlr_log(WLR_ERROR, "Failed to get RDP file descriptors");
        freerdp_listener_free(backend->listener);
        free(backend);
        return NULL;
    }

    // Add each descriptor to the event loop
    for (int i = 0; i < rcount; i++) {
        int fd = (int)(intptr_t)rfds[i];
        wl_event_loop_add_fd(backend->event_loop, fd, WL_EVENT_READABLE,
                            rdp_listener_activity, backend->listener);
        wlr_log(WLR_DEBUG, "Added RDP listener fd %d to event loop", fd);
    }

    wlr_log(WLR_ERROR, "RDP Backend Creation - COMPLETE");
    return &backend->backend;
}*/

/*//almost fixed bug
struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display) {
    wlr_log(WLR_ERROR, "RDP Backend Creation - START");

    // Reset global peer state
    set_global_rdp_peer(NULL);
    rdp_connection_established = false;
    init_rdp_peer_manager();

    struct wlr_RDP_backend *backend = calloc(1, sizeof(*backend));
    if (!backend) {
        wlr_log(WLR_ERROR, "RDP Backend: Failed to allocate memory");
        return NULL;
    }

    wlr_backend_init(&backend->backend, &rdp_backend_impl);
    backend->display = display;
    wl_list_init(&backend->outputs);
    wl_list_init(&backend->peers);

    // Get event loop
    backend->event_loop = wl_display_get_event_loop(display);
    if (!backend->event_loop) {
        wlr_log(WLR_ERROR, "Failed to get event loop");
        free(backend);
        return NULL;
    }

    // Create FreeRDP listener
    backend->listener = freerdp_listener_new();
    if (!backend->listener) {
        wlr_log(WLR_ERROR, "RDP Backend: Failed to create listener");
        free(backend);
        return NULL;
    }

    // Configure listener
    backend->listener->info = backend;
    backend->listener->PeerAccepted = rdp_incoming_peer;

    // Open RDP listener
    if (!backend->listener->Open(backend->listener, NULL, 3389)) {
        wlr_log(WLR_ERROR, "RDP Backend: Failed to open listener");
        freerdp_listener_free(backend->listener);
        free(backend);
        return NULL;
    }

    // Get socket descriptors
    void* rfds[32] = {0};
    int rcount = 0;
    
    if (!backend->listener->GetFileDescriptor(backend->listener, rfds, &rcount)) {
        wlr_log(WLR_ERROR, "Failed to get RDP file descriptors");
        freerdp_listener_free(backend->listener);
        free(backend);
        return NULL;
    }

    // Add each descriptor to the event loop and store event sources
    backend->fd_count = 0;
    for (int i = 0; i < rcount; i++) {
        int fd = (int)(intptr_t)rfds[i];
        struct wl_event_source *source = wl_event_loop_add_fd(
            backend->event_loop, fd, WL_EVENT_READABLE,
            rdp_listener_activity, backend->listener);
        if (!source) {
            wlr_log(WLR_ERROR, "Failed to add fd %d to event loop", fd);
            // Cleanup previously added sources
            for (int j = 0; j < backend->fd_count; j++) {
                wl_event_source_remove(backend->fd_event_sources[j]);
            }
            freerdp_listener_free(backend->listener);
            free(backend);
            return NULL;
        }
        backend->fd_event_sources[backend->fd_count++] = source;
        wlr_log(WLR_DEBUG, "Added RDP listener fd %d to event loop", fd);
    }

    wlr_log(WLR_ERROR, "RDP Backend Creation - COMPLETE");
    return &backend->backend;
}*/

/*//was before bug has a bug
struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display) {
    wlr_log(WLR_ERROR, "RDP Backend Creation - START");

    set_global_rdp_peer(NULL);
    rdp_connection_established = false;
    init_rdp_peer_manager();

    struct wlr_RDP_backend *backend = calloc(1, sizeof(*backend));
    if (!backend) {
        wlr_log(WLR_ERROR, "RDP Backend: Failed to allocate memory");
        return NULL;
    }

    wlr_backend_init(&backend->backend, &rdp_backend_impl);
    backend->display = display;
    wl_list_init(&backend->outputs);
    wl_list_init(&backend->peers);

    backend->event_loop = wl_display_get_event_loop(display);
    if (!backend->event_loop) {
        wlr_log(WLR_ERROR, "Failed to get event loop");
        free(backend);
        return NULL;
    }

    backend->listener = freerdp_listener_new();
    if (!backend->listener) {
        wlr_log(WLR_ERROR, "RDP Backend: Failed to create listener");
        free(backend);
        return NULL;
    }

    backend->listener->info = backend;
    backend->listener->PeerAccepted = rdp_incoming_peer;

    if (!backend->listener->Open(backend->listener, NULL, 3389)) {
        wlr_log(WLR_ERROR, "RDP Backend: Failed to open listener");
        freerdp_listener_free(backend->listener);
        free(backend);
        return NULL;
    }

    void* rfds[32] = {0};
    int rcount = 0;
    
    if (!backend->listener->GetFileDescriptor(backend->listener, rfds, &rcount)) {
        wlr_log(WLR_ERROR, "Failed to get RDP file descriptors");
        freerdp_listener_free(backend->listener);
        free(backend);
        return NULL;
    }

    backend->fd_count = 0;
    for (int i = 0; i < rcount; i++) {
        int fd = (int)(intptr_t)rfds[i];
        struct wl_event_source *source = wl_event_loop_add_fd(
            backend->event_loop, fd, WL_EVENT_READABLE,
            rdp_listener_activity, backend->listener);
        if (!source) {
            wlr_log(WLR_ERROR, "Failed to add fd %d to event loop", fd);
            for (int j = 0; j < backend->fd_count; j++) {
                wl_event_source_remove(backend->fd_event_sources[j]);
            }
            freerdp_listener_free(backend->listener);
            free(backend);
            return NULL;
        }
        backend->fd_event_sources[backend->fd_count++] = source;
        wlr_log(WLR_DEBUG, "Added RDP listener fd %d to event loop", fd);
    }

    wlr_log(WLR_ERROR, "RDP Backend Creation - COMPLETE");
    return &backend->backend;
}
*/

struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display) {
    wlr_log(WLR_ERROR, "RDP Backend Creation - START");

    set_global_rdp_peer(NULL);
    rdp_connection_established = false;
    init_rdp_peer_manager();

    struct wlr_RDP_backend *backend = calloc(1, sizeof(*backend));
    if (!backend) {
        wlr_log(WLR_ERROR, "RDP Backend: Failed to allocate memory");
        return NULL;
    }

    wlr_backend_init(&backend->backend, &rdp_backend_impl);
    backend->display = display;
    wl_list_init(&backend->outputs);
    wl_list_init(&backend->peers);

    backend->event_loop = wl_display_get_event_loop(display);
    if (!backend->event_loop) {
        wlr_log(WLR_ERROR, "Failed to get event loop");
        free(backend);
        return NULL;
    }

    backend->listener = freerdp_listener_new();
    if (!backend->listener) {
        wlr_log(WLR_ERROR, "RDP Backend: Failed to create listener");
        free(backend);
        return NULL;
    }

    backend->listener->info = backend;
    backend->listener->PeerAccepted = rdp_incoming_peer;

    if (!backend->listener->Open(backend->listener, NULL, 3389)) {
        wlr_log(WLR_ERROR, "RDP Backend: Failed to open listener");
        freerdp_listener_free(backend->listener);
        free(backend);
        return NULL;
    }

    void* rfds[32] = {0};
    int rcount = 0;
    
    if (!backend->listener->GetFileDescriptor(backend->listener, rfds, &rcount)) {
        wlr_log(WLR_ERROR, "Failed to get RDP file descriptors");
        freerdp_listener_free(backend->listener);
        free(backend);
        return NULL;
    }

    backend->fd_count = 0;
    for (int i = 0; i < rcount; i++) {
        int fd = (int)(intptr_t)rfds[i];
        struct wl_event_source *source = wl_event_loop_add_fd(
            backend->event_loop, fd, WL_EVENT_READABLE,
            rdp_listener_activity, backend->listener); // Line ~625
        if (!source) {
            wlr_log(WLR_ERROR, "Failed to add fd %d to event loop", fd);
            for (int j = 0; j < backend->fd_count; j++) {
                wl_event_source_remove(backend->fd_event_sources[j]);
            }
            freerdp_listener_free(backend->listener);
            free(backend);
            return NULL;
        }
        backend->fd_event_sources[backend->fd_count++] = source;
        wlr_log(WLR_DEBUG, "Added RDP listener fd %d to event loop", fd);
    }

    wlr_log(WLR_ERROR, "RDP Backend Creation - COMPLETE");
    return &backend->backend;
}





// Add this function to handle incoming RDP peers
/*
static void rdp_peer_disconnect(freerdp_peer* client) {
    wlr_log(WLR_ERROR, "RDP: Peer Disconnection");
    
    // Thread-safe peer cleanup
    pthread_mutex_lock(&rdp_peer_mutex);
    if (global_rdp_peer == client) {
        wlr_log(WLR_ERROR, "RDP: Clearing disconnected peer");
        global_rdp_peer = NULL;
        rdp_connection_established = false;
    }
    pthread_mutex_unlock(&rdp_peer_mutex);

    wlr_log(WLR_ERROR, "RDP: Peer Disconnected");
}*/

/*
// Add callback handlers
static BOOL rdp_begin_paint(rdpContext* context) {
    wlr_log(WLR_DEBUG, "RDP: Begin paint");
    return TRUE;
}

static BOOL rdp_end_paint(rdpContext* context) {
    wlr_log(WLR_DEBUG, "RDP: End paint");
    return TRUE;
}*/
/*
static BOOL rdp_peer_post_connect(freerdp_peer* client) {
    wlr_log(WLR_DEBUG, "RDP: Post connect");
    client->settings->CompressionLevel = PACKET_COMPR_TYPE_RDP61;
    return TRUE;
}*/

/*
// Modify the rdp_peer_initialize function to use the existing xf_peer_post_connect
static BOOL rdp_peer_initialize(freerdp_peer* client) {
    wlr_log(WLR_ERROR, "RDP: Peer Initialization START");

    if (!client || !client->context || !client->settings) {
        wlr_log(WLR_ERROR, "Invalid client state");
        return FALSE;
    }

    // Enable basic events
    client->update->BeginPaint = rdp_begin_paint;
    client->update->EndPaint = rdp_end_paint;
    
    // Use the existing xf_peer_post_connect function
    client->PostConnect = xf_peer_post_connect;
    client->Activate = rdp_peer_activate;
    client->Disconnect = rdp_peer_disconnect;

    // Set synchronized drawing
    client->settings->SupportGraphicsPipeline = FALSE;
    client->settings->DrawAllowSkipAlpha = TRUE;
    client->settings->DrawAllowColorSubsampling = TRUE;
    client->settings->DrawAllowDynamicColorFidelity = TRUE;
    
    return TRUE;
}*/

static BOOL xf_peer_capabilities(freerdp_peer* client)
{
    // In the original code, this simply returns TRUE
    return TRUE;
}

static BOOL xf_peer_post_connect(freerdp_peer *client)
{
    // In the original code, this simply returns TRUE
    return TRUE;
}

static BOOL xf_suppress_output(rdpContext *context, BYTE allow, const RECTANGLE_16 *area)
{
    struct rdp_peer_context *peerContext = (struct rdp_peer_context *)context;

    if (allow)
        peerContext->item.flags |= RDP_PEER_OUTPUT_ENABLED;
    else
        peerContext->item.flags &= (~RDP_PEER_OUTPUT_ENABLED);

    return TRUE;
}
// Add implementations for the missing input event handlers
static BOOL xf_input_synchronize_event(rdpInput *input, UINT32 flags) {
    __attribute__((unused)) struct rdp_peer_context *peerContext = 
        (struct rdp_peer_context *)input->context;
    
    wlr_log(WLR_DEBUG, "RDP backend: Synchronize Event - Scroll Lock: %d, Num Lock: %d, Caps Lock: %d, Kana Lock: %d",
        flags & KBD_SYNC_SCROLL_LOCK ? 1 : 0,
        flags & KBD_SYNC_NUM_LOCK ? 1 : 0,
        flags & KBD_SYNC_CAPS_LOCK ? 1 : 0,
        flags & KBD_SYNC_KANA_LOCK ? 1 : 0);

    return TRUE;
}
static int rdp_client_activity(int fd, uint32_t mask, void *data)
{
    freerdp_peer *client = (freerdp_peer *)data;
 //   struct rdp_peer_context *peerContext = (struct rdp_peer_context *)client->context;
    
    // Remove unused backend variable
    if (!client->CheckFileDescriptor(client)) {
        wlr_log(WLR_ERROR, "Unable to check descriptor for client %p", client);
        goto out_clean;
    }

    // Comment out or remove WTS-specific code for now
    // if (peerContext->vcm) {
    //     if (!WTSVirtualChannelManagerCheckFileDescriptor(peerContext->vcm)) {
    //         wlr_log(WLR_ERROR, "Failed to check FreeRDP WTS virtual channel file descriptor for %p", client);
    //         goto out_clean;
    //     }
    // }

    return 0;

out_clean:
    freerdp_peer_context_free(client);
    freerdp_peer_free(client);
    return 0;
}

static BOOL xf_peer_adjust_monitor_layout(freerdp_peer *client) {
    __attribute__((unused)) struct rdp_peer_context *peerContext = 
        (struct rdp_peer_context *)client->context;
    rdpSettings *settings = client->context->settings;

    wlr_log(WLR_ERROR, "Monitor Layout Adjustment:");
    wlr_log(WLR_ERROR, "  DesktopWidth: %d", settings->DesktopWidth);
    wlr_log(WLR_ERROR, "  DesktopHeight: %d", settings->DesktopHeight);
    wlr_log(WLR_ERROR, "  MonitorCount: %d", settings->MonitorCount);

    return TRUE;
}
/*
BOOL rdp_peer_context_new(freerdp_peer *client, rdpContext *context) {
    struct rdp_peer_context *peer_context = (struct rdp_peer_context *)context;
    
    if (!peer_context) {
        wlr_log(WLR_ERROR, "RDP: Failed to allocate peer context");
        return FALSE;
    }

    // Initialize context fields
    peer_context->peer = client;
    peer_context->backend = NULL;  // Optionally set backend if available
    peer_context->update = client->update;
    peer_context->settings = client->settings;

    peer_context->nsc_context = nsc_context_new();
    if (!peer_context->nsc_context) {
        wlr_log(WLR_ERROR, "Failed to create NSCodec context");
        return FALSE;
    }

    nsc_context_set_parameters(peer_context->nsc_context, 
                             NSC_COLOR_FORMAT, 
                             DEFAULT_PIXEL_FORMAT);

    peer_context->encode_stream = Stream_New(NULL, 65536);
    if (!peer_context->encode_stream) {
        wlr_log(WLR_ERROR, "Failed to create encode stream");
        nsc_context_free(peer_context->nsc_context);
        return FALSE;
    }

    wlr_log(WLR_INFO, "RDP: New peer context created successfully");
    return TRUE;
}*/

BOOL rdp_peer_context_new(freerdp_peer *client, rdpContext *context) {
    struct rdp_peer_context *peer_context = (struct rdp_peer_context *)context;
    
    if (!peer_context) {
        wlr_log(WLR_ERROR, "RDP: Failed to allocate peer context");
        return FALSE;
    }

    // Initialize context fields
    peer_context->peer = client;
    peer_context->backend = NULL;  // Optionally set backend if available
    peer_context->update = client->update;
    peer_context->settings = client->settings;

    // Initialize frame sync fields
    peer_context->frame_ack_pending = false;
    peer_context->current_output = NULL;

    // Create NSCodec context
    peer_context->nsc_context = nsc_context_new();
    if (!peer_context->nsc_context) {
        wlr_log(WLR_ERROR, "Failed to create NSCodec context");
        return FALSE;
    }

    nsc_context_set_parameters(peer_context->nsc_context, 
                             NSC_COLOR_FORMAT, 
                             DEFAULT_PIXEL_FORMAT);

    peer_context->encode_stream = Stream_New(NULL, 65536);
    if (!peer_context->encode_stream) {
        wlr_log(WLR_ERROR, "Failed to create encode stream");
        nsc_context_free(peer_context->nsc_context);
        return FALSE;
    }

    // Set up suppress output callback
    client->update->SuppressOutput = rdp_suppress_output;

    wlr_log(WLR_INFO, "RDP: New peer context created successfully");
    return TRUE;
}

void rdp_peer_context_free(freerdp_peer *client, rdpContext *ctx) {
    struct rdp_peer_context *context = (struct rdp_peer_context *)ctx;

    wlr_log(WLR_INFO, "RDP: free peer context");

    if (global_rdp_peer == client) {
        global_rdp_peer = NULL;
    }

    // Free resources if they exist
    if (context->nsc_context) {
        nsc_context_free(context->nsc_context);
        context->nsc_context = NULL;
    }

    if (context->encode_stream) {
        Stream_Free(context->encode_stream, TRUE);
        context->encode_stream = NULL;
    }
}

/*
// Placeholder for these functions - you'll need to implement them based on your specific requirements
static int rdp_initialize_dispatch_task_event_source(struct rdp_peer_context *peerCtx)
{
    // Placeholder implementation
    return 1;
}

static void rdp_destroy_dispatch_task_event_source(struct rdp_peer_context *peerCtx)
{
    // Placeholder implementation
}
*/
static int rdp_rail_peer_init(freerdp_peer *client, struct rdp_peer_context *peerCtx)
{
    // Placeholder implementation
    return 1;
}


static BOOL rdp_incoming_peer(freerdp_listener *instance, freerdp_peer *client)
{
    struct wlr_RDP_backend *b = (struct wlr_RDP_backend *)instance->info;

    // Directly call rdp_peer_init and handle the initialization
    if (rdp_peer_init(client, b) < 0) {
        wlr_log(WLR_ERROR, "error when treating incoming peer");
        return FALSE;
    }

    return TRUE;
}

BOOL xf_mouseEvent(rdpInput *input, UINT16 flags, UINT16 x, UINT16 y) {
    // Basic implementation that logs the event
 //   struct rdp_peer_context *peerContext = (struct rdp_peer_context *)input->context;
    wlr_log(WLR_DEBUG, "Mouse Event: flags=%d, x=%d, y=%d", flags, x, y);
    return TRUE;
}

BOOL xf_extendedMouseEvent(rdpInput *input, UINT16 flags, UINT16 x, UINT16 y) {
 //   struct rdp_peer_context *peerContext = (struct rdp_peer_context *)input->context;
    wlr_log(WLR_DEBUG, "Extended Mouse Event: flags=%d, x=%d, y=%d", flags, x, y);
    return TRUE;
}

BOOL xf_input_keyboard_event(rdpInput *input, UINT16 flags, UINT16 code) {
  //  struct rdp_peer_context *peerContext = (struct rdp_peer_context *)input->context;
    wlr_log(WLR_DEBUG, "Keyboard Event: flags=%d, code=%d", flags, code);
    return TRUE;
}

BOOL xf_input_unicode_keyboard_event(rdpInput *input, UINT16 flags, UINT16 code) {
  //  struct rdp_peer_context *peerContext = (struct rdp_peer_context *)input->context;
    wlr_log(WLR_DEBUG, "Unicode Keyboard Event: flags=%d, code=%d", flags, code);
    return TRUE;
}

int rdp_peer_init(freerdp_peer *client, struct wlr_RDP_backend *b)
{
    wlr_log(WLR_ERROR, "RDP: Peer Initialization START");

    // Validate inputs
    if (!client || !b) {
        wlr_log(WLR_ERROR, "RDP: Invalid client or backend");
        return -1;
    }

    // Ensure peers list is initialized
    if (wl_list_empty(&b->peers)) {
        wlr_log(WLR_DEBUG, "Initializing RDP peers list");
        wl_list_init(&b->peers);
    }

    // Set context size and callbacks
    client->ContextSize = sizeof(struct rdp_peer_context);
    client->ContextNew = (psPeerContextNew)rdp_peer_context_new;
    client->ContextFree = (psPeerContextFree)rdp_peer_context_free;
    
    // Create peer context
    if (!freerdp_peer_context_new(client)) {
        wlr_log(WLR_ERROR, "Failed to create peer context");
        return -1;
    }

    struct rdp_peer_context *peerCtx = (struct rdp_peer_context *)client->context;
    
    // Validate created context
    if (!peerCtx) {
        wlr_log(WLR_ERROR, "Peer context creation failed");
        return -1;
    }

    // Initialize context fields
    peerCtx->backend = b;
    peerCtx->peer = client;
    peerCtx->ctx = client->context;
    peerCtx->update = client->update;
    peerCtx->settings = client->settings;

    // Configure basic RDP settings
    rdpSettings *settings = client->context->settings;
    settings->ServerMode = TRUE;
    settings->ColorDepth = 32;
    settings->NlaSecurity = FALSE;
    settings->TlsSecurity = FALSE;
    settings->RdpSecurity = TRUE;
    settings->UseRdpSecurityLayer = TRUE;

    // Configure operating system settings
    settings->OsMajorType = OSMAJORTYPE_UNIX;
    settings->OsMinorType = OSMINORTYPE_PSEUDO_XSERVER;

    // Graphics and display settings
    settings->RefreshRect = TRUE;
    settings->RemoteFxCodec = FALSE;
    settings->NSCodec = TRUE;
    settings->FrameMarkerCommandEnabled = TRUE;
    settings->SurfaceFrameMarkerEnabled = TRUE;

    // Advanced features
    settings->RemoteApplicationMode = TRUE;
    settings->SupportGraphicsPipeline = TRUE;
    settings->SupportMonitorLayoutPdu = TRUE;
    settings->RedirectClipboard = TRUE;
    settings->HasExtendedMouseEvent = TRUE;
    settings->HasHorizontalWheel = TRUE;

    // Initialize client
    if (!client->Initialize(client)) {
        wlr_log(WLR_ERROR, "RDP: Peer initialization failed");
        freerdp_peer_context_free(client);
        return -1;
    }

    // Set up client callbacks
    client->Capabilities = xf_peer_capabilities;
    client->PostConnect = xf_peer_post_connect;
    client->Activate = rdp_peer_activate;
    client->AdjustMonitorsLayout = xf_peer_adjust_monitor_layout;

    // Update suppression callback
    client->context->update->SuppressOutput = (pSuppressOutput)xf_suppress_output;

    // Set up input event handlers
    rdpInput *input = client->context->input;
    input->SynchronizeEvent = xf_input_synchronize_event;
    input->MouseEvent = xf_mouseEvent;
    input->ExtendedMouseEvent = xf_extendedMouseEvent;
    input->KeyboardEvent = xf_input_keyboard_event;
    input->UnicodeKeyboardEvent = xf_input_unicode_keyboard_event;

    // Retrieve and add client event handles to event loop
    HANDLE handles[MAX_FREERDP_FDS];
    int handle_count = client->GetEventHandles(client, handles, MAX_FREERDP_FDS);
    
    if (handle_count <= 0) {
        wlr_log(WLR_ERROR, "Unable to retrieve client handles");
        freerdp_peer_context_free(client);
        return -1;
    }

    // Get Wayland event loop
    struct wl_event_loop *loop = wl_display_get_event_loop(b->display);

    // Initialize event sources
    memset(peerCtx->events, 0, sizeof(peerCtx->events));

    // Add file descriptors to event loop
    for (int i = 0; i < handle_count; i++) {
        int fd = GetEventFileDescriptor(handles[i]);
        
        if (fd < 0) {
            wlr_log(WLR_ERROR, "Invalid file descriptor for handle %d", i);
            continue;
        }

        peerCtx->events[i] = wl_event_loop_add_fd(loop, fd, 
                                                  WL_EVENT_READABLE,
                                                  rdp_client_activity, 
                                                  client);
        
        if (!peerCtx->events[i]) {
            wlr_log(WLR_ERROR, "Failed to add file descriptor %d to event loop", fd);
        }
    }

    // Initialize peer item link
    wl_list_init(&peerCtx->item.link);
    peerCtx->item.peer = client;
    peerCtx->item.flags = RDP_PEER_ACTIVATED;

    // Add to peers list
    wl_list_insert(&b->peers, &peerCtx->item.link);

    // Optional: Rail (Remote Application Integrated Locally) initialization
    if (rdp_rail_peer_init(client, peerCtx) != 1) {
        wlr_log(WLR_ERROR, "RDP: RAIL peer initialization failed");
        // Consider whether to abort or continue
    }

    wlr_log(WLR_ERROR, "RDP: Peer Initialization COMPLETE");
    return 0;
}
// Add event loop integration for the RDP listener
/**/

/* ------------------------------------------------------------------------
 * Utility & “is RDP backend?” checks
 * ------------------------------------------------------------------------ */

bool wlr_backend_is_RDP(struct wlr_backend *backend) {
    return (backend->impl == &rdp_backend_impl);
}





struct wlr_RDP_backend *RDP_backend_from_backend(struct wlr_backend *backend) {
    assert(wlr_backend_is_RDP(backend));
    return (struct wlr_RDP_backend *)backend;
}

static struct wlr_RDP_output *RDP_output_from_output(struct wlr_output *output) {
    assert(output->impl == &rdp_output_impl);
    return (struct wlr_RDP_output *)output;
}




/* ------------------------------------------------------------------------
 * Output Implementation
 * ------------------------------------------------------------------------ */

static bool rdp_output_test(struct wlr_output *wlr_output, 
        const struct wlr_output_state *state) {
    struct wlr_RDP_output *output = RDP_output_from_output(wlr_output);
    if (!output->backend->started) {
        return false;
    }
    
    // Always allow test mode for surfaceless output
    if (state->committed & WLR_OUTPUT_STATE_MODE) {
        const struct wlr_output_mode *mode = state->mode;
        if (!mode) {
            return false;
        }
        wlr_log(WLR_DEBUG, "Testing mode %dx%d@%d", 
                mode->width, mode->height, mode->refresh/1000);
    }
    
    return true;
}






// Frame synchronization callback from RDP
static BOOL rdp_suppress_output(rdpContext *context, BYTE allow, 
                              const RECTANGLE_16 *area) {
    struct rdp_peer_context *peerCtx = (struct rdp_peer_context *)context;
    
    wlr_log(WLR_DEBUG, "RDP: Output suppression changed: allow=%d", allow);
    
    if (allow) {
        peerCtx->item.flags |= RDP_PEER_OUTPUT_ENABLED;
        
        // If we have a pending frame, send it now
        if (peerCtx->frame_ack_pending && peerCtx->current_output) {
            wlr_output_send_frame(peerCtx->current_output);
            peerCtx->frame_ack_pending = false;
        }
    } else {
        peerCtx->item.flags &= (~RDP_PEER_OUTPUT_ENABLED);
    }
    
    return TRUE;
}



// In rdp_output_commit
static bool rdp_output_commit(struct wlr_output *wlr_output,
        const struct wlr_output_state *state) {
    struct wlr_RDP_output *output = RDP_output_from_output(wlr_output);
    struct wlr_RDP_backend *backend = output->backend;
    
    if (!backend->started) {
        return false;
    }

    // Handle bufferless commits for surfaceless mode
    if (!(state->committed & WLR_OUTPUT_STATE_BUFFER)) {
        wlr_log(WLR_DEBUG, "Bufferless commit on RDP output");
        return true;
    }
    
    // Get the current RDP peer
    freerdp_peer *peer = get_global_rdp_peer();
    if (!peer || !peer->context) {
        wlr_log(WLR_ERROR, "No active RDP peer for frame commit");
        return false;
    }
    
    struct rdp_peer_context *peerCtx = (struct rdp_peer_context *)peer->context;
    peerCtx->current_output = wlr_output;
    
    // Only send frame event if output is enabled
    if (peerCtx->item.flags & RDP_PEER_OUTPUT_ENABLED) {
        wlr_output_send_frame(wlr_output);
        peerCtx->frame_ack_pending = false;
    } else {
        peerCtx->frame_ack_pending = true;
    }
    
    return true;
}





static void rdp_output_destroy(struct wlr_output *wlr_output) {
    struct wlr_RDP_output *output = RDP_output_from_output(wlr_output);
    wlr_log(WLR_INFO, "RDP: destroying output '%s'", wlr_output->name);

    wl_list_remove(&output->link);
    free(output);
}

static size_t rdp_output_get_gamma_size(struct wlr_output *wlr_output) {
    return 0; /* No gamma-lut support in RDP skeleton */
}

static const struct wlr_drm_format_set *rdp_output_get_cursor_formats(
        struct wlr_output *o, uint32_t buffer_flags) {
    return NULL; /* Not supporting hardware cursors in this example */
}

static const struct wlr_output_impl rdp_output_impl = {
    .destroy = rdp_output_destroy,
    .test = rdp_output_test,
    .commit = rdp_output_commit,
    .get_gamma_size = rdp_output_get_gamma_size,
    .get_cursor_formats = rdp_output_get_cursor_formats,
};
/* Creates one “virtual” RDP output. */
/*
static struct wlr_RDP_output *rdp_output_create(
        struct wlr_RDP_backend *backend, const char *name,
        int width, int height, int refresh_hz) {
    struct wlr_RDP_output *output = calloc(1, sizeof(*output));
    if (!output) {
        return NULL;
    }
    output->backend = backend;

    struct wlr_output *wlr_output = &output->wlr_output;
    wlr_output_init(wlr_output, &backend->backend,
        &rdp_output_impl, backend->display);

    wlr_output->width = width;
    wlr_output->height = height;
    wlr_output->refresh = refresh_hz * 1000;
    snprintf(wlr_output->name, sizeof(wlr_output->name) - 1, "%s", name);
    wlr_output->name[sizeof(wlr_output->name) - 1] = '\0';

    wl_list_insert(&backend->outputs, &output->link);
    wlr_output_update_enabled(wlr_output, true);
    return output;
}*/
/*
static struct wlr_RDP_output *rdp_output_create(
        struct wlr_RDP_backend *backend, const char *name,
        int width, int height, int refresh_hz) {
    
    // First, allocate and zero the entire structure
    struct wlr_RDP_output *output = calloc(1, sizeof(struct wlr_RDP_output));
    if (!output) {
        wlr_log(WLR_ERROR, "Failed to allocate RDP output");
        return NULL;
    }

    // Set backend pointer
    output->backend = backend;

    // Initialize the embedded wlr_output structure
    wlr_log(WLR_DEBUG, "Initializing wlr_output");
    wlr_output_init(&output->wlr_output, &backend->backend,
                   &rdp_output_impl, backend->display);

    // Now that wlr_output is initialized, we can set its fields
    struct wlr_output *wlr_output = &output->wlr_output;
    wlr_output->width = width;
    wlr_output->height = height;
    wlr_output->refresh = refresh_hz * 1000;

    // Initialize the name now that the structure is properly set up
    const char default_name[] = "rdp-0";
    const char *output_name = name ? name : default_name;
    const size_t max_name_len = sizeof(wlr_output->name) - 1;
    strncpy(wlr_output->name, output_name, max_name_len);
    wlr_output->name[max_name_len] = '\0';

    // Add to outputs list
    wl_list_insert(&backend->outputs, &output->link);
    wlr_output_update_enabled(wlr_output, true);

    wlr_log(WLR_DEBUG, "RDP output created successfully");
    return output;
}*/
/*
static struct wlr_RDP_output *rdp_output_create(
        struct wlr_RDP_backend *backend, const char *name,
        int width, int height, int refresh_hz) {
    
    struct wlr_RDP_output *output = calloc(1, sizeof(struct wlr_RDP_output));
    if (!output) {
        wlr_log(WLR_ERROR, "Failed to allocate RDP output");
        return NULL;
    }

    output->backend = backend;
    
    // Initialize the base output
    wlr_log(WLR_DEBUG, "Initializing wlr_output");
    wlr_output_init(&output->wlr_output, &backend->backend,
                    &rdp_output_impl, backend->display);

    // Get pointer after initialization
    struct wlr_output *wlr_output = &output->wlr_output;

    // Set basic properties
    wlr_output->width = width;
    wlr_output->height = height;
    wlr_output->refresh = refresh_hz * 1000;

    // Just use static name for now for debugging
    memset(wlr_output->name, 0, 8);
    memcpy(wlr_output->name, "rdp-0", 5);

    wl_list_insert(&backend->outputs, &output->link);
    wlr_output_update_enabled(wlr_output, true);

    return output;
}*/
/*/
static struct wlr_RDP_output *rdp_output_create(
        struct wlr_RDP_backend *backend, const char *name,
        int width, int height, int refresh_hz) {
    
    struct wlr_RDP_output *output = calloc(1, sizeof(struct wlr_RDP_output));
    if (!output) {
        wlr_log(WLR_ERROR, "Failed to allocate RDP output");
        return NULL;
    }

    output->backend = backend;
    
    // Get the output pointer
    struct wlr_output *wlr_output = &output->wlr_output;
    
    // Initialize core output fields
    wlr_output_init(wlr_output, &backend->backend,
                    &rdp_output_impl, backend->display);
    wlr_output_set_name(wlr_output, name); // Assign name
    
    wlr_output_set_custom_mode(wlr_output, width, height, refresh_hz * 1000);
    wlr_output_enable(wlr_output, true);

    // Add to list and enable
    wl_list_insert(&backend->outputs, &output->link);
    
    return output;
}*/

static struct wlr_RDP_output *rdp_output_create(
        struct wlr_RDP_backend *backend, const char *name,
        int width, int height, int refresh_hz) {
    
    wlr_log(WLR_DEBUG, "Creating RDP output: %s %dx%d@%d", 
            name, width, height, refresh_hz);
    
    struct wlr_RDP_output *output = calloc(1, sizeof(struct wlr_RDP_output));
    if (!output) {
        wlr_log(WLR_ERROR, "Failed to allocate RDP output");
        return NULL;
    }

    output->backend = backend;
    struct wlr_output *wlr_output = &output->wlr_output;
    
    wlr_log(WLR_DEBUG, "Initializing output implementation");
    wlr_output_init(wlr_output, &backend->backend,
                    &rdp_output_impl, backend->display);

    // Setup output properties for surfaceless mode
    struct wlr_output_mode *mode = calloc(1, sizeof(*mode));
    if (!mode) {
        wlr_log(WLR_ERROR, "Failed to allocate output mode");
        free(output);
        return NULL;
    }

    mode->width = width;
    mode->height = height;
    mode->refresh = refresh_hz * 1000; // Convert Hz to mHz
    wlr_log(WLR_DEBUG, "Adding mode: %dx%d@%d", width, height, refresh_hz);
    wl_list_insert(&wlr_output->modes, &mode->link);

    // Set the current mode
    wlr_output_set_mode(wlr_output, mode);
    wlr_output_enable(wlr_output, true);

    // Set output name
    wlr_output_set_name(wlr_output, name);

    // Initialize output state for surfaceless mode
    wlr_output->width = width;
    wlr_output->height = height;
    wlr_output->refresh = refresh_hz * 1000;

    // Add to backend's output list
    wl_list_insert(&backend->outputs, &output->link);
    
    wlr_log(WLR_INFO, "RDP output created successfully");
    return output;
}

/* ------------------------------------------------------------------------
 * RDP backend Implementation
 * ------------------------------------------------------------------------ */
static bool rdp_backend_start(struct wlr_backend *wlr_backend) {
    struct wlr_RDP_backend *backend = RDP_backend_from_backend(wlr_backend);
    wlr_log(WLR_INFO, "Starting RDP backend");

    /* Create output */
    struct wlr_RDP_output *out = rdp_output_create(backend, "rdp-0", 1280, 720, 60);
    if (!out) {
        wlr_log(WLR_ERROR, "Failed to create RDP output");
        return false;
    }

    wlr_output_update_enabled(&out->wlr_output, true);
    wl_signal_emit_mutable(&backend->backend.events.new_output, &out->wlr_output);
    backend->started = true;
    return true;
}

/*
static void rdp_backend_destroy(struct wlr_backend *wlr_backend) {
    struct wlr_RDP_backend *backend = RDP_backend_from_backend(wlr_backend);
    if (!backend) {
        return;
    }

    // Destroy outputs
    struct wlr_RDP_output *output, *tmp;
    wl_list_for_each_safe(output, tmp, &backend->outputs, link) {
        wlr_output_destroy(&output->wlr_output);
    }

    // Safely destroy renderer
    if (backend->renderer) {
        wlr_renderer_destroy(backend->renderer);
        backend->renderer = NULL;
    }

    wlr_backend_finish(wlr_backend);
    free(backend);
}*/
/*//working but check if memory is cache heavily
static void rdp_backend_destroy(struct wlr_backend *wlr_backend) {
    struct wlr_RDP_backend *backend = RDP_backend_from_backend(wlr_backend);
    if (!backend) {
        return;
    }

    // Remove all event sources
    for (int i = 0; i < backend->fd_count; i++) {
        if (backend->fd_event_sources[i]) {
            wl_event_source_remove(backend->fd_event_sources[i]);
            backend->fd_event_sources[i] = NULL;
        }
    }

    // Destroy outputs
    struct wlr_RDP_output *output, *tmp;
    wl_list_for_each_safe(output, tmp, &backend->outputs, link) {
        wlr_output_destroy(&output->wlr_output);
    }

    // Free FreeRDP listener
    if (backend->listener) {
        freerdp_listener_free(backend->listener);
    }

    // Cleanup peers
    struct rdp_peers_item *peer, *peer_tmp;
    wl_list_for_each_safe(peer, peer_tmp, &backend->peers, link) {
        wl_list_remove(&peer->link);
        // Peer cleanup handled by rdp_peer_context_free
    }

    wlr_backend_finish(wlr_backend);
    free(backend);
}*/
/*//was working before but has a bug
static void rdp_backend_destroy(struct wlr_backend *wlr_backend) {
    struct wlr_RDP_backend *backend = RDP_backend_from_backend(wlr_backend);
    if (!backend) {
        return;
    }

    wlr_log(WLR_DEBUG, "Destroying RDP backend");

    for (int i = 0; i < backend->fd_count; i++) {
        if (backend->fd_event_sources[i]) {
            wlr_log(WLR_DEBUG, "Removing event source %d", i);
            wl_event_source_remove(backend->fd_event_sources[i]);
            backend->fd_event_sources[i] = NULL;
        }
    }

    struct wlr_RDP_output *output, *tmp;
    wl_list_for_each_safe(output, tmp, &backend->outputs, link) {
        wlr_log(WLR_DEBUG, "Destroying output %s", output->wlr_output.name);
        wlr_output_destroy(&output->wlr_output);
    }

    if (backend->listener) {
        wlr_log(WLR_DEBUG, "Freeing FreeRDP listener at %p", (void*)backend->listener);
        freerdp_listener_free(backend->listener);
    }

    struct rdp_peers_item *peer, *peer_tmp;
    int peer_count = 0;
    wl_list_for_each_safe(peer, peer_tmp, &backend->peers, link) {
        peer_count++;
        wlr_log(WLR_DEBUG, "Removing peer %d at %p", peer_count, (void*)peer->peer);
        wl_list_remove(&peer->link);
        if (peer->peer) {
            freerdp_peer_context_free(peer->peer);
            freerdp_peer_free(peer->peer);
        }
    }
    wlr_log(WLR_DEBUG, "Total peers cleaned up: %d", peer_count);

    wlr_backend_finish(wlr_backend);
    free(backend);
    wlr_log(WLR_DEBUG, "RDP backend destroyed - check 'free' memory post-exit");
}*/

static void rdp_backend_destroy(struct wlr_backend *wlr_backend) {
    struct wlr_RDP_backend *backend = (struct wlr_RDP_backend *)wlr_backend;
    if (!backend) {
        return;
    }

    // Free event sources
    for (int i = 0; i < backend->fd_count; i++) {
        if (backend->fd_event_sources[i]) {
            wl_event_source_remove(backend->fd_event_sources[i]);
            backend->fd_event_sources[i] = NULL;
            wlr_log(WLR_INFO, "Removed RDP backend FD event source %d", i);
        }
    }
    backend->fd_count = 0;

    // Free listener
    if (backend->listener) {
        freerdp_listener_free(backend->listener);
    }

    // Clean up other resources
    wl_list_remove(&backend->outputs);
    wl_list_remove(&backend->peers);

    free(backend);
    wlr_log(WLR_INFO, "RDP backend destroyed");
}

static uint32_t rdp_backend_get_buffer_caps(struct wlr_backend *wlr_backend) {
    return WLR_BUFFER_CAP_DATA_PTR | WLR_BUFFER_CAP_SHM;  // Only support data pointer and shared memory
}


static const struct wlr_backend_impl rdp_backend_impl = {
    .start = rdp_backend_start,
    .destroy = rdp_backend_destroy,
    .get_buffer_caps = rdp_backend_get_buffer_caps,
};
/* ------------------------------------------------------------------------
 * The Public Constructor for RDP Backend
 * ------------------------------------------------------------------------ */
/*
struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display) {
    wlr_log(WLR_INFO, "Creating RDP backend (surfaceless approach)");

    struct wlr_RDP_backend *backend = calloc(1, sizeof(*backend));
    if (!backend) {
        return NULL;
    }

    wlr_backend_init(&backend->backend, &rdp_backend_impl);
    backend->display = display;
    wl_list_init(&backend->outputs);

    // Set up environment for Zink and surfaceless rendering
    setenv("MESA_LOADER_DRIVER_OVERRIDE", "zink", 1);
    setenv("EGL_PLATFORM", "surfaceless", 1);
    setenv("WLR_RENDERER", "gles2", 1);  // Explicitly set to GLES2

    // Try to create renderer with more relaxed configuration
    struct wlr_renderer *renderer = wlr_renderer_autocreate(&backend->backend);
    if (!renderer) {
        wlr_log(WLR_ERROR, "Failed to create RDP renderer");
        free(backend);
        return NULL;
    }

    // Initialize renderer for Wayland display
    wlr_renderer_init_wl_display(renderer, display);

    wlr_log(WLR_INFO, "RDP backend created successfully with surfaceless renderer");
    return &backend->backend;
}*/


// Modify the backend creation function
/*
struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display) {
    wlr_log(WLR_INFO, "Creating RDP backend (surfaceless approach)");

    struct wlr_RDP_backend *backend = calloc(1, sizeof(*backend));
    if (!backend) {
        wlr_log(WLR_ERROR, "Failed to allocate RDP backend");
        return NULL;
    }

    wlr_backend_init(&backend->backend, &rdp_backend_impl);
    backend->display = display;
    wl_list_init(&backend->outputs);

    
    // Create and store renderer in the backend
    backend->renderer = wlr_renderer_autocreate(&backend->backend);
    if (!backend->renderer) {
        wlr_log(WLR_ERROR, "Failed to create RDP renderer");
        free(backend);
        return NULL;
    }

    // Initialize renderer for Wayland display
    wlr_renderer_init_wl_display(backend->renderer, display);

    wlr_log(WLR_INFO, "RDP backend created successfully with surfaceless renderer");
    return &backend->backend;
}*/
/*
struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display) {
    wlr_log(WLR_INFO, "Creating RDP backend (surfaceless approach)");

    struct wlr_RDP_backend *backend = calloc(1, sizeof(*backend));
    if (!backend) {
        wlr_log(WLR_ERROR, "Failed to allocate RDP backend");
        return NULL;
    }

    wlr_backend_init(&backend->backend, &rdp_backend_impl);
    backend->display = display;
    wl_list_init(&backend->outputs);

    // Create renderer with explicit surfaceless initialization
    backend->renderer = wlr_gles2_renderer_create_surfaceless();
    if (!backend->renderer) {
        wlr_log(WLR_ERROR, "Failed to create RDP renderer");
        free(backend);
        return NULL;
    }

    // Create allocator 
    backend->allocator = wlr_allocator_autocreate(&backend->backend, backend->renderer);
    if (!backend->allocator) {
        wlr_log(WLR_ERROR, "Failed to create RDP allocator");
        wlr_renderer_destroy(backend->renderer);
        free(backend);
        return NULL;
    }

    // Ensure EGL context is current before further operations
    struct wlr_egl *egl = wlr_gles2_renderer_get_egl(backend->renderer);
    if (!egl || !wlr_egl_make_current(egl)) {
        wlr_log(WLR_ERROR, "Failed to make EGL context current");
        wlr_renderer_destroy(backend->renderer);
        free(backend);
        return NULL;
    }

    // Initialize renderer for display
    wlr_renderer_init_wl_display(backend->renderer, display);

    wlr_log(WLR_INFO, "RDP backend created successfully with surfaceless renderer");
    return &backend->backend;
}*/

// In backend/RDP/backend.c

// In backend/RDP/backend.c
/*
struct wlr_backend *wlr_RDP_backend_create(struct wl_display *display) {
    wlr_log(WLR_INFO, "Creating RDP backend (using global renderer)");

    struct wlr_RDP_backend *backend = calloc(1, sizeof(*backend));
    if (!backend) {
        wlr_log(WLR_ERROR, "Failed to allocate wlr_RDP_backend");
        return NULL;
    }

    wlr_backend_init(&backend->backend, &rdp_backend_impl);
    backend->display = display;
    wl_list_init(&backend->outputs);

    // **Attach the global renderer to the backend**
   // backend->renderer = renderer;

    wlr_log(WLR_INFO, "RDP backend created successfully");
    return &backend->backend;
}*/



///////////////////////////////////////////////////////////


