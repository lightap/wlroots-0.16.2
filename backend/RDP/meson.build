# Dependencies
dep_freerdp_server = dependency('freerdp-server2', required: false)
dep_freerdp = dependency('freerdp2', required: false)
dep_winpr = dependency('winpr2', required: false)
dep_wayland_server = dependency('wayland-server', required: false)
dep_pixman = dependency('pixman-1', required: false)

if not dep_freerdp_server.found() or not dep_freerdp.found() or not dep_winpr.found()
    # Instead of error, just don't build the backend
    subdir_done()
endif

# Include directories
winpr_includes = include_directories('/usr/include/winpr2')
freerdp_includes = include_directories('/usr/include/freerdp2')


# Add dependencies to the global dependency list
wlr_deps += [
    dep_freerdp_server,
    dep_freerdp,
    dep_winpr,
    dep_wayland_server,
    dep_pixman
]



wlr_files += files(
	'backend.c',
	#'input_device.c',
	#'output.c',
)

features += { 'RDP-backend': true }
