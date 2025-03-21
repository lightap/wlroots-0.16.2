RDP_libs = []
RDP_required = [
	'xcb',
	'xcb-dri3',
	'xcb-present',
	'xcb-render',
	'xcb-renderutil',
	'xcb-shm',
	'xcb-xfixes',
	'xcb-xinput',
]

msg = ['Required for RDP backend support.']
if 'RDP' in backends
	msg += 'Install "@0@" or disable the RDP backend.'
endif

foreach lib : RDP_required
	dep = dependency(lib,
		required: 'RDP' in backends,
		not_found_message: '\n'.join(msg).format(lib),
	)
	if not dep.found()
		subdir_done()
	endif

	RDP_libs += dep
endforeach

wlr_files += files(
	'backend.c',
	'input_device.c',
	'output.c',
)
wlr_deps += RDP_libs
features += { 'RDP-backend': true }
