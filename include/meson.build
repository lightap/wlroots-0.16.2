subdir('wlr')

exclude_files = ['meson.build', 'config.h.in', 'version.h.in']
if not features.get('drm-backend')
	exclude_files += 'backend/drm.h'
	exclude_files += 'types/wlr_drm_lease_v1.h'
endif
if not features.get('libinput-backend')
	exclude_files += 'backend/libinput.h'
endif
if not features.get('RDP-backend')
	exclude_files += 'backend/RDP.h'
endif
if not features.get('xwayland')
	exclude_files += 'xwayland.h'
else
	subdir('xwayland')
endif
if not features.get('gles2-renderer')
	exclude_files += ['render/egl.h', 'render/gles2.h']
endif
if not features.get('vulkan-renderer')
	exclude_files += 'render/vulkan.h'
endif

install_subdir('wlr',
	install_dir: get_option('includedir'),
	exclude_files: exclude_files,
)
