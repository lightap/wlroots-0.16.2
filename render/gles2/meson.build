glesv2 = dependency('glesv2', required: 'gles2' in renderers)

if not (glesv2.found() and internal_features['egl'])
	subdir_done()
endif

features += { 'gles2-renderer': true }
wlr_deps += glesv2

wlr_files += files(
	'pixel_format.c',
	'renderer.c',
	'texture.c',
	'surfaceless.c',
)

subdir('shaders')
