# Define paths and tools
WAYLAND_PROTOCOLS=$(shell pkg-config --variable=pkgdatadir wayland-protocols)
WAYLAND_SCANNER=$(shell pkg-config --variable=wayland_scanner wayland-scanner)

# Libraries with explicit cflags and libs for wlroots, wayland, and dependencies
# Use PKG_CONFIG_PATH to prioritize /usr/local/ for debug wlroots
LIBS=\
	$(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$$PKG_CONFIG_PATH pkg-config --cflags --libs wlroots) \
	$(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$$PKG_CONFIG_PATH pkg-config --cflags --libs wayland-server) \
	$(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$$PKG_CONFIG_PATH pkg-config --cflags --libs xkbcommon) \
	$(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$$PKG_CONFIG_PATH pkg-config --cflags --libs pixman-1) \
	$(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$$PKG_CONFIG_PATH pkg-config --cflags --libs libdrm) \
	-lfreerdp2

# Generate xdg-shell protocol header
xdg-shell-protocol.h:
	$(WAYLAND_SCANNER) server-header \
		$(WAYLAND_PROTOCOLS)/stable/xdg-shell/xdg-shell.xml $@

# Build tinywl with debug symbols
tinywl: tinywl.c xdg-shell-protocol.h
	$(CC) $(CFLAGS) \
		-g -O0 -Wall -Wextra -I. \
		-DWLR_USE_UNSTABLE \
		-o $@ $< \
		$(LIBS)

# Clean up
clean:
	rm -f tinywl xdg-shell-protocol.h

# Default target
.DEFAULT_GOAL=tinywl

# Phony targets
.PHONY: clean