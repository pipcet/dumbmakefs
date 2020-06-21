all: dumbmakefs.exe passthrough.exe

%.exe: %.c
	gcc -Wall -O0 -g3 $< `pkg-config fuse3 --cflags --libs` -o $@
