all: dumbmakefs.exe passthrough.exe passthrough_hp.exe hotfs.exe

%.exe: %.c
	gcc -Wall -O0 -g3 $< `pkg-config fuse3 --cflags --libs` -o $@

%.exe: %.cc
	g++ -Wall -O0 -g3 $< `pkg-config fuse3 --cflags --libs` -o $@
