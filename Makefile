all: hotfs.exe

%.exe: %.c
	gcc -Wall -O0 -g3 $< `pkg-config fuse3 --cflags --libs` -o $@

%.exe: %.cc
	g++ -Wall -O0 -g3 $< `pkg-config fuse3 --cflags --libs` -o $@

test: hotfs.exe
	mkdir build
	mkdir test
	echo "a: b ; echo hello world > a" > build/Makefile
	./hotfs.exe build test &
	touch test/b
	cat test/a
	umount test

