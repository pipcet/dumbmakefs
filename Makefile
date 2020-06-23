all: hotfs.exe

%.exe: %.c
	gcc -Wall -O0 -g3 $< `pkg-config fuse3 --cflags --libs` -o $@

%.exe: %.cc
	g++ -Wall -O0 -g3 $< `pkg-config fuse3 --cflags --libs` -o $@

test: hotfs.exe
	mkdir build
	mkdir test
	touch build/mounted
	echo "a: b ; echo hello world > a" > build/Makefile
	./hotfs.exe build test &
	while ! [ -e test/mounted ]; do sleep 1; done
	touch test/b
	cat test/a
	umount test

