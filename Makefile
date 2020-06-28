all: hotfs.exe hotfs2.exe

%.exe: %.c
	gcc -Wall -O0 -g3 $< `pkg-config fuse3 --cflags --libs` -o $@

%.exe: %.cc
	g++ -Wall -O0 -g3 $< `pkg-config fuse3 --cflags --libs` -o $@

test: hotfs.exe
	mkdir hot
	mkdir cold
	mkdir cold/cold
	mkdir cold/cold/mounted
	touch cold/cold/mounted/cold
	echo "a: b ; echo hello world > a" > cold/Makefile
	./hotfs.exe cold hot &
	while ! [ -e hot/hot/mounted ]; do sleep 1; done
	umount hot

