all: hotfs.exe

%.exe: %.c
	gcc -Wall -O0 -g3 $< `pkg-config fuse3 --cflags --libs` -o $@

%.exe: %.cc
	g++ -Wall -O0 -g3 $< `pkg-config fuse3 --cflags --libs` -o $@

test: hotfs.exe
	mkdir hot
	mkdir cold
	touch cold/mounted
	echo "a: b ; echo hello world > a" > cold/Makefile
	./hotfs.exe cold hot &
	while ! [ -e hot/mounted ]; do sleep 1; done
	touch hot/b
	cat hot/a
	umount hot

