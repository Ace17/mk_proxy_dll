all: make_proxy_dll

clean:
	rm -f *.o pe_headers.h header_gen make_proxy_dll

make_proxy_dll: main.o
	g++ $^ -o "$@"

main.o: main.cpp pe_headers.h
	g++ -c -o "$@" $<

pe_headers.h: header_gen
	./header_gen > "$@"

header_gen: header_gen.cpp
	g++ -o "$@" $^
