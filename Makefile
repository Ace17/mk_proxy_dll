all: bin/make_proxy_dll

clean:
	rm -rf bin
	mkdir bin

bin/make_proxy_dll: bin/main.o
	g++ $^ -o "$@"

bin/main.o: src/main.cpp bin/pe_headers.h
	g++ -Ibin -c -o "$@" $<

bin/pe_headers.h: bin/header_gen
	./bin/header_gen > "$@"

bin/header_gen: src/header_gen.cpp
	g++ -o "$@" $^

