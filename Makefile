all: bin/make_proxy_dll

CXXFLAGS+=-std=c++11

clean:
	rm -rf bin
	mkdir bin

bin/make_proxy_dll: bin/main.o
	@mkdir -p $(dir $@)
	g++ $(CXXFLAGS) $^ -o "$@"

bin/main.o: src/main.cpp bin/pe_headers.h
	@mkdir -p $(dir $@)
	g++ $(CXXFLAGS) -Ibin -c -o "$@" $<

bin/pe_headers.h: bin/header_gen
	@mkdir -p $(dir $@)
	./bin/header_gen > "$@"

bin/header_gen: src/header_gen.cpp
	@mkdir -p $(dir $@)
	g++ $(CXXFLAGS) -o "$@" $^

