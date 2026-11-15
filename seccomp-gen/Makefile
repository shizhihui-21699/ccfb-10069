# seccomp-gen: strace -> minimal seccomp-bpf policy + interpreter/verifier
CXX ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion
LDFLAGS ?=

SRCS = src/main.cpp src/common.cpp src/syscall_table.cpp src/strace_parser.cpp \
       src/policy.cpp src/bpf.cpp src/compiler.cpp src/verifier.cpp
OBJS = $(SRCS:.cpp=.o)

bin/seccomp-gen: $(OBJS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY: clean test selftest
clean:
	rm -f $(OBJS) bin/seccomp-gen

selftest: bin/seccomp-gen
	./bin/seccomp-gen selftest

test: bin/seccomp-gen
	./tests/run_tests.sh
