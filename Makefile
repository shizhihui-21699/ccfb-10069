CXX ?= c++
CXXFLAGS ?= -std=c++20 -O2 -g -Wall -Wextra -Wpedantic -Wshadow
CPPFLAGS += -Isrc
LDFLAGS ?=

BUILD := build
BIN := $(BUILD)/sctrace
SRCS := $(wildcard src/*.cpp)
OBJS := $(patsubst src/%.cpp,$(BUILD)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

TEST_BIN := $(BUILD)/sctrace_tests
TEST_SRCS := $(wildcard tests/*.cpp)
TEST_OBJS := $(patsubst tests/%.cpp,$(BUILD)/tests/%.o,$(TEST_SRCS))
LIB_OBJS := $(filter-out $(BUILD)/main.o,$(OBJS))

.PHONY: all test check-tables clean

all: $(BIN)

$(BIN): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^

$(BUILD)/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c -o $@ $<

$(BUILD)/tests/%.o: tests/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c -o $@ $<

# The CLI test runs the built binary and reads the committed examples.
$(BUILD)/tests/test_cli.o: CPPFLAGS += -DSCTRACE_BINARY='"$(abspath $(BIN))"' \
                                      -DSCTRACE_SOURCE_DIR='"$(CURDIR)"'

$(TEST_BIN): $(BIN) $(LIB_OBJS) $(TEST_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(LIB_OBJS) $(TEST_OBJS)

test: $(TEST_BIN)
	./$(TEST_BIN)

check-tables:
	python3 tools/gen_tables.py --check

clean:
	rm -rf $(BUILD)

-include $(DEPS)
