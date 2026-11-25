CXX      = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -g -Isrc/common -Isrc/core -Isrc/bot
LDLIBS   = -lsodium

# Code shared by the client, the server and the tests
COMMON_SRCS = src/common/net.cpp src/common/crypto.cpp
COMMON_HDRS = src/common/net.hpp src/common/crypto.hpp

# The headless bot client, used by the tests and the load generator
BOT_SRCS = src/bot/botclient.cpp
BOT_HDRS = src/bot/botclient.hpp

# The client's logic, with no I/O: used by the terminal client (and the tests)
CORE_SRCS = src/core/util.cpp src/core/contacts.cpp src/core/handshake.cpp src/core/chatcore.cpp
CORE_HDRS = src/core/util.hpp src/core/contacts.hpp src/core/handshake.hpp src/core/chatcore.hpp

TEST_FLAGS = $(CXXFLAGS) -fsanitize=address,undefined -fno-sanitize-recover=all
TEST_SRCS  = $(wildcard tests/test_*.cpp)

# The load generator is built optimised and without sanitizers,
# because we want to measure the server, not the tool's own overhead.
LOADGEN_FLAGS = -std=c++20 -Wall -Wextra -O2 -pthread -Isrc/common -Isrc/bot

all: server client

server: src/server/server.cpp $(COMMON_SRCS) $(COMMON_HDRS)
	$(CXX) $(CXXFLAGS) src/server/server.cpp $(COMMON_SRCS) -o server $(LDLIBS)

client: src/terminal/client.cpp $(CORE_SRCS) $(CORE_HDRS) $(COMMON_SRCS) $(COMMON_HDRS)
	$(CXX) $(CXXFLAGS) src/terminal/client.cpp $(CORE_SRCS) $(COMMON_SRCS) -o client $(LDLIBS)

run_tests: $(TEST_SRCS) $(BOT_SRCS) $(BOT_HDRS) $(CORE_SRCS) $(CORE_HDRS) $(COMMON_SRCS) $(COMMON_HDRS)
	$(CXX) $(TEST_FLAGS) $(TEST_SRCS) $(BOT_SRCS) $(CORE_SRCS) $(COMMON_SRCS) -o run_tests $(LDLIBS)

loadgen: tools/loadgen.cpp $(BOT_SRCS) $(BOT_HDRS) $(COMMON_SRCS) $(COMMON_HDRS)
	$(CXX) $(LOADGEN_FLAGS) tools/loadgen.cpp $(BOT_SRCS) $(COMMON_SRCS) -o loadgen $(LDLIBS)

test: run_tests server
	./run_tests

clean:
	rm -f server client run_tests loadgen server_test.log

.PHONY: all clean test
