CXX      = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -g -Isrc
LDLIBS   = -lsodium

# Code shared by the client, the server and the tests
COMMON_SRCS = src/net.cpp src/crypto.cpp
COMMON_HDRS = src/net.hpp src/crypto.hpp

# The headless bot client, used by the tests and the load generator
BOT_SRCS = src/botclient.cpp
BOT_HDRS = src/botclient.hpp

# Code only the client (and the tests) use
CLIENT_SRCS = src/util.cpp src/contacts.cpp
CLIENT_HDRS = src/util.hpp src/contacts.hpp

TEST_FLAGS = $(CXXFLAGS) -fsanitize=address,undefined -fno-sanitize-recover=all
TEST_SRCS  = $(wildcard tests/test_*.cpp)

# The load generator is built optimised and without sanitizers,
# because we want to measure the server, not the tool's own overhead.
LOADGEN_FLAGS = -std=c++20 -Wall -Wextra -O2 -pthread -Isrc

all: server client

server: src/server.cpp $(COMMON_SRCS) $(COMMON_HDRS)
	$(CXX) $(CXXFLAGS) src/server.cpp $(COMMON_SRCS) -o server $(LDLIBS)

client: src/client.cpp $(CLIENT_SRCS) $(CLIENT_HDRS) $(COMMON_SRCS) $(COMMON_HDRS)
	$(CXX) $(CXXFLAGS) src/client.cpp $(CLIENT_SRCS) $(COMMON_SRCS) -o client $(LDLIBS)

run_tests: $(TEST_SRCS) $(BOT_SRCS) $(BOT_HDRS) $(CLIENT_SRCS) $(CLIENT_HDRS) $(COMMON_SRCS) $(COMMON_HDRS)
	$(CXX) $(TEST_FLAGS) $(TEST_SRCS) $(BOT_SRCS) $(CLIENT_SRCS) $(COMMON_SRCS) -o run_tests $(LDLIBS)

loadgen: tools/loadgen.cpp $(BOT_SRCS) $(BOT_HDRS) $(COMMON_SRCS) $(COMMON_HDRS)
	$(CXX) $(LOADGEN_FLAGS) tools/loadgen.cpp $(BOT_SRCS) $(COMMON_SRCS) -o loadgen $(LDLIBS)

test: run_tests server
	./run_tests

clean:
	rm -f server client run_tests loadgen server_test.log

.PHONY: all clean test
