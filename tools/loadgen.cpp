// Load generator, step 2: the smallest possible version.
//
// Two bots log in, do one handshake, and alice sends N messages to bob.
// Each message is sent and then received before the next one goes out ("lockstep"),
// so this measures one message's trip through the server, not maximum throughput.
//
// Usage: ./loadgen <host> <port> [messages]

#include <sodium.h>

#include <chrono>
#include <cstdio>
#include <iostream>
#include <string>

#include "botclient.hpp"

using namespace std;
using Clock = chrono::steady_clock;   // steady: never jumps when the system clock is adjusted

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        cerr << "usage: " << argv[0] << " <host> <port> [messages]\n";
        return 1;
    }
    const string host = argv[1];
    const int port = stoi(argv[2]);
    const int messages = (argc > 3) ? stoi(argv[3]) : 1000;

    if (sodium_init() < 0)
    {
        cerr << "sodium_init failed\n";
        return 1;
    }

    // ---------- setup (not timed) ----------
    bot::Bot alice;
    bot::Bot bob;

    if (!bot::login(alice, host, port) || !bot::login(bob, host, port))
    {
        cerr << "login failed: " << bot::lastError() << "\n";
        return 1;
    }

    // Bob logging in makes the server tell alice "bob is online".
    // Read that frame now, otherwise alice would find it where she expects bob's reply.
    string body;
    if (!bot::expectFrame(alice.sock, MsgType::USER_ONLINE, body))
    {
        cerr << "missing USER_ONLINE: " << bot::lastError() << "\n";
        return 1;
    }

    Session aliceSession;
    Session bobSession;
    if (!bot::handshake(alice, aliceSession, bob, bobSession))
    {
        cerr << "handshake failed: " << bot::lastError() << "\n";
        return 1;
    }

    // ---------- the timed part ----------
    int sent = 0;
    int received = 0;
    int errors = 0;
    const string text(64, 'x');   // a fixed 64-byte message

    const auto start = Clock::now();
    for (int i = 0; i < messages; ++i)
    {
        if (!bot::sendMessage(alice, bob.pid, aliceSession, text))
        {
            ++errors;
            cerr << "send " << i << ": " << bot::lastError() << "\n";
            break;   // the connection is probably gone; no point continuing
        }
        ++sent;

        optional<string> got = bot::receiveMessage(bob, alice.pid, bobSession);
        if (!got || *got != text)
        {
            ++errors;
            cerr << "receive " << i << ": " << (got ? "wrong content" : bot::lastError()) << "\n";
            continue;
        }
        ++received;
    }
    const auto end = Clock::now();

    // ---------- report ----------
    const double seconds = chrono::duration<double>(end - start).count();
    printf("messages sent:     %d\n", sent);
    printf("messages received: %d\n", received);
    printf("errors:            %d\n", errors);
    printf("elapsed:           %.3f s\n", seconds);
    printf("throughput:        %.0f msg/s\n", received / seconds);
    printf("average trip:      %.1f us\n", seconds / received * 1e6);

    return errors == 0 ? 0 : 1;
}
