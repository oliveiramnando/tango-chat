// Load generator, step 3: every message carries its own send time and sequence number.
//
// Two bots log in, do one handshake, and alice sends N messages to bob, in lockstep
// (send one, receive it, then send the next).
//
// Each message's plaintext is a "probe":
//   [8-byte send time (ns)][8-byte sequence number][padding up to the message size]
// so bob can measure each message's own trip time and notice lost, duplicated
// or out-of-order messages.
//
// Usage: ./loadgen <host> <port> [messages] [size]

#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "botclient.hpp"

using namespace std;
using Clock = chrono::steady_clock;   // steady: never jumps when the system clock is adjusted

// ---------- probes ----------

constexpr size_t PROBE_HEADER = 16;   // 8 bytes time + 8 bytes sequence number

// Nanoseconds on the steady clock. Only meaningful inside this process:
// alice and bob live in the same program, so both read the same clock.
uint64_t nowNs()
{
    return chrono::duration_cast<chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
}

// Builds [send time][seq][padding]. `size` is the total plaintext length (at least 16).
string makeProbe(uint64_t seq, size_t size)
{
    string probe(size, 'x');               // padding first; the header overwrites the start
    uint64_t sentNs = nowNs();              // stamped as late as possible, right before sending
    memcpy(probe.data(), &sentNs, 8);
    memcpy(probe.data() + 8, &seq, 8);
    return probe;
}

// Reads the header back. False if the message is too short to be a probe.
bool readProbe(const string& probe, uint64_t& seq, uint64_t& sentNs)
{
    if (probe.size() < PROBE_HEADER)
    {
        return false;
    }
    memcpy(&sentNs, probe.data(), 8);
    memcpy(&seq, probe.data() + 8, 8);
    return true;
}

// ---------- statistics ----------

// Nearest-rank percentile of an already sorted list: the smallest value that
// at least p% of the samples are less than or equal to.
uint64_t percentile(const vector<uint64_t>& sorted, double p)
{
    if (sorted.empty())
    {
        return 0;
    }
    size_t rank = static_cast<size_t>(ceil(p / 100.0 * sorted.size()));
    return sorted[max<size_t>(rank, 1) - 1];
}

double toUs(uint64_t ns)
{
    return ns / 1000.0;
}

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        cerr << "usage: " << argv[0] << " <host> <port> [messages] [size]\n";
        return 1;
    }
    const string host = argv[1];
    const int port = stoi(argv[2]);
    const int messages = (argc > 3) ? stoi(argv[3]) : 1000;
    const size_t size = (argc > 4) ? stoul(argv[4]) : 64;

    if (size < PROBE_HEADER)
    {
        cerr << "size must be at least " << PROBE_HEADER << " bytes\n";
        return 1;
    }
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
    int sendErrors = 0;
    int receiveErrors = 0;   // timeouts, decrypt failures, not a probe
    int lost = 0;            // sequence numbers that were skipped
    int outOfOrder = 0;      // older than one we already saw (duplicate or reordered)

    vector<uint64_t> latencies;   // one entry per received message, in nanoseconds
    latencies.reserve(messages);
    uint64_t expectedSeq = 0;     // the sequence number bob expects next

    const auto start = Clock::now();
    for (int i = 0; i < messages; ++i)
    {
        if (!bot::sendMessage(alice, bob.pid, aliceSession, makeProbe(i, size)))
        {
            ++sendErrors;
            cerr << "send " << i << ": " << bot::lastError() << "\n";
            break;   // the connection is probably gone; no point continuing
        }
        ++sent;

        optional<string> got = bot::receiveMessage(bob, alice.pid, bobSession);
        const uint64_t arrivedNs = nowNs();   // read the clock first, before any other work

        uint64_t seq = 0;
        uint64_t sentNs = 0;
        if (!got || !readProbe(*got, seq, sentNs))
        {
            ++receiveErrors;
            cerr << "receive " << i << ": " << (got ? "not a probe" : bot::lastError()) << "\n";
            continue;
        }
        ++received;
        latencies.push_back(arrivedNs - sentNs);

        // Order checks: in a correct run, seq is always exactly expectedSeq.
        if (seq > expectedSeq)
        {
            lost += static_cast<int>(seq - expectedSeq);   // the ones in between never came
            expectedSeq = seq + 1;
        }
        else if (seq < expectedSeq)
        {
            ++outOfOrder;   // already past this one
        }
        else
        {
            ++expectedSeq;
        }
    }
    const auto end = Clock::now();

    // ---------- report ----------
    const double seconds = chrono::duration<double>(end - start).count();
    sort(latencies.begin(), latencies.end());

    printf("messages:      %d sent, %d received (%zu bytes each)\n", sent, received, size);
    printf("errors:        %d send, %d receive\n", sendErrors, receiveErrors);
    printf("order:         %d lost, %d out of order\n", lost, outOfOrder);
    printf("elapsed:       %.3f s\n", seconds);
    printf("throughput:    %.0f msg/s\n", received / seconds);
    if (!latencies.empty())
    {
        printf("latency (us):  p50 %.1f   p90 %.1f   p99 %.1f   p99.9 %.1f   max %.1f\n",
               toUs(percentile(latencies, 50)), toUs(percentile(latencies, 90)),
               toUs(percentile(latencies, 99)), toUs(percentile(latencies, 99.9)),
               toUs(latencies.back()));
    }

    const bool clean = sendErrors == 0 && receiveErrors == 0 && lost == 0 && outOfOrder == 0;
    return clean ? 0 : 1;
}
