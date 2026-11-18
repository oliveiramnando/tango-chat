// Load generator, step 4: many pairs at once.
//
// P pairs of bots (alice_i -> bob_i). For each pair:
//   - a sender thread sends M probes from alice_i as fast as it can (no waiting for delivery)
//   - a receiver thread reads them on bob_i and records each one's latency
// Every thread writes only to its own pair's stats; the main thread merges them after join().
//
// Each message's plaintext is a "probe":
//   [8-byte send time (ns)][8-byte sequence number][padding up to the message size]
//
// Usage: ./loadgen <host> <port> [pairs] [messages per pair] [size]

#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <latch>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "botclient.hpp"

using namespace std;
using Clock = chrono::steady_clock;   // steady: never jumps when the system clock is adjusted

// ---------- probes ----------

constexpr size_t PROBE_HEADER = 16;   // 8 bytes time + 8 bytes sequence number

// Nanoseconds on the steady clock. Only meaningful inside this process:
// every sender and receiver lives in this program, so they all read the same clock.
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

// ---------- one pair ----------

// Everything one pair needs. Each Pair is touched by exactly two threads during the run:
// the sender uses alice + aliceSession and writes `sent`/`sendErrors`;
// the receiver uses bob + bobSession and writes everything else.
// No field is written by both, so no mutex is needed.
struct Pair
{
    bot::Bot alice;
    bot::Bot bob;
    Session aliceSession;
    Session bobSession;

    // written by the sender thread
    int sent = 0;
    int sendErrors = 0;
    string sendError;          // first failure reason, for the report

    // written by the receiver thread
    int received = 0;
    int receiveErrors = 0;
    int lost = 0;              // sequence numbers that were skipped
    int outOfOrder = 0;        // older than one already seen (duplicate or reordered)
    vector<uint64_t> latencies;
    string receiveError;       // first failure reason, for the report
};

void runSender(Pair& p, int messages, size_t size, latch& go)
{
    go.wait();   // every thread starts at the same moment
    for (int i = 0; i < messages; ++i)
    {
        if (!bot::sendMessage(p.alice, p.bob.pid, p.aliceSession, makeProbe(i, size)))
        {
            ++p.sendErrors;
            p.sendError = bot::lastError();
            return;   // the connection is probably gone; no point continuing
        }
        ++p.sent;
    }
}

// True if the failure means nothing more will arrive on this socket.
bool isFatal(const string& error)
{
    return error.starts_with("timed out") || error.starts_with("connection closed");
}

void runReceiver(Pair& p, int messages, latch& go)
{
    p.latencies.reserve(messages);
    uint64_t expectedSeq = 0;
    go.wait();

    // Stops after `messages` probes, or when nothing has arrived for 2 s.
    while (p.received + p.receiveErrors < messages)
    {
        optional<string> got = bot::receiveMessage(p.bob, p.alice.pid, p.bobSession);
        const uint64_t arrivedNs = nowNs();   // read the clock first, before any other work

        uint64_t seq = 0;
        uint64_t sentNs = 0;
        if (!got || !readProbe(*got, seq, sentNs))
        {
            const string why = got ? "not a probe" : bot::lastError();
            if (p.receiveError.empty())
            {
                p.receiveError = why;
            }
            if (isFatal(why))
            {
                break;   // timeouts and closed connections are reported as "missing"
            }
            ++p.receiveErrors;
            continue;
        }
        ++p.received;
        p.latencies.push_back(arrivedNs - sentNs);

        if (seq > expectedSeq)
        {
            p.lost += static_cast<int>(seq - expectedSeq);   // the ones in between never came
            expectedSeq = seq + 1;
        }
        else if (seq < expectedSeq)
        {
            ++p.outOfOrder;   // already past this one
        }
        else
        {
            ++expectedSeq;
        }
    }
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
        cerr << "usage: " << argv[0] << " <host> <port> [pairs] [messages per pair] [size]\n";
        return 1;
    }
    const string host = argv[1];
    const int port = stoi(argv[2]);
    const int pairCount = (argc > 3) ? stoi(argv[3]) : 10;
    const int messages = (argc > 4) ? stoi(argv[4]) : 10000;
    const size_t size = (argc > 5) ? stoul(argv[5]) : 64;

    if (pairCount < 1 || messages < 1 || size < PROBE_HEADER)
    {
        cerr << "need pairs >= 1, messages >= 1, size >= " << PROBE_HEADER << "\n";
        return 1;
    }
    if (sodium_init() < 0)
    {
        cerr << "sodium_init failed\n";
        return 1;
    }

    // ---------- setup (not timed) ----------
    // unique_ptr because a Pair holds Bots, which can't be copied or moved,
    // and a vector needs to move its elements when it grows.
    vector<unique_ptr<Pair>> pairs;
    for (int i = 0; i < pairCount; ++i)
    {
        pairs.push_back(make_unique<Pair>());
    }

    // 1. Log everyone in, one after another.
    vector<bot::Bot*> loginOrder;
    for (auto& p : pairs)
    {
        loginOrder.push_back(&p->alice);
        loginOrder.push_back(&p->bob);
    }
    for (size_t k = 0; k < loginOrder.size(); ++k)
    {
        if (!bot::login(*loginOrder[k], host, port))
        {
            cerr << "login " << k + 1 << " of " << loginOrder.size()
                 << " failed: " << bot::lastError() << "\n";
            return 1;
        }
    }

    // 2. Every login told everyone already online "X is online". So the bot that logged in
    //    k-th (counting from 0) should get a USER_ONLINE for each bot after it. Wait for
    //    exactly those, which also checks the server announced every login.
    //    Other presence frames (e.g. bots from a previous run still going offline) are skipped.
    const size_t total = loginOrder.size();
    for (size_t k = 0; k < total; ++k)
    {
        set<PeerId> waitingFor;
        for (size_t later = k + 1; later < total; ++later)
        {
            waitingFor.insert(loginOrder[later]->pid);
        }

        while (!waitingFor.empty())
        {
            MsgType type{};
            string body;
            if (!bot::nextFrame(loginOrder[k]->sock, type, body))
            {
                cerr << "missing USER_ONLINE: " << bot::lastError() << "\n";
                return 1;
            }
            if (type == MsgType::USER_ONLINE && body.size() == PeerId{}.size())
            {
                PeerId id{};
                memcpy(id.data(), body.data(), id.size());
                waitingFor.erase(id);   // no-op if it's someone else's bot
            }
            else if (type != MsgType::USER_OFFLINE)
            {
                cerr << "unexpected frame type " << static_cast<int>(type) << " during login\n";
                return 1;
            }
        }
        loginOrder[k]->ignorePresence = true;   // from now on, presence frames are noise
    }

    // 3. Handshake each pair.
    for (auto& p : pairs)
    {
        if (!bot::handshake(p->alice, p->aliceSession, p->bob, p->bobSession))
        {
            cerr << "handshake failed: " << bot::lastError() << "\n";
            return 1;
        }
    }

    // ---------- the timed part ----------
    // The latch holds every thread at the start line until the main thread counts it down,
    // so no pair gets a head start while the others are still being created.
    latch go(1);
    vector<thread> threads;
    for (auto& p : pairs)
    {
        threads.emplace_back(runSender, ref(*p), messages, size, ref(go));
        threads.emplace_back(runReceiver, ref(*p), messages, ref(go));
    }

    const auto start = Clock::now();
    go.count_down();
    for (thread& t : threads)
    {
        t.join();
    }
    const auto end = Clock::now();

    // ---------- merge (after join, so no thread is still writing) ----------
    int sent = 0, received = 0, sendErrors = 0, receiveErrors = 0, lost = 0, outOfOrder = 0;
    vector<uint64_t> latencies;
    vector<string> reasons;
    for (auto& p : pairs)
    {
        sent += p->sent;
        received += p->received;
        sendErrors += p->sendErrors;
        receiveErrors += p->receiveErrors;
        lost += p->lost;
        outOfOrder += p->outOfOrder;
        latencies.insert(latencies.end(), p->latencies.begin(), p->latencies.end());
        for (const string& why : {p->sendError, p->receiveError})
        {
            if (!why.empty() && reasons.size() < 5)
            {
                reasons.push_back(why);
            }
        }
    }
    const int missing = sent - received - receiveErrors;   // sent, but never arrived at all

    // ---------- report ----------
    const double seconds = chrono::duration<double>(end - start).count();
    sort(latencies.begin(), latencies.end());

    printf("pairs:         %d (%zu bots), %d messages each, %zu bytes\n",
           pairCount, total, messages, size);
    printf("messages:      %d sent, %d received\n", sent, received);
    printf("errors:        %d send, %d receive\n", sendErrors, receiveErrors);
    printf("order:         %d missing, %d lost, %d out of order\n", missing, lost, outOfOrder);
    printf("elapsed:       %.3f s\n", seconds);
    printf("throughput:    %.0f msg/s\n", received / seconds);
    if (!latencies.empty())
    {
        printf("latency (us):  p50 %.1f   p90 %.1f   p99 %.1f   p99.9 %.1f   max %.1f\n",
               toUs(percentile(latencies, 50)), toUs(percentile(latencies, 90)),
               toUs(percentile(latencies, 99)), toUs(percentile(latencies, 99.9)),
               toUs(latencies.back()));
    }
    for (const string& why : reasons)
    {
        printf("  e.g. %s\n", why.c_str());
    }

    const bool clean = sendErrors == 0 && receiveErrors == 0 && missing == 0 &&
                       lost == 0 && outOfOrder == 0;
    return clean ? 0 : 1;
}
