// Load generator: drives the chat server with many headless bot clients and reports
// correctness, throughput, latency and fairness.
//
// P pairs of bots (alice_i -> bob_i). For each pair:
//   - a sender thread sends M probes from alice_i, either as fast as it can or at a fixed
//     rate (--rate), never waiting for delivery
//   - a receiver thread reads them on bob_i and records when each one was sent and arrived
// Every thread writes only to its own pair's data; the main thread merges after join().
//
// Each message's plaintext is a "probe":
//   [8-byte send time (ns)][8-byte sequence number][padding up to the message size]
//
// The report separates:
//   - correctness (every run):    sent / delivered / errors / missing / lost / out of order
//   - performance (after warm-up): throughput and latency of the steady part of the run
//   - fairness:                    how differently the pairs were treated
// and ends with one key=value line, easy to collect from many runs with grep.
//
// Usage: ./loadgen [--host H] [--port N] [--pairs N] [--messages N] [--size N] [--rate N]
//        ./loadgen --help

#include <sodium.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
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

// The first WARMUP_FRACTION of each pair's messages are delivered and checked like any other,
// but left out of the performance numbers: caches, branch predictors, socket buffers and the
// CPU's clock speed all need a moment to settle, and the start of a run is never typical.
constexpr double WARMUP_FRACTION = 0.10;

// ---------- probes ----------

constexpr size_t PROBE_HEADER = 16;   // 8 bytes time + 8 bytes sequence number

// Nanoseconds on the steady clock. Only meaningful inside this process:
// every sender and receiver lives in this program, so they all read the same clock.
uint64_t nowNs()
{
    return chrono::duration_cast<chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
}

// Builds [send time][seq][padding]. `size` is the total plaintext length (at least 16).
// `sentNs` is the time the message counts as sent from (see runSender for why that
// isn't always "now").
string makeProbe(uint64_t seq, uint64_t sentNs, size_t size)
{
    string probe(size, 'x');               // padding first; the header overwrites the start
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

// ---------- configuration ----------

struct Config
{
    string host = "127.0.0.1";
    int port = 9000;
    int pairs = 10;
    int messages = 10000;   // per pair
    size_t size = 64;       // plaintext bytes per message
    double rate = 0;        // messages per second per pair; 0 = as fast as possible

    int warmupMessages() const { return static_cast<int>(messages * WARMUP_FRACTION); }
    bool paced() const { return rate > 0; }
};

// A sender counts as "behind" when a message goes out more than this long after its slot.
constexpr uint64_t LATE_NS = 1'000'000;   // 1 ms

// ---------- one pair ----------

// One delivered message.
struct Sample
{
    uint64_t seq;
    uint64_t sentNs;
    uint64_t arrivedNs;
};

// Everything one pair needs. Each Pair is touched by exactly two threads during the run:
// the sender uses alice + aliceSession and writes `sent`/`sendErrors`/`sendError`;
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
    int late = 0;              // paced runs: messages sent more than LATE_NS after their slot
    uint64_t maxLagNs = 0;     // paced runs: the furthest behind schedule the sender got

    // written by the receiver thread
    vector<Sample> samples;    // one per delivered message, in arrival order
    int receiveErrors = 0;
    int lost = 0;              // sequence numbers that were skipped
    int outOfOrder = 0;        // older than one already seen (duplicate or reordered)
    string receiveError;       // first failure reason, for the report
};

// Unpaced: send as fast as possible; each message counts as sent when it is built.
//
// Paced (--rate R): message i has a fixed slot at start + i/R. The sender sleeps until the
// slot, then sends. If it is already late (the server or this machine fell behind), it sends
// straight away to catch up, without sleeping.
//
// In a paced run each message counts as sent at its SLOT, not when it actually went out.
// Otherwise a stall hides itself: while the sender is stuck, it isn't sending, so no message
// "experiences" the stall, and the latency numbers look fine. A real user who pressed enter
// at that slot would have waited the whole time. Measuring from the slot charges the delay to
// every message that should have been sent during it. (This mistake is known as
// "coordinated omission".)
void runSender(Pair& p, const Config& cfg, latch& go)
{
    go.wait();   // every thread starts at the same moment
    const uint64_t startNs = nowNs();
    const double slotNs = cfg.paced() ? 1e9 / cfg.rate : 0;

    for (int i = 0; i < cfg.messages; ++i)
    {
        uint64_t sentNs = 0;
        if (cfg.paced())
        {
            const uint64_t slot = startNs + static_cast<uint64_t>(i * slotNs);
            uint64_t now = nowNs();
            if (now < slot)
            {
                this_thread::sleep_for(chrono::nanoseconds(slot - now));
                now = nowNs();
            }
            const uint64_t lag = now > slot ? now - slot : 0;
            p.maxLagNs = max(p.maxLagNs, lag);
            if (lag > LATE_NS)
            {
                ++p.late;
            }
            sentNs = slot;
        }
        else
        {
            sentNs = nowNs();   // stamped as late as possible, right before sending
        }

        if (!bot::sendMessage(p.alice, p.bob.pid, p.aliceSession, makeProbe(i, sentNs, cfg.size)))
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

void runReceiver(Pair& p, const Config& cfg, latch& go)
{
    p.samples.reserve(cfg.messages);
    uint64_t expectedSeq = 0;
    go.wait();

    // Stops after `messages` probes, or when nothing has arrived for 2 s.
    while (static_cast<int>(p.samples.size()) + p.receiveErrors < cfg.messages)
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
        p.samples.push_back({seq, sentNs, arrivedNs});

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

// ---------- setup ----------

// Logs every bot in, waits for the presence announcements, and handshakes each pair.
// Returns false (after printing why) if anything fails.
bool setUp(vector<unique_ptr<Pair>>& pairs, const Config& cfg)
{
    // 1. Log everyone in, one after another.
    vector<bot::Bot*> loginOrder;
    for (auto& p : pairs)
    {
        loginOrder.push_back(&p->alice);
        loginOrder.push_back(&p->bob);
    }
    for (size_t k = 0; k < loginOrder.size(); ++k)
    {
        if (!bot::login(*loginOrder[k], cfg.host, cfg.port))
        {
            cerr << "login " << k + 1 << " of " << loginOrder.size()
                 << " failed: " << bot::lastError() << "\n";
            return false;
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
                return false;
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
                return false;
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
            return false;
        }
    }
    return true;
}

// ---------- the run ----------

// Starts a sender and a receiver thread per pair, releases them together, waits for all.
// Returns the steady-clock time (ns) at which they were released.
uint64_t runLoad(vector<unique_ptr<Pair>>& pairs, const Config& cfg)
{
    // The latch holds every thread at the start line until the main thread counts it down,
    // so no pair gets a head start while the others are still being created.
    latch go(1);
    vector<thread> threads;
    for (auto& p : pairs)
    {
        threads.emplace_back(runSender, ref(*p), cref(cfg), ref(go));
        threads.emplace_back(runReceiver, ref(*p), cref(cfg), ref(go));
    }

    const uint64_t startNs = nowNs();
    go.count_down();
    for (thread& t : threads)
    {
        t.join();   // after this, no thread is writing to any Pair any more
    }
    return startNs;
}

// ---------- statistics ----------

// Nearest-rank percentile of an already sorted list: the smallest value that
// at least p% of the samples are less than or equal to.
template <typename T>
T percentile(const vector<T>& sorted, double p)
{
    if (sorted.empty())
    {
        return T{};
    }
    size_t rank = static_cast<size_t>(ceil(p / 100.0 * sorted.size()));
    return sorted[max<size_t>(rank, 1) - 1];
}

// Everything the report prints, computed once from the pairs.
struct Summary
{
    // correctness, over every message
    int sent = 0, delivered = 0, sendErrors = 0, receiveErrors = 0;
    int missing = 0, lost = 0, outOfOrder = 0;
    vector<string> reasons;          // a few example failure reasons
    double totalSeconds = 0;         // release of the threads -> last message delivered

    // paced runs: did the senders actually keep to the schedule?
    int late = 0;                    // messages sent more than LATE_NS after their slot
    uint64_t maxLagNs = 0;

    // performance, over messages after warm-up only
    size_t measured = 0;             // how many messages that is
    double windowSeconds = 0;        // first to last measured arrival
    double throughput = 0;           // measured / windowSeconds
    vector<uint64_t> latencies;      // sorted, ns

    // fairness: one value per pair
    vector<double> pairThroughput;   // msg/s, over the whole run
    vector<double> pairFinish;       // seconds from release to that pair's last delivery
    vector<double> pairP50;          // that pair's own median latency, us

    bool clean() const
    {
        return sendErrors == 0 && receiveErrors == 0 && missing == 0 && lost == 0 &&
               outOfOrder == 0;
    }
};

Summary summarize(const vector<unique_ptr<Pair>>& pairs, const Config& cfg, uint64_t startNs)
{
    Summary s;
    const uint64_t warmup = static_cast<uint64_t>(cfg.warmupMessages());
    uint64_t firstMeasured = UINT64_MAX;
    uint64_t lastMeasured = 0;
    uint64_t lastArrival = startNs;

    for (const auto& p : pairs)
    {
        s.sent += p->sent;
        s.delivered += static_cast<int>(p->samples.size());
        s.sendErrors += p->sendErrors;
        s.receiveErrors += p->receiveErrors;
        s.lost += p->lost;
        s.outOfOrder += p->outOfOrder;
        s.late += p->late;
        s.maxLagNs = max(s.maxLagNs, p->maxLagNs);
        for (const string& why : {p->sendError, p->receiveError})
        {
            if (!why.empty() && s.reasons.size() < 5)
            {
                s.reasons.push_back(why);
            }
        }

        vector<uint64_t> own;   // this pair's latencies, for its own median
        for (const Sample& m : p->samples)
        {
            lastArrival = max(lastArrival, m.arrivedNs);
            if (m.seq < warmup)
            {
                continue;   // warm-up: checked above, not measured
            }
            const uint64_t latency = m.arrivedNs - m.sentNs;
            s.latencies.push_back(latency);
            own.push_back(latency);
            firstMeasured = min(firstMeasured, m.arrivedNs);
            lastMeasured = max(lastMeasured, m.arrivedNs);
        }

        if (!p->samples.empty())
        {
            const double finish = (p->samples.back().arrivedNs - startNs) / 1e9;
            s.pairFinish.push_back(finish);
            s.pairThroughput.push_back(p->samples.size() / finish);
        }
        if (!own.empty())
        {
            sort(own.begin(), own.end());
            s.pairP50.push_back(percentile(own, 50) / 1000.0);
        }
    }

    s.missing = s.sent - s.delivered - s.receiveErrors;   // sent, but never arrived at all
    s.totalSeconds = (lastArrival - startNs) / 1e9;
    s.measured = s.latencies.size();
    if (s.measured > 1)
    {
        s.windowSeconds = (lastMeasured - firstMeasured) / 1e9;
        s.throughput = s.windowSeconds > 0 ? s.measured / s.windowSeconds : 0;
    }

    sort(s.latencies.begin(), s.latencies.end());
    sort(s.pairThroughput.begin(), s.pairThroughput.end());
    sort(s.pairFinish.begin(), s.pairFinish.end());
    sort(s.pairP50.begin(), s.pairP50.end());
    return s;
}

// ---------- report ----------

string localTime()
{
    time_t now = time(nullptr);
    char text[32];
    strftime(text, sizeof(text), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return text;
}

string hostName()
{
    char name[256] = {};
    gethostname(name, sizeof(name) - 1);
    return name;
}

double us(uint64_t ns)
{
    return ns / 1000.0;
}

void printReport(const Summary& s, const Config& cfg)
{
    // What was measured, where and when: a result without this is hard to compare later.
    printf("run         %s  on %s (%u CPUs)  -> %s:%d\n", localTime().c_str(),
           hostName().c_str(), thread::hardware_concurrency(), cfg.host.c_str(), cfg.port);
    printf("load        %d pairs (%d bots), %d messages each, %zu bytes, first %d per pair = warm-up\n",
           cfg.pairs, cfg.pairs * 2, cfg.messages, cfg.size, cfg.warmupMessages());
    if (cfg.paced())
    {
        printf("rate        %.0f msg/s per pair = %.0f msg/s offered in total\n",
               cfg.rate, cfg.rate * cfg.pairs);
    }
    else
    {
        printf("rate        unlimited (senders never wait: latency = time spent queued)\n");
    }

    // Correctness first: performance numbers mean nothing if messages went missing.
    printf("delivery    %d / %d delivered   errors: %d send, %d receive   "
           "missing %d, lost %d, out of order %d   -> %s\n",
           s.delivered, s.sent, s.sendErrors, s.receiveErrors, s.missing, s.lost, s.outOfOrder,
           s.clean() ? "OK" : "FAILED");
    for (const string& why : s.reasons)
    {
        printf("              e.g. %s\n", why.c_str());
    }

    // A paced run only means something if the load was actually applied. If the senders fell
    // behind, the server (or this machine) couldn't keep up with the offered rate.
    if (cfg.paced())
    {
        const double latePct = s.sent > 0 ? 100.0 * s.late / s.sent : 0;
        printf("schedule    %d sent >1 ms late (%.1f%%), worst lag %.1f ms   -> %s\n",
               s.late, latePct, s.maxLagNs / 1e6,
               latePct < 1.0 ? "kept up" : "FELL BEHIND (couldn't keep to the schedule)");
    }

    printf("time        %.3f s total, %.3f s measured\n", s.totalSeconds, s.windowSeconds);
    printf("throughput  %.0f msg/s (after warm-up)\n", s.throughput);
    if (!s.latencies.empty())
    {
        printf("latency us  p50 %.1f   p90 %.1f   p99 %.1f   p99.9 %.1f   max %.1f\n",
               us(percentile(s.latencies, 50)), us(percentile(s.latencies, 90)),
               us(percentile(s.latencies, 99)), us(percentile(s.latencies, 99.9)),
               us(s.latencies.back()));
    }

    // Fairness: with one shared server, some pairs can be starved while others race ahead.
    // Compare the slowest pair with the median one; a big gap means unfair treatment.
    if (!s.pairFinish.empty())
    {
        printf("per pair    msg/s   min %.0f  median %.0f  max %.0f\n",
               s.pairThroughput.front(), percentile(s.pairThroughput, 50),
               s.pairThroughput.back());
        printf("            done at min %.3f s  median %.3f s  max %.3f s\n",
               s.pairFinish.front(), percentile(s.pairFinish, 50), s.pairFinish.back());
    }
    if (!s.pairP50.empty())
    {
        printf("            p50 us  min %.1f  median %.1f  max %.1f\n",
               s.pairP50.front(), percentile(s.pairP50, 50), s.pairP50.back());
    }

    // One line with everything, for scripts: ./loadgen ... | grep '^summary'
    printf("summary pairs=%d messages=%d size=%zu rate=%.0f ok=%d delivered=%d missing=%d lost=%d "
           "ooo=%d errors=%d late=%d throughput=%.0f p50_us=%.1f p99_us=%.1f max_us=%.1f\n",
           cfg.pairs, cfg.messages, cfg.size, cfg.rate, s.clean() ? 1 : 0, s.delivered, s.missing,
           s.lost, s.outOfOrder, s.sendErrors + s.receiveErrors, s.late, s.throughput,
           us(percentile(s.latencies, 50)), us(percentile(s.latencies, 99)),
           s.latencies.empty() ? 0.0 : us(s.latencies.back()));
}

// ---------- options ----------

void printUsage(const char* program)
{
    const Config d;   // the defaults
    printf("usage: %s [options]\n"
           "  --host H        server address          (default %s)\n"
           "  --port N        server port             (default %d)\n"
           "  --pairs N       sender/receiver pairs   (default %d)\n"
           "  --messages N    messages per pair       (default %d)\n"
           "  --size N        bytes per message, >= %zu (default %zu)\n"
           "  --rate N        msg/s per pair, 0 = as fast as possible (default 0)\n"
           "  --help          show this\n",
           program, d.host.c_str(), d.port, d.pairs, d.messages, PROBE_HEADER, d.size);
}

// Fills `cfg` from --name value pairs. Returns false (after printing why) on a bad option.
bool parseOptions(int argc, char* argv[], Config& cfg)
{
    for (int i = 1; i < argc; ++i)
    {
        const string name = argv[i];
        if (name == "--help" || name == "-h")
        {
            printUsage(argv[0]);
            exit(0);
        }
        if (i + 1 >= argc)
        {
            cerr << name << " needs a value (see --help)\n";
            return false;
        }
        const string value = argv[++i];   // consume the value too

        // stoi/stod throw on text that isn't a number; turn that into a clear message.
        try
        {
            size_t used = 0;
            if (name == "--host")          { cfg.host = value; used = value.size(); }
            else if (name == "--port")     { cfg.port = stoi(value, &used); }
            else if (name == "--pairs")    { cfg.pairs = stoi(value, &used); }
            else if (name == "--messages") { cfg.messages = stoi(value, &used); }
            else if (name == "--size")     { cfg.size = stoul(value, &used); }
            else if (name == "--rate")     { cfg.rate = stod(value, &used); }
            else
            {
                cerr << "unknown option " << name << " (see --help)\n";
                return false;
            }
            if (used != value.size())   // e.g. "10x": stoi reads the 10 and stops
            {
                throw invalid_argument("trailing characters");
            }
        }
        catch (const exception&)
        {
            cerr << "invalid value for " << name << ": " << value << "\n";
            return false;
        }
    }

    if (cfg.pairs < 1 || cfg.messages < 1 || cfg.size < PROBE_HEADER || cfg.rate < 0)
    {
        cerr << "need pairs >= 1, messages >= 1, size >= " << PROBE_HEADER << ", rate >= 0\n";
        return false;
    }
    return true;
}

// ---------- main ----------

int main(int argc, char* argv[])
{
    Config cfg;
    if (!parseOptions(argc, argv, cfg))
    {
        return 1;
    }
    if (sodium_init() < 0)
    {
        cerr << "sodium_init failed\n";
        return 1;
    }

    // unique_ptr because a Pair holds Bots, which can't be copied or moved,
    // and a vector needs to move its elements when it grows.
    vector<unique_ptr<Pair>> pairs;
    for (int i = 0; i < cfg.pairs; ++i)
    {
        pairs.push_back(make_unique<Pair>());
    }

    if (!setUp(pairs, cfg))
    {
        return 1;
    }
    const uint64_t startNs = runLoad(pairs, cfg);
    const Summary summary = summarize(pairs, cfg, startNs);
    printReport(summary, cfg);

    return summary.clean() ? 0 : 1;
}
