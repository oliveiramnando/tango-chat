// Load generator: drives the chat server with many headless bot clients and reports
// correctness, throughput, latency and fairness.
//
// GROUPS (the measured traffic). Each group is one receiver and K senders (--fanin K):
//   - each sender thread sends M probes to the receiver, either as fast as it can or at a
//     fixed rate (--rate), never waiting for delivery
//   - one receiver thread reads them all and records when each one was sent and arrived
//   With K > 1 the server has several threads writing to the receiver's socket at once.
//
// CHURN (optional, --churn C). C extra pairs whose receiver keeps disconnecting and logging
// back in while its sender keeps sending, so connections (and their socket numbers) are
// constantly closed and reused under traffic. Churn traffic is checked for correctness only:
// every login must see the right frames, and nobody may receive someone else's messages.
//
// STALLED (optional, --stalled S). S receivers that log in and then never read again, while
// their sender floods them, so the server's socket buffers towards them fill up. Any send to
// them then blocks. A server must not let one such client hold up everyone else.
//
// Each message's plaintext is a "probe":
//   [8-byte send time (ns)][8-byte sequence number][padding up to the message size]
//
// Usage: ./loadgen [--host H] [--port N] [--pairs N] [--fanin K] [--messages N]
//                  [--size N] [--rate N] [--churn C] [--stalled S]
//        ./loadgen --help

#include <sodium.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <latch>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "botclient.hpp"

using namespace std;
using Clock = chrono::steady_clock;   // steady: never jumps when the system clock is adjusted

// The first WARMUP_FRACTION of each sender's messages are delivered and checked like any
// other, but left out of the performance numbers: the start of a run is never typical.
constexpr double WARMUP_FRACTION = 0.10;

// A sender counts as "behind" when a message goes out more than this long after its slot.
constexpr uint64_t LATE_NS = 1'000'000;   // 1 ms

// Churn: each churn receiver stays online for a random time in this range, then reconnects.
// Short holds and busy churn senders keep many messages in flight to connections that are
// closing, which is what it takes to hit the (tiny) socket-reuse race in the server.
constexpr int CHURN_HOLD_MIN_MS = 2;
constexpr int CHURN_HOLD_MAX_MS = 10;
constexpr int CHURN_SEND_GAP_US = 20;     // pause between a churn sender's messages

// Stalled: each stalled receiver's sender sends this many large messages, then stops.
// 1,000 x 8,000 bytes = 8 MB, more than the socket buffers between server and receiver hold.
constexpr int STALL_MESSAGES = 1000;
constexpr size_t STALL_SIZE = 8000;

// ---------- probes ----------

constexpr size_t PROBE_HEADER = 16;   // 8 bytes time + 8 bytes sequence number

// Nanoseconds on the steady clock. Only meaningful inside this process:
// every sender and receiver lives in this program, so they all read the same clock.
uint64_t nowNs()
{
    return chrono::duration_cast<chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
}

// Builds [send time][seq][padding]. `size` is the total plaintext length (at least 16).
// `sentNs` is the time the message counts as sent from (see runSender).
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
    int groups = 10;        // --pairs: number of receivers
    int fanin = 1;          // senders per receiver
    int messages = 10000;   // per sender
    size_t size = 64;       // plaintext bytes per message
    double rate = 0;        // messages per second per sender; 0 = as fast as possible
    int churn = 0;          // extra pairs whose receiver keeps reconnecting
    int stalled = 0;        // extra receivers that never read

    int warmupMessages() const { return static_cast<int>(messages * WARMUP_FRACTION); }
    bool paced() const { return rate > 0; }
    int senders() const { return groups * fanin; }
};

// ---------- reading what nobody asked for ----------

// Senders never wait for incoming frames, but the server still sends them things (presence
// updates, "user not found" errors). Reading them now and then keeps the socket's receive
// buffer from filling up, which would block the server, the way a real client never would.
// A MESSAGE here is a bug: senders are never sent messages, so it was meant for someone else.
// Returns the number of misdelivered messages found.
int drainIncoming(const bot::Bot& b)
{
    int misdelivered = 0;
    MsgType type{};
    string body;
    while (bot::nextFrame(b.sock, type, body, 0))   // timeout 0: only what's already there
    {
        if (type == MsgType::MESSAGE)
        {
            ++misdelivered;
        }
    }
    return misdelivered;
}

// ---------- groups ----------

// One delivered message.
struct Sample
{
    uint32_t sender;   // index of the sender within its group
    uint64_t seq;
    uint64_t sentNs;
    uint64_t arrivedNs;
};

// One sender. Its thread is the only one that writes these fields during the run.
struct Sender
{
    bot::Bot bot;
    Session session;

    int sent = 0;
    int sendErrors = 0;
    string sendError;          // first failure reason, for the report
    int late = 0;              // paced runs: messages sent more than LATE_NS after their slot
    uint64_t maxLagNs = 0;     // paced runs: the furthest behind schedule it got
    int misdelivered = 0;      // MESSAGE frames this sender received (should be 0)
};

// One receiver and its senders. During the run, each Sender is written only by its own
// thread, and everything else here only by the receiver thread, so no mutex is needed.
struct Group
{
    bot::Bot receiver;
    vector<unique_ptr<Sender>> senders;
    map<PeerId, Session> sessions;   // the receiver's session with each sender
    map<PeerId, uint32_t> indexOf;   // sender ID -> index in `senders`

    // written by the receiver thread
    vector<Sample> samples;          // one per delivered message, in arrival order
    int receiveErrors = 0;
    int lost = 0;                    // sequence numbers that were skipped
    int outOfOrder = 0;              // older than one already seen (duplicate or reordered)
    string receiveError;             // first failure reason, for the report
};

// Unpaced: send as fast as possible; each message counts as sent when it is built.
//
// Paced (--rate R): message i has a fixed slot at start + i/R. The sender sleeps until the
// slot, then sends. If it is already late, it sends straight away to catch up.
//
// In a paced run each message counts as sent at its SLOT, not when it actually went out.
// Otherwise a stall hides itself: while the sender is stuck, no message "experiences" the
// stall. Measuring from the slot charges the delay to every message that should have been
// sent during it. (Getting this wrong is known as "coordinated omission".)
void runSender(Sender& s, const PeerId& to, const Config& cfg, latch& go)
{
    go.wait();   // every thread starts at the same moment
    const uint64_t startNs = nowNs();
    const double slotNs = cfg.paced() ? 1e9 / cfg.rate : 0;

    for (int i = 0; i < cfg.messages; ++i)
    {
        if (i % 64 == 0)
        {
            s.misdelivered += drainIncoming(s.bot);
        }

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
            s.maxLagNs = max(s.maxLagNs, lag);
            if (lag > LATE_NS)
            {
                ++s.late;
            }
            sentNs = slot;
        }
        else
        {
            sentNs = nowNs();   // stamped as late as possible, right before sending
        }

        if (!bot::sendMessage(s.bot, to, s.session, makeProbe(i, sentNs, cfg.size)))
        {
            ++s.sendErrors;
            s.sendError = bot::lastError();
            return;   // the connection is probably gone; no point continuing
        }
        ++s.sent;
    }
    s.misdelivered += drainIncoming(s.bot);
}

// True if the failure means nothing more will arrive on this socket.
bool isFatal(const string& error)
{
    return error.starts_with("timed out") || error.starts_with("connection closed");
}

void runReceiver(Group& g, const Config& cfg, latch& go)
{
    const int expected = cfg.fanin * cfg.messages;
    g.samples.reserve(expected);
    vector<uint64_t> expectedSeq(g.senders.size(), 0);   // per sender: the next seq due
    go.wait();

    // Stops after all expected probes, or when nothing has arrived for 2 s.
    while (static_cast<int>(g.samples.size()) + g.receiveErrors < expected)
    {
        PeerId from{};
        optional<string> got = bot::receiveMessageFromAny(g.receiver, g.sessions, from);
        const uint64_t arrivedNs = nowNs();   // read the clock first, before any other work

        uint64_t seq = 0;
        uint64_t sentNs = 0;
        if (!got || !readProbe(*got, seq, sentNs))
        {
            const string why = got ? "not a probe" : bot::lastError();
            if (g.receiveError.empty())
            {
                g.receiveError = why;
            }
            if (isFatal(why))
            {
                break;   // timeouts and closed connections are reported as "missing"
            }
            ++g.receiveErrors;
            continue;
        }
        const uint32_t sender = g.indexOf.at(from);   // receiveMessageFromAny checked it's known
        g.samples.push_back({sender, seq, sentNs, arrivedNs});

        // Order is per sender: messages from different senders may interleave freely,
        // but each sender's own messages must arrive in the order it sent them.
        uint64_t& next = expectedSeq[sender];
        if (seq > next)
        {
            g.lost += static_cast<int>(seq - next);   // the ones in between never came
            next = seq + 1;
        }
        else if (seq < next)
        {
            ++g.outOfOrder;   // already past this one
        }
        else
        {
            ++next;
        }
    }
}

// ---------- churn ----------

// A sender that keeps sending to a receiver that keeps reconnecting.
// alice: written only by the churn sender thread. bob: only by the churn receiver thread.
struct Churner
{
    bot::Bot alice;
    bot::Bot bob;
    Session aliceSession;
    Session bobSession;

    // churn sender thread
    int sent = 0;
    int misdelivered = 0;            // MESSAGE frames alice received (should be 0)
    int sendFailures = 0;            // 1 if alice's send failed (the server stopped reading her)
    string sendError;

    // churn receiver thread
    int received = 0;
    int reconnects = 0;
    int rejected = 0;                // "already logged in": the server hadn't noticed bob left yet
    int loginFailures = 0;           // any other login failure (e.g. a stray frame first)
    int receiveFailures = 0;         // wrong sender, decrypt failure, garbled frame...
    vector<string> reasons;          // first few failure reasons

    void note(const string& why)
    {
        if (reasons.size() < 3)
        {
            reasons.push_back(why);
        }
    }
    int failures() const { return misdelivered + sendFailures + loginFailures + receiveFailures; }
};

void runChurnSender(Churner& c, const atomic<bool>& stop, latch& go)
{
    go.wait();
    uint64_t seq = 0;
    while (!stop)
    {
        // While bob is offline the server answers with "user not found" errors; read them.
        c.misdelivered += drainIncoming(c.alice);
        if (!bot::sendMessage(c.alice, c.bob.pid, c.aliceSession, makeProbe(seq++, nowNs(), 64)))
        {
            c.sendError = bot::lastError();
            ++c.sendFailures;   // blocked for 5 s: the server stopped reading from alice
            return;
        }
        ++c.sent;
        this_thread::sleep_for(chrono::microseconds(CHURN_SEND_GAP_US));
    }
}

void runChurnReceiver(Churner& c, const Config& cfg, const atomic<bool>& stop, latch& go,
                      unsigned seed)
{
    mt19937 rng(seed);
    uniform_int_distribution<int> holdMs(CHURN_HOLD_MIN_MS, CHURN_HOLD_MAX_MS);
    go.wait();

    while (!stop)
    {
        // 1. Stay online for a while, reading whatever arrives.
        const auto until = Clock::now() + chrono::milliseconds(holdMs(rng));
        while (!stop && Clock::now() < until)
        {
            const int leftMs = static_cast<int>(
                chrono::duration_cast<chrono::milliseconds>(until - Clock::now()).count());
            optional<string> got =
                bot::receiveMessage(c.bob, c.alice.pid, c.bobSession, max(leftMs, 1));
            if (got)
            {
                ++c.received;
                continue;
            }
            const string why = bot::lastError();
            if (why.starts_with("timed out"))
            {
                break;   // nothing arrived in the rest of the window
            }
            ++c.receiveFailures;   // e.g. someone else's message, or a garbled frame
            c.note("receive: " + why);
            if (why.starts_with("connection closed"))
            {
                break;
            }
        }

        // 2. Leave, and log straight back in with the same identity.
        //    The server frees bob's socket; a new connection may get the same socket number.
        c.bob.disconnect();
        while (!stop)
        {
            if (bot::login(c.bob, cfg.host, cfg.port))
            {
                c.bob.ignorePresence = true;
                ++c.reconnects;
                break;
            }
            const string why = bot::lastError();
            c.bob.disconnect();
            if (why.starts_with("server rejected login"))
            {
                ++c.rejected;   // expected now and then: the server hadn't noticed we left
            }
            else
            {
                ++c.loginFailures;   // e.g. a stray frame arrived before the CHALLENGE
                c.note("login: " + why);
            }
            this_thread::sleep_for(chrono::milliseconds(5));
        }
    }
}

// ---------- stalled receivers ----------

// A receiver that never reads after login, and a sender that floods it.
// Their own results don't count: what matters is whether everyone ELSE keeps working.
struct Staller
{
    bot::Bot alice;
    bot::Bot bob;              // never read from during the run
    Session aliceSession;
    Session bobSession;
};

void runStaller(Staller& st, latch& go)
{
    go.wait();
    for (int i = 0; i < STALL_MESSAGES; ++i)
    {
        drainIncoming(st.alice);
        if (!bot::sendMessage(st.alice, st.bob.pid, st.aliceSession,
                              makeProbe(i, nowNs(), STALL_SIZE)))
        {
            return;   // expected: the server stops reading alice while bob is stuck
        }
    }
}

// ---------- setup ----------

// Logs every bot in, waits for the presence announcements, and handshakes everyone.
// Returns false (after printing why) if anything fails.
bool setUp(vector<unique_ptr<Group>>& groups, vector<unique_ptr<Churner>>& churners,
           vector<unique_ptr<Staller>>& stallers, const Config& cfg)
{
    // 1. Log everyone in, one after another.
    vector<bot::Bot*> loginOrder;
    for (auto& g : groups)
    {
        for (auto& s : g->senders)
        {
            loginOrder.push_back(&s->bot);
        }
        loginOrder.push_back(&g->receiver);
    }
    for (auto& c : churners)
    {
        loginOrder.push_back(&c->alice);
        loginOrder.push_back(&c->bob);
    }
    for (auto& st : stallers)
    {
        loginOrder.push_back(&st->alice);
        loginOrder.push_back(&st->bob);
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

    // 3. Handshakes: every sender with its receiver, and every churn pair.
    for (auto& g : groups)
    {
        for (auto& s : g->senders)
        {
            Session& receiverSide = g->sessions[s->bot.pid];   // creates the entry
            if (!bot::handshake(s->bot, s->session, g->receiver, receiverSide))
            {
                cerr << "handshake failed: " << bot::lastError() << "\n";
                return false;
            }
        }
    }
    for (auto& c : churners)
    {
        if (!bot::handshake(c->alice, c->aliceSession, c->bob, c->bobSession))
        {
            cerr << "churn handshake failed: " << bot::lastError() << "\n";
            return false;
        }
    }
    for (auto& st : stallers)
    {
        if (!bot::handshake(st->alice, st->aliceSession, st->bob, st->bobSession))
        {
            cerr << "stalled handshake failed: " << bot::lastError() << "\n";
            return false;
        }
    }
    return true;
}

// ---------- the run ----------

// Starts every thread, releases them together, and waits for the measured traffic to
// finish; churn keeps going until then and is stopped afterwards.
// Returns the steady-clock time (ns) at which the threads were released.
uint64_t runLoad(vector<unique_ptr<Group>>& groups, vector<unique_ptr<Churner>>& churners,
                 vector<unique_ptr<Staller>>& stallers, const Config& cfg)
{
    // The latch holds every thread at the start line until the main thread counts it down,
    // so nobody gets a head start while the others are still being created.
    latch go(1);
    atomic<bool> stop{false};   // tells the churn threads when the measured traffic is done

    vector<thread> measured;
    for (auto& g : groups)
    {
        for (auto& s : g->senders)
        {
            measured.emplace_back(runSender, ref(*s), cref(g->receiver.pid), cref(cfg), ref(go));
        }
        measured.emplace_back(runReceiver, ref(*g), cref(cfg), ref(go));
    }
    vector<thread> churn;
    unsigned seed = 1;
    for (auto& c : churners)
    {
        churn.emplace_back(runChurnSender, ref(*c), cref(stop), ref(go));
        churn.emplace_back(runChurnReceiver, ref(*c), cref(cfg), cref(stop), ref(go), seed++);
    }
    for (auto& st : stallers)
    {
        churn.emplace_back(runStaller, ref(*st), ref(go));   // joined with the churn threads
    }

    const uint64_t startNs = nowNs();
    go.count_down();
    for (thread& t : measured)
    {
        t.join();   // after this, no thread is writing to any Group any more
    }
    stop = true;
    for (thread& t : churn)
    {
        t.join();
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

// Everything the report prints, computed once.
struct Summary
{
    // correctness of the measured traffic, over every message
    int sent = 0, delivered = 0, sendErrors = 0, receiveErrors = 0;
    int missing = 0, lost = 0, outOfOrder = 0, misdelivered = 0;
    vector<string> reasons;          // a few example failure reasons
    double totalSeconds = 0;         // release of the threads -> last message delivered

    // paced runs: did the senders keep to the schedule?
    int late = 0;                    // messages sent more than LATE_NS after their slot
    uint64_t maxLagNs = 0;

    // performance, over messages after warm-up only
    size_t measured = 0;
    double windowSeconds = 0;        // first to last measured arrival
    double throughput = 0;           // measured / windowSeconds
    vector<uint64_t> latencies;      // sorted, ns

    // fairness: one value per sender
    vector<double> senderThroughput; // msg/s, over the whole run
    vector<double> senderFinish;     // seconds from release to its last delivery
    vector<double> senderP50;        // its own median latency, us

    // churn (correctness only)
    int churnSent = 0, churnReceived = 0, reconnects = 0, rejected = 0;
    int churnLoginFailures = 0, churnReceiveFailures = 0, churnMisdelivered = 0;
    int churnSendFailures = 0;
    vector<string> churnReasons;

    int churnFailures() const
    {
        return churnLoginFailures + churnReceiveFailures + churnMisdelivered + churnSendFailures;
    }
    bool clean() const
    {
        return sendErrors == 0 && receiveErrors == 0 && missing == 0 && lost == 0 &&
               outOfOrder == 0 && misdelivered == 0 && churnFailures() == 0;
    }
};

Summary summarize(const vector<unique_ptr<Group>>& groups,
                  const vector<unique_ptr<Churner>>& churners, const Config& cfg,
                  uint64_t startNs)
{
    Summary s;
    const uint64_t warmup = static_cast<uint64_t>(cfg.warmupMessages());
    uint64_t firstMeasured = UINT64_MAX;
    uint64_t lastMeasured = 0;
    uint64_t lastArrival = startNs;

    auto addReason = [&s](const string& why)
    {
        if (!why.empty() && s.reasons.size() < 5)
        {
            s.reasons.push_back(why);
        }
    };

    // Receivers' reasons first: a receiver failing is usually the cause, and the senders'
    // errors that follow (they get stuck once it stops reading) are the consequence.
    for (const auto& g : groups)
    {
        addReason(g->receiveError);
    }

    for (const auto& g : groups)
    {
        for (const auto& snd : g->senders)
        {
            s.sent += snd->sent;
            s.sendErrors += snd->sendErrors;
            s.late += snd->late;
            s.maxLagNs = max(s.maxLagNs, snd->maxLagNs);
            s.misdelivered += snd->misdelivered;
            addReason(snd->sendError);
        }
        s.delivered += static_cast<int>(g->samples.size());
        s.receiveErrors += g->receiveErrors;
        s.lost += g->lost;
        s.outOfOrder += g->outOfOrder;

        // Split this group's samples by sender, for the overall and per-sender numbers.
        const size_t n = g->senders.size();
        vector<vector<uint64_t>> own(n);   // each sender's measured latencies
        vector<uint64_t> lastOf(n, 0);     // each sender's last arrival
        vector<int> countOf(n, 0);
        for (const Sample& m : g->samples)
        {
            lastArrival = max(lastArrival, m.arrivedNs);
            lastOf[m.sender] = max(lastOf[m.sender], m.arrivedNs);
            ++countOf[m.sender];
            if (m.seq < warmup)
            {
                continue;   // warm-up: checked above, not measured
            }
            const uint64_t latency = m.arrivedNs - m.sentNs;
            s.latencies.push_back(latency);
            own[m.sender].push_back(latency);
            firstMeasured = min(firstMeasured, m.arrivedNs);
            lastMeasured = max(lastMeasured, m.arrivedNs);
        }
        for (size_t i = 0; i < n; ++i)
        {
            if (countOf[i] > 0)
            {
                const double finish = (lastOf[i] - startNs) / 1e9;
                s.senderFinish.push_back(finish);
                s.senderThroughput.push_back(countOf[i] / finish);
            }
            if (!own[i].empty())
            {
                sort(own[i].begin(), own[i].end());
                s.senderP50.push_back(percentile(own[i], 50) / 1000.0);
            }
        }
    }

    for (const auto& c : churners)
    {
        s.churnSent += c->sent;
        s.churnReceived += c->received;
        s.reconnects += c->reconnects;
        s.rejected += c->rejected;
        s.churnLoginFailures += c->loginFailures;
        s.churnReceiveFailures += c->receiveFailures;
        s.churnMisdelivered += c->misdelivered;
        s.churnSendFailures += c->sendFailures;
        for (const string& why : c->reasons)
        {
            if (s.churnReasons.size() < 5)
            {
                s.churnReasons.push_back(why);
            }
        }
        if (!c->sendError.empty() && s.churnReasons.size() < 5)
        {
            s.churnReasons.push_back("send: " + c->sendError);
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
    sort(s.senderThroughput.begin(), s.senderThroughput.end());
    sort(s.senderFinish.begin(), s.senderFinish.end());
    sort(s.senderP50.begin(), s.senderP50.end());
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
    printf("load        %d receivers x %d senders (%d bots), %d messages per sender, %zu bytes,"
           " first %d = warm-up\n",
           cfg.groups, cfg.fanin, cfg.groups * (cfg.fanin + 1), cfg.messages, cfg.size,
           cfg.warmupMessages());
    if (cfg.paced())
    {
        printf("rate        %.0f msg/s per sender = %.0f msg/s offered in total\n",
               cfg.rate, cfg.rate * cfg.senders());
    }
    else
    {
        printf("rate        unlimited (senders never wait: latency = time spent queued)\n");
    }
    if (cfg.churn > 0)
    {
        printf("churn       %d pairs, receiver reconnects every %d-%d ms\n",
               cfg.churn, CHURN_HOLD_MIN_MS, CHURN_HOLD_MAX_MS);
    }
    if (cfg.stalled > 0)
    {
        printf("stalled     %d receivers that never read, each flooded with %d x %zu bytes\n",
               cfg.stalled, STALL_MESSAGES, STALL_SIZE);
    }

    // Correctness first: performance numbers mean nothing if messages went astray.
    printf("delivery    %d / %d delivered   errors: %d send, %d receive   "
           "missing %d, lost %d, out of order %d, misdelivered %d\n",
           s.delivered, s.sent, s.sendErrors, s.receiveErrors, s.missing, s.lost,
           s.outOfOrder, s.misdelivered);
    for (const string& why : s.reasons)
    {
        printf("              e.g. %s\n", why.c_str());
    }
    if (cfg.churn > 0)
    {
        printf("churn       %d reconnects (%d refused as still logged in), %d sent, %d received"
               "   failures: %d login, %d receive, %d misdelivered, %d senders stuck\n",
               s.reconnects, s.rejected, s.churnSent, s.churnReceived, s.churnLoginFailures,
               s.churnReceiveFailures, s.churnMisdelivered, s.churnSendFailures);
        for (const string& why : s.churnReasons)
        {
            printf("              e.g. %s\n", why.c_str());
        }
    }
    printf("verdict     %s\n", s.clean() ? "OK" : "FAILED");

    // A paced run only means something if the load was actually applied.
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

    // Fairness: compare the slowest sender with the median one; a big gap means some
    // senders were starved (or favoured).
    if (!s.senderFinish.empty())
    {
        printf("per sender  msg/s   min %.0f  median %.0f  max %.0f\n",
               s.senderThroughput.front(), percentile(s.senderThroughput, 50),
               s.senderThroughput.back());
        printf("            done at min %.3f s  median %.3f s  max %.3f s\n",
               s.senderFinish.front(), percentile(s.senderFinish, 50), s.senderFinish.back());
    }
    if (!s.senderP50.empty())
    {
        printf("            p50 us  min %.1f  median %.1f  max %.1f\n",
               s.senderP50.front(), percentile(s.senderP50, 50), s.senderP50.back());
    }

    // One line with everything, for scripts: ./loadgen ... | grep '^summary'
    printf("summary pairs=%d fanin=%d messages=%d size=%zu rate=%.0f churn=%d stalled=%d ok=%d "
           "delivered=%d missing=%d lost=%d ooo=%d misdelivered=%d errors=%d churn_failures=%d "
           "late=%d throughput=%.0f p50_us=%.1f p99_us=%.1f max_us=%.1f\n",
           cfg.groups, cfg.fanin, cfg.messages, cfg.size, cfg.rate, cfg.churn, cfg.stalled,
           s.clean() ? 1 : 0, s.delivered, s.missing, s.lost, s.outOfOrder, s.misdelivered,
           s.sendErrors + s.receiveErrors, s.churnFailures(), s.late, s.throughput,
           us(percentile(s.latencies, 50)), us(percentile(s.latencies, 99)),
           s.latencies.empty() ? 0.0 : us(s.latencies.back()));
}

// ---------- options ----------

void printUsage(const char* program)
{
    const Config d;   // the defaults
    printf("usage: %s [options]\n"
           "  --host H        server address                          (default %s)\n"
           "  --port N        server port                             (default %d)\n"
           "  --pairs N       receivers                               (default %d)\n"
           "  --fanin K       senders per receiver                    (default %d)\n"
           "  --messages N    messages per sender                     (default %d)\n"
           "  --size N        bytes per message, >= %zu                (default %zu)\n"
           "  --rate N        msg/s per sender, 0 = as fast as possible (default 0)\n"
           "  --churn C       extra pairs whose receiver keeps reconnecting (default 0)\n"
           "  --stalled S     extra receivers that never read           (default 0)\n"
           "  --help          show this\n",
           program, d.host.c_str(), d.port, d.groups, d.fanin, d.messages, PROBE_HEADER,
           d.size);
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
            else if (name == "--pairs")    { cfg.groups = stoi(value, &used); }
            else if (name == "--fanin")    { cfg.fanin = stoi(value, &used); }
            else if (name == "--messages") { cfg.messages = stoi(value, &used); }
            else if (name == "--size")     { cfg.size = stoul(value, &used); }
            else if (name == "--rate")     { cfg.rate = stod(value, &used); }
            else if (name == "--churn")    { cfg.churn = stoi(value, &used); }
            else if (name == "--stalled")  { cfg.stalled = stoi(value, &used); }
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

    if (cfg.groups < 1 || cfg.fanin < 1 || cfg.messages < 1 || cfg.size < PROBE_HEADER ||
        cfg.rate < 0 || cfg.churn < 0 || cfg.stalled < 0)
    {
        cerr << "need pairs >= 1, fanin >= 1, messages >= 1, size >= " << PROBE_HEADER
             << ", rate >= 0, churn >= 0, stalled >= 0\n";
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
    // Writing to a socket the server has closed raises SIGPIPE, which kills the process by
    // default. Ignore it, so the write just fails and gets counted like any other error.
    signal(SIGPIPE, SIG_IGN);

    // unique_ptr because Groups, Senders and Churners hold Bots, which can't be copied or
    // moved, and a vector needs to move its elements when it grows.
    vector<unique_ptr<Group>> groups;
    for (int i = 0; i < cfg.groups; ++i)
    {
        auto g = make_unique<Group>();
        for (int k = 0; k < cfg.fanin; ++k)
        {
            g->senders.push_back(make_unique<Sender>());
            g->indexOf[g->senders.back()->bot.pid] = static_cast<uint32_t>(k);
        }
        groups.push_back(move(g));
    }
    vector<unique_ptr<Churner>> churners;
    for (int i = 0; i < cfg.churn; ++i)
    {
        churners.push_back(make_unique<Churner>());
    }
    vector<unique_ptr<Staller>> stallers;
    for (int i = 0; i < cfg.stalled; ++i)
    {
        stallers.push_back(make_unique<Staller>());
    }

    if (!setUp(groups, churners, stallers, cfg))
    {
        return 1;
    }
    const uint64_t startNs = runLoad(groups, churners, stallers, cfg);
    const Summary summary = summarize(groups, churners, cfg, startNs);
    printReport(summary, cfg);

    return summary.clean() ? 0 : 1;
}
