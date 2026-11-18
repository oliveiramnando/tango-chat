#include "botclient.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <vector>

using namespace std;

namespace bot
{

// ---------- error reporting ----------

namespace
{
// thread_local: each thread has its own copy, so bots on different threads
// (as in the load generator) never overwrite each other's error message.
thread_local string g_lastError;

// Records the reason and returns false, so failures read as: return fail("why");
bool fail(const string& why)
{
    g_lastError = why;
    return false;
}

constexpr size_t KEY_LEN = crypto_kx_PUBLICKEYBYTES;   // 32
constexpr int SEND_TIMEOUT_MS = 5000;   // a send blocked this long counts as failed
}

const string& lastError()
{
    return g_lastError;
}

// ---------- Bot ----------

Bot::Bot()
{
    crypto_sign_keypair(id.pk, id.sk);
    memcpy(pid.data(), id.pk, pid.size());
}

Bot::Bot(const Identity& existing) : id(existing)
{
    memcpy(pid.data(), id.pk, pid.size());
}

Bot::~Bot()
{
    disconnect();
    sodium_memzero(id.sk, sizeof(id.sk));
}

void Bot::disconnect()
{
    if (sock >= 0)
    {
        close(sock);
        sock = -1;
    }
}

// ---------- connection and frames ----------

int connectTo(const string& host, int port, int recvTimeoutMs)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        fail("socket() failed");
        return -1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
    {
        close(s);
        fail("invalid address: " + host);
        return -1;
    }

    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        close(s);
        fail("connect() failed: " + string(strerror(errno)));
        return -1;
    }

    // Send small frames immediately (see setNoDelay in net.hpp).
    if (!setNoDelay(s))
    {
        close(s);
        fail("setsockopt(TCP_NODELAY) failed");
        return -1;
    }

    // Never block forever in the middle of a frame.
    timeval timeout{recvTimeoutMs / 1000, (recvTimeoutMs % 1000) * 1000};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Same for sending: if the server stops reading from us (stuck, or blocked on someone
    // else), a send would otherwise wait forever and hang the whole program.
    timeval sendTimeout{SEND_TIMEOUT_MS / 1000, (SEND_TIMEOUT_MS % 1000) * 1000};
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &sendTimeout, sizeof(sendTimeout));
    return s;
}

bool nextFrame(int sock, MsgType& type, string& body, int timeoutMs)
{
    // poll() waits until data arrives (or the time runs out) without reading anything.
    pollfd p{sock, POLLIN, 0};
    int ready = poll(&p, 1, timeoutMs);
    if (ready == 0)
    {
        return fail("timed out waiting for a frame");
    }
    if (ready < 0)
    {
        return fail("poll() failed");
    }
    if (!receiveFrame(sock, type, body))
    {
        return fail("connection closed or invalid frame");
    }
    return true;
}

bool expectFrame(int sock, MsgType want, string& body, int timeoutMs)
{
    MsgType type{};
    if (!nextFrame(sock, type, body, timeoutMs))
    {
        return false;   // nextFrame already recorded why
    }
    if (type != want)
    {
        return fail("expected frame type " + to_string(static_cast<int>(want)) +
                    ", got " + to_string(static_cast<int>(type)));
    }
    return true;
}

// ---------- login ----------

// ---------- receiving as a bot ----------

namespace
{
bool isPresence(MsgType type)
{
    return type == MsgType::USER_ONLINE || type == MsgType::USER_OFFLINE;
}

// expectFrame for a bot: skips presence frames first if the bot asked for that.
bool expectFrameFor(const Bot& me, MsgType want, string& body, int timeoutMs = 2000)
{
    MsgType type{};
    do
    {
        if (!nextFrame(me.sock, type, body, timeoutMs))
        {
            return false;
        }
    } while (me.ignorePresence && isPresence(type) && !isPresence(want));

    if (type != want)
    {
        return fail("expected frame type " + to_string(static_cast<int>(want)) +
                    ", got " + to_string(static_cast<int>(type)));
    }
    return true;
}
}

bool login(Bot& b, const string& host, int port, set<PeerId>* online)
{
    b.sock = connectTo(host, port);
    if (b.sock < 0)
    {
        return false;
    }

    // 1. the server's random challenge (or a refusal, e.g. "Server full.")
    string body;
    MsgType first{};
    if (!nextFrame(b.sock, first, body))
    {
        return false;
    }
    if (first == MsgType::ERROR_MSG)
    {
        b.disconnect();
        return fail("server rejected login: " + body);
    }
    if (first != MsgType::CHALLENGE)
    {
        return fail("expected CHALLENGE, got frame type " + to_string(static_cast<int>(first)));
    }
    if (body.size() != CHALLENGE_BYTES)
    {
        return fail("challenge has the wrong size");
    }
    array<unsigned char, CHALLENGE_BYTES> challenge{};
    memcpy(challenge.data(), body.data(), challenge.size());

    // 2. prove we own the identity: AUTH = [public key][signature over label || challenge]
    unsigned char sig[crypto_sign_BYTES];
    if (!signLogin(b.id, challenge, sig))
    {
        return fail("signLogin failed");
    }
    vector<unsigned char> auth(b.id.pk, b.id.pk + crypto_sign_PUBLICKEYBYTES);
    auth.insert(auth.end(), sig, sig + crypto_sign_BYTES);
    if (!sendFrame(b.sock, MsgType::AUTH, auth))
    {
        return fail("could not send AUTH");
    }

    // 3. accepted (or refused, with the reason), then the list of who else is online
    MsgType type{};
    if (!nextFrame(b.sock, type, body))
    {
        return false;
    }
    if (type == MsgType::ERROR_MSG)
    {
        b.disconnect();
        return fail("server rejected login: " + body);
    }
    if (type != MsgType::AUTH_OK)
    {
        return fail("expected AUTH_OK, got frame type " + to_string(static_cast<int>(type)));
    }
    // The list may be split over several USER_LIST frames; read until "no more follow".
    set<PeerId> ids;
    bool more = true;
    while (more)
    {
        if (!expectFrame(b.sock, MsgType::USER_LIST, body))
        {
            return false;
        }
        if (!parseUserList(body, ids, more))
        {
            return fail("invalid user list");
        }
    }
    if (online != nullptr)
    {
        *online = ids;
    }
    return true;
}

// ---------- handshake ----------

namespace
{
// Same rule as the client: the lower identity key takes the initiator role in crypto_kx.
bool isInitiator(const Bot& me, const PeerId& peer)
{
    return memcmp(me.id.pk, peer.data(), PeerId{}.size()) < 0;
}

// Reads the next HANDSHAKE frame and checks who sent it. Fills `payload`.
bool receiveHandshake(const Bot& me, const PeerId& expectedSender, vector<unsigned char>& payload)
{
    string body;
    if (!expectFrameFor(me, MsgType::HANDSHAKE, body))
    {
        return false;
    }
    PeerId sender{};
    if (!parseBody(body, sender, payload))
    {
        return fail("malformed handshake body");
    }
    if (sender != expectedSender)
    {
        return fail("handshake from an unexpected sender");
    }
    return true;
}
}

bool sendOffer(const Bot& from, const PeerId& to, Session& s)
{
    wipeSession(s);
    s.isInitiator = isInitiator(from, to);
    makeKeyPair(s);

    unsigned char sig[crypto_sign_BYTES];
    if (!signOffer(from.id, to.data(), s.pk, sig))
    {
        return fail("signOffer failed");
    }

    // [OFFER][offer key][sig]
    vector<unsigned char> payload{static_cast<unsigned char>(HandshakeType::OFFER)};
    payload.insert(payload.end(), s.pk, s.pk + KEY_LEN);
    payload.insert(payload.end(), sig, sig + crypto_sign_BYTES);

    if (!sendFrame(from.sock, MsgType::HANDSHAKE, buildBody(to, payload)))
    {
        return fail("could not send offer");
    }
    s.state = SessionState::OFFERED;
    return true;
}

optional<string> receiveOffer(const Bot& me, const PeerId& expectedSender)
{
    vector<unsigned char> payload;
    if (!receiveHandshake(me, expectedSender, payload))
    {
        return nullopt;
    }
    if (payload.size() != OFFER_PAYLOAD_SIZE ||
        payload[0] != static_cast<unsigned char>(HandshakeType::OFFER))
    {
        fail("not a well-formed offer");
        return nullopt;
    }

    const unsigned char* offerPk = payload.data() + 1;
    const unsigned char* sig = offerPk + KEY_LEN;
    if (!verifyOffer(expectedSender.data(), me.id.pk, offerPk, sig))
    {
        fail("offer signature invalid");
        return nullopt;
    }
    return string(offerPk, offerPk + KEY_LEN);
}

bool sendReply(const Bot& from, const PeerId& to, Session& s, const string& offerPk)
{
    if (offerPk.size() != KEY_LEN)
    {
        return fail("offer key has the wrong size");
    }
    const auto* answered = reinterpret_cast<const unsigned char*>(offerPk.data());

    // Derive first: if it fails, nothing has been sent.
    wipeSession(s);
    s.isInitiator = isInitiator(from, to);
    makeKeyPair(s);
    if (!deriveSessionKeys(s, offerPk))
    {
        return fail("deriveSessionKeys failed");
    }

    unsigned char sig[crypto_sign_BYTES];
    if (!signReply(from.id, to.data(), s.pk, answered, sig))
    {
        return fail("signReply failed");
    }

    // [REPLY][reply key][answered offer key][sig]
    vector<unsigned char> payload{static_cast<unsigned char>(HandshakeType::REPLY)};
    payload.insert(payload.end(), s.pk, s.pk + KEY_LEN);
    payload.insert(payload.end(), answered, answered + KEY_LEN);
    payload.insert(payload.end(), sig, sig + crypto_sign_BYTES);

    if (!sendFrame(from.sock, MsgType::HANDSHAKE, buildBody(to, payload)))
    {
        return fail("could not send reply");
    }
    s.state = SessionState::READY;
    return true;
}

optional<string> receiveReply(const Bot& me, const PeerId& expectedSender, const unsigned char* myOfferPk)
{
    vector<unsigned char> payload;
    if (!receiveHandshake(me, expectedSender, payload))
    {
        return nullopt;
    }
    if (payload.size() != REPLY_PAYLOAD_SIZE ||
        payload[0] != static_cast<unsigned char>(HandshakeType::REPLY))
    {
        fail("not a well-formed reply");
        return nullopt;
    }

    const unsigned char* replyPk = payload.data() + 1;
    const unsigned char* answeredPk = replyPk + KEY_LEN;
    const unsigned char* sig = answeredPk + KEY_LEN;
    if (!verifyReply(expectedSender.data(), me.id.pk, replyPk, answeredPk, sig))
    {
        fail("reply signature invalid");
        return nullopt;
    }
    if (memcmp(answeredPk, myOfferPk, KEY_LEN) != 0)
    {
        fail("reply answers a different offer");
        return nullopt;
    }
    return string(replyPk, replyPk + KEY_LEN);
}

bool handshake(const Bot& a, Session& sa, const Bot& b, Session& sb)
{
    if (!sendOffer(a, b.pid, sa))
    {
        return false;
    }

    optional<string> offer = receiveOffer(b, a.pid);
    if (!offer || !sendReply(b, a.pid, sb, *offer))
    {
        return false;
    }

    optional<string> reply = receiveReply(a, b.pid, sa.pk);
    if (!reply)
    {
        return false;   // receiveReply already recorded why
    }
    if (!deriveSessionKeys(sa, *reply))
    {
        return fail("deriveSessionKeys failed");
    }
    sa.state = SessionState::READY;
    return true;
}

// ---------- messages ----------

namespace
{
// opens a MESSAGE payload from `sender`, recording why if it fails
optional<string> openFrom(const Bot& me, const PeerId& sender, Session& s, const vector<unsigned char>& payload)
{
    string plain;
    uint64_t skipped = 0;
    switch (openMessage(s, sender.data(), me.id.pk, string(payload.begin(), payload.end()), plain, skipped))
    {
        case OpenResult::OK:
            return plain;
        case OpenResult::REPLAYED:
            fail("replayed or out-of-order message");
            return nullopt;
        case OpenResult::INVALID:
        default:
            fail("decrypt failed");
            return nullopt;
    }
}
}

bool sendMessage(const Bot& from, const PeerId& to, Session& s, const string& text)
{
    vector<unsigned char> encrypted;
    if (!sealMessage(s, from.id.pk, to.data(), text, encrypted))
    {
        return fail("encrypt failed");
    }
    if (!sendFrame(from.sock, MsgType::MESSAGE, buildBody(to, encrypted)))
    {
        return fail("could not send message");
    }
    return true;
}

optional<string> receiveMessage(const Bot& me, const PeerId& expectedSender, Session& s, int timeoutMs)
{
    string body;
    if (!expectFrameFor(me, MsgType::MESSAGE, body, timeoutMs))
    {
        return nullopt;
    }

    PeerId sender{};
    vector<unsigned char> payload;
    if (!parseBody(body, sender, payload))
    {
        fail("malformed message body");
        return nullopt;
    }
    if (sender != expectedSender)
    {
        fail("message from an unexpected sender");
        return nullopt;
    }

    return openFrom(me, expectedSender, s, payload);
}

optional<string> receiveMessageFromAny(const Bot& me, map<PeerId, Session>& sessions,
                                       PeerId& sender, int timeoutMs)
{
    string body;
    if (!expectFrameFor(me, MsgType::MESSAGE, body, timeoutMs))
    {
        return nullopt;
    }

    vector<unsigned char> payload;
    if (!parseBody(body, sender, payload))
    {
        fail("malformed message body");
        return nullopt;
    }
    auto it = sessions.find(sender);
    if (it == sessions.end())
    {
        fail("message from an unexpected sender");
        return nullopt;
    }

    return openFrom(me, sender, it->second, payload);
}

} // namespace bot
