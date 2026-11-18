#ifndef BOTCLIENT_HPP
#define BOTCLIENT_HPP

// A headless client: speaks the chat protocol directly, with no terminal and no contacts.
// Used by the integration tests and the load generator.
//
// Every function returns false (or an empty optional) on failure instead of stopping,
// and records why in bot::lastError(), so callers decide what a failure means:
// the tests turn it into a failed REQUIRE, the load generator counts it.

#include <map>
#include <optional>
#include <set>
#include <string>

#include "crypto.hpp"
#include "net.hpp"

namespace bot
{

// One simulated user: an identity plus a connection.
struct Bot
{
    Identity id;          // long-term Ed25519 identity (in memory only)
    PeerId pid{};         // the same public key, as the ID the server uses
    int sock = -1;        // -1 = not connected

    // If true, the receive functions below silently skip USER_ONLINE / USER_OFFLINE frames.
    // The tests leave it off (they check presence explicitly); the load generator turns it on,
    // because other bots, even from an earlier run, can come and go at any moment.
    bool ignorePresence = false;

    Bot();                                    // brand-new random identity
    explicit Bot(const Identity& existing);   // reuse an identity (e.g. to test duplicate logins)
    ~Bot();                                   // closes the socket

    void disconnect();

    // A Bot owns its socket, so copying would make two objects close the same socket.
    Bot(const Bot&) = delete;
    Bot& operator=(const Bot&) = delete;
};

// Why the last call on this thread failed (empty if nothing failed yet).
const std::string& lastError();

// ---------- connection and frames ----------

// Connects to host:port. Returns the socket, or -1 on failure.
// Reads on it time out after recvTimeoutMs, so a missing frame can never hang forever.
int connectTo(const std::string& host, int port, int recvTimeoutMs = 2000);

// Waits up to timeoutMs for the next frame. False on timeout or closed connection.
bool nextFrame(int sock, MsgType& type, std::string& body, int timeoutMs = 2000);

// Like nextFrame, but also fails if the frame is not of type `want`.
bool expectFrame(int sock, MsgType want, std::string& body, int timeoutMs = 2000);

// ---------- protocol steps ----------

// Connects and runs the full login (CHALLENGE -> AUTH -> AUTH_OK -> USER_LIST, possibly
// split over several frames).
// On success, `online` holds the other users the server listed.
// If the server refuses (e.g. already logged in), lastError() starts with "server rejected login".
bool login(Bot& b, const std::string& host, int port, std::set<PeerId>* online = nullptr);

// Sends a signed offer from `from` to `to`. Leaves `s` in OFFERED.
bool sendOffer(const Bot& from, const PeerId& to, Session& s);

// Receives an offer from `expectedSender` and checks its signature.
// Returns the offered ephemeral key.
std::optional<std::string> receiveOffer(const Bot& me, const PeerId& expectedSender);

// Answers `offerPk`: derives the session keys, then sends a signed reply. Leaves `s` in READY.
bool sendReply(const Bot& from, const PeerId& to, Session& s, const std::string& offerPk);

// Receives a reply from `expectedSender`, checks its signature and that it answers `myOfferPk`.
// Returns the reply's ephemeral key.
std::optional<std::string> receiveReply(const Bot& me, const PeerId& expectedSender,
                                        const unsigned char* myOfferPk);

// The whole handshake between two logged-in bots, the way two real clients do it:
// a offers, b replies, a derives. Both sessions end up READY with matching keys.
bool handshake(const Bot& a, Session& sa, const Bot& b, Session& sb);

// Encrypts `text` with s.tx and sends it to `to`.
bool sendMessage(const Bot& from, const PeerId& to, const Session& s, const std::string& text);

// Receives a message from `expectedSender` and decrypts it with s.rx.
std::optional<std::string> receiveMessage(const Bot& me, const PeerId& expectedSender,
                                          const Session& s, int timeoutMs = 2000);

// Receives a message from any peer in `sessions` and decrypts it with that peer's session.
// `sender` is set to who sent it. Fails if the sender isn't in `sessions`.
std::optional<std::string> receiveMessageFromAny(const Bot& me,
                                                 const std::map<PeerId, Session>& sessions,
                                                 PeerId& sender, int timeoutMs = 2000);

} // namespace bot

#endif
