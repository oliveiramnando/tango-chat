#include "doctest.h"
#include "handshake.hpp"

#include <cstring>
#include <string>

using namespace std;

// ---------- helpers ----------

namespace
{
// the key type used in IncomingHandshake, whatever it's called in the header
using TestKey = decltype(IncomingHandshake::key);

// a key filled with one repeated byte, so "lower" and "higher" are easy to see: 0x10 < 0x20
TestKey keyOf(unsigned char fill)
{
    TestKey k{};
    k.fill(fill);
    return k;
}

// a session in `state`, with our current key (s.pk) and the key we last accepted (s.peerPk)
Session sessionWith(SessionState state, const TestKey& ours, const TestKey& accepted)
{
    Session s;
    s.state = state;
    memcpy(s.pk, ours.data(), ours.size());
    memcpy(s.peerPk, accepted.data(), accepted.size());
    return s;
}

IncomingHandshake offerOf(const TestKey& theirOffer)
{
    IncomingHandshake h{};
    h.kind = HandshakeType::OFFER;
    h.key = theirOffer;
    return h;
}

IncomingHandshake replyOf(const TestKey& theirReply, const TestKey& answeredOffer)
{
    IncomingHandshake h{};
    h.kind = HandshakeType::REPLY;
    h.key = theirReply;
    h.answered = answeredOffer;
    return h;
}

// readable names in failure messages
string name(HandshakeAction a)
{
    switch (a)
    {
        case HandshakeAction::REPLY:        return "REPLY";
        case HandshakeAction::RESEND_OFFER: return "RESEND_OFFER";
        case HandshakeAction::DERIVE:       return "DERIVE";
        case HandshakeAction::IGNORE:       return "IGNORE";
    }
    return "?";
}

const TestKey ZERO = keyOf(0x00);   // how sendOffer leaves s.peerPk: wiped
}

// ---------- offers ----------

TEST_CASE("NONE + offer -> REPLY")
{
    Session s;   // a brand-new session, as sessions[sender] creates it
    CHECK(name(decideHandshake(s, offerOf(keyOf(0x30)))) == "REPLY");
}

TEST_CASE("READY + the offer we already answered -> IGNORE (duplicate)")
{
    // we answered their offer 0x30, so s.peerPk holds 0x30; s.pk is our own reply key 0x50
    Session s = sessionWith(SessionState::READY, keyOf(0x50), keyOf(0x30));
    CHECK(name(decideHandshake(s, offerOf(keyOf(0x30)))) == "IGNORE");
}

TEST_CASE("READY + an offer with a new key -> REPLY (peer started over)")
{
    Session s = sessionWith(SessionState::READY, keyOf(0x50), keyOf(0x30));
    CHECK(name(decideHandshake(s, offerOf(keyOf(0x40)))) == "REPLY");
}

TEST_CASE("READY + an offer equal to OUR key is not a duplicate")
{
    // a duplicate means "the key we answered" (s.peerPk), not our own key (s.pk)
    Session s = sessionWith(SessionState::READY, keyOf(0x50), keyOf(0x30));
    CHECK(name(decideHandshake(s, offerOf(keyOf(0x50)))) == "REPLY");
}

TEST_CASE("OFFERED + offer, ours is lower -> RESEND_OFFER (we win)")
{
    Session s = sessionWith(SessionState::OFFERED, keyOf(0x10), ZERO);
    CHECK(name(decideHandshake(s, offerOf(keyOf(0x20)))) == "RESEND_OFFER");
}

TEST_CASE("OFFERED + offer, theirs is lower -> REPLY (they win)")
{
    Session s = sessionWith(SessionState::OFFERED, keyOf(0x20), ZERO);
    CHECK(name(decideHandshake(s, offerOf(keyOf(0x10)))) == "REPLY");
}

TEST_CASE("crossed offers compare OUR offer key, not s.peerPk (the one-word bug)")
{
    // In OFFERED, s.peerPk is all zeros. Comparing against it made every offer look
    // higher than "ours", so both sides resent forever.
    Session s = sessionWith(SessionState::OFFERED, keyOf(0x80), ZERO);
    CHECK(name(decideHandshake(s, offerOf(keyOf(0x05)))) == "REPLY");
    CHECK(name(decideHandshake(s, offerOf(keyOf(0xF0)))) == "RESEND_OFFER");
}

TEST_CASE("crossed offers: keys that differ only in the last byte")
{
    TestKey low = keyOf(0x77), high = keyOf(0x77);
    high.back() = 0x78;

    Session haveLow = sessionWith(SessionState::OFFERED, low, ZERO);
    Session haveHigh = sessionWith(SessionState::OFFERED, high, ZERO);
    CHECK(name(decideHandshake(haveLow, offerOf(high))) == "RESEND_OFFER");
    CHECK(name(decideHandshake(haveHigh, offerOf(low))) == "REPLY");
}

TEST_CASE("crossed offers: exactly one side resends and the other replies (random keys)")
{
    // The property crossed offers depend on. If both resend, they loop forever;
    // if both reply, they derive from different key pairs and can't talk.
    for (int i = 0; i < 500; ++i)
    {
        TestKey a{}, b{};
        randombytes_buf(a.data(), a.size());
        randombytes_buf(b.data(), b.size());
        if (a == b)
        {
            continue;   // practically impossible with 32 random bytes
        }

        Session alice = sessionWith(SessionState::OFFERED, a, ZERO);
        Session bob = sessionWith(SessionState::OFFERED, b, ZERO);

        const string aliceDoes = name(decideHandshake(alice, offerOf(b)));   // alice receives bob's offer
        const string bobDoes = name(decideHandshake(bob, offerOf(a)));       // bob receives alice's offer
        CAPTURE(i);
        CAPTURE(aliceDoes);
        CAPTURE(bobDoes);

        const bool aliceWins = memcmp(a.data(), b.data(), a.size()) < 0;   // lower key wins
        REQUIRE(aliceDoes == (aliceWins ? "RESEND_OFFER" : "REPLY"));
        REQUIRE(bobDoes == (aliceWins ? "REPLY" : "RESEND_OFFER"));
    }
}

// ---------- replies ----------

TEST_CASE("OFFERED + reply answering our current offer -> DERIVE")
{
    Session s = sessionWith(SessionState::OFFERED, keyOf(0x10), ZERO);
    CHECK(name(decideHandshake(s, replyOf(keyOf(0x99), keyOf(0x10)))) == "DERIVE");
}

TEST_CASE("OFFERED + reply answering an older offer -> IGNORE (stale)")
{
    // we sent 0x0A, then retried with 0x10; a late reply to 0x0A must not be used
    Session s = sessionWith(SessionState::OFFERED, keyOf(0x10), ZERO);
    CHECK(name(decideHandshake(s, replyOf(keyOf(0x99), keyOf(0x0A)))) == "IGNORE");
}

TEST_CASE("a reply is matched by the offer it answers, not by its own key")
{
    // the reply's own key happens to equal our offer key, but it answers something else
    Session s = sessionWith(SessionState::OFFERED, keyOf(0x10), ZERO);
    CHECK(name(decideHandshake(s, replyOf(keyOf(0x10), keyOf(0x0A)))) == "IGNORE");
}

TEST_CASE("NONE + reply -> IGNORE (we never offered)")
{
    Session s;
    CHECK(name(decideHandshake(s, replyOf(keyOf(0x99), keyOf(0x00)))) == "IGNORE");
    CHECK(name(decideHandshake(s, replyOf(keyOf(0x99), keyOf(0x10)))) == "IGNORE");
}

TEST_CASE("READY + reply -> IGNORE, even one answering our key (already derived)")
{
    // a second copy of the reply we already used must not derive again
    Session s = sessionWith(SessionState::READY, keyOf(0x10), keyOf(0x99));
    CHECK(name(decideHandshake(s, replyOf(keyOf(0x99), keyOf(0x10)))) == "IGNORE");
}

// ---------- anything else ----------

TEST_CASE("an unknown handshake kind -> IGNORE")
{
    IncomingHandshake h = replyOf(keyOf(0x99), keyOf(0x10));
    h.kind = static_cast<HandshakeType>(7);

    Session offered = sessionWith(SessionState::OFFERED, keyOf(0x10), ZERO);
    CHECK(name(decideHandshake(offered, h)) == "IGNORE");
}

TEST_CASE("decideHandshake never changes the session")
{
    // it takes const Session&, so this is checked by the compiler; this just shows it
    Session s = sessionWith(SessionState::OFFERED, keyOf(0x10), ZERO);
    const Session before = s;
    decideHandshake(s, offerOf(keyOf(0x20)));
    decideHandshake(s, replyOf(keyOf(0x99), keyOf(0x10)));
    CHECK(s.state == before.state);
    CHECK(memcmp(s.pk, before.pk, sizeof(s.pk)) == 0);
    CHECK(memcmp(s.peerPk, before.peerPk, sizeof(s.peerPk)) == 0);
}

// =====================================================================
// checkHandshake: parsing and verifying a handshake payload
// =====================================================================

namespace
{
// one user: an identity and the same public key as the ID the server uses
struct Party
{
    Identity id;
    PeerId pid{};
};

Party makeParty()
{
    Party p;
    crypto_sign_keypair(p.id.pk, p.id.sk);
    memcpy(p.pid.data(), p.id.pk, p.pid.size());
    return p;
}

TestKey randomKey()
{
    TestKey k{};
    randombytes_buf(k.data(), k.size());
    return k;
}

// a genuine offer payload from `from` to `to`: [kind][offer key][sig], as the client builds it
vector<unsigned char> offerPayload(const Party& from, const Party& to, const TestKey& offerKey)
{
    unsigned char sig[crypto_sign_BYTES];
    REQUIRE(signOffer(from.id, to.id.pk, offerKey.data(), sig));

    vector<unsigned char> payload{static_cast<unsigned char>(HandshakeType::OFFER)};
    payload.insert(payload.end(), offerKey.begin(), offerKey.end());
    payload.insert(payload.end(), sig, sig + crypto_sign_BYTES);
    return payload;
}

// a genuine reply payload: [kind][reply key][answered offer key][sig]
vector<unsigned char> replyPayload(const Party& from, const Party& to, const TestKey& replyKey,
                                   const TestKey& answered)
{
    unsigned char sig[crypto_sign_BYTES];
    REQUIRE(signReply(from.id, to.id.pk, replyKey.data(), answered.data(), sig));

    vector<unsigned char> payload{static_cast<unsigned char>(HandshakeType::REPLY)};
    payload.insert(payload.end(), replyKey.begin(), replyKey.end());
    payload.insert(payload.end(), answered.begin(), answered.end());
    payload.insert(payload.end(), sig, sig + crypto_sign_BYTES);
    return payload;
}

string name(HandshakeCheck c)
{
    switch (c)
    {
        case HandshakeCheck::OK:       return "OK";
        case HandshakeCheck::EMPTY:    return "EMPTY";
        case HandshakeCheck::UNKNOWN:  return "UNKNOWN";
        case HandshakeCheck::BAD_SIZE: return "BAD_SIZE";
        case HandshakeCheck::BAD_SIG:  return "BAD_SIG";
    }
    return "?";
}

// alice -> bob, checked on bob's side
string checkFromAlice(const Party& alice, const Party& bob, const vector<unsigned char>& payload,
                      IncomingHandshake& h)
{
    return name(checkHandshake(payload, alice.pid, bob.id.pk, h));
}
}

// ---------- genuine handshakes ----------

TEST_CASE("checkHandshake: a genuine offer is OK and fills kind and key")
{
    Party alice = makeParty(), bob = makeParty();
    TestKey offerKey = randomKey();
    vector<unsigned char> payload = offerPayload(alice, bob, offerKey);
    REQUIRE(payload.size() == OFFER_PAYLOAD_SIZE);

    IncomingHandshake h{};
    REQUIRE(checkFromAlice(alice, bob, payload, h) == "OK");
    CHECK(h.kind == HandshakeType::OFFER);
    CHECK(h.key == offerKey);
    CHECK(h.answered == TestKey{});   // offers don't answer anything
}

TEST_CASE("checkHandshake: a genuine reply is OK and fills kind, key and answered")
{
    Party alice = makeParty(), bob = makeParty();
    TestKey replyKey = randomKey(), answered = randomKey();
    vector<unsigned char> payload = replyPayload(alice, bob, replyKey, answered);
    REQUIRE(payload.size() == REPLY_PAYLOAD_SIZE);

    IncomingHandshake h{};
    REQUIRE(checkFromAlice(alice, bob, payload, h) == "OK");
    CHECK(h.kind == HandshakeType::REPLY);
    CHECK(h.key == replyKey);
    CHECK(h.answered == answered);
}

TEST_CASE("checkHandshake only checks authenticity: whether a reply fits our offer is decided later")
{
    // a genuine reply answering some other offer passes the check; decideHandshake ignores it
    Party alice = makeParty(), bob = makeParty();
    TestKey otherOffer = keyOf(0x0A);
    IncomingHandshake h{};
    REQUIRE(checkFromAlice(alice, bob, replyPayload(alice, bob, randomKey(), otherOffer), h) == "OK");
    CHECK(h.answered == otherOffer);

    Session bobSession = sessionWith(SessionState::OFFERED, keyOf(0x10), ZERO);
    CHECK(name(decideHandshake(bobSession, h)) == "IGNORE");
}

// ---------- malformed payloads ----------

TEST_CASE("checkHandshake: an empty payload is EMPTY")
{
    Party alice = makeParty(), bob = makeParty();
    IncomingHandshake h{};
    CHECK(checkFromAlice(alice, bob, {}, h) == "EMPTY");
}

TEST_CASE("checkHandshake: an unknown kind byte is UNKNOWN, whatever the size")
{
    Party alice = makeParty(), bob = makeParty();
    for (unsigned char kind : {0, 3, 4, 255})
    {
        for (size_t size : {size_t{1}, OFFER_PAYLOAD_SIZE, REPLY_PAYLOAD_SIZE})
        {
            CAPTURE(int(kind));
            CAPTURE(size);
            vector<unsigned char> payload(size, 0x55);
            payload[0] = kind;
            IncomingHandshake h{};
            CHECK(checkFromAlice(alice, bob, payload, h) == "UNKNOWN");
        }
    }
}

TEST_CASE("checkHandshake: a wrong size is BAD_SIZE, and kind is still set")
{
    Party alice = makeParty(), bob = makeParty();
    vector<unsigned char> offer = offerPayload(alice, bob, randomKey());
    vector<unsigned char> reply = replyPayload(alice, bob, randomKey(), randomKey());

    SUBCASE("offer one byte short")
    {
        offer.pop_back();
        IncomingHandshake h{};
        CHECK(checkFromAlice(alice, bob, offer, h) == "BAD_SIZE");
        CHECK(h.kind == HandshakeType::OFFER);   // so the client can say "Malformed Offer payload"
    }
    SUBCASE("offer one byte long")
    {
        offer.push_back(0);
        IncomingHandshake h{};
        CHECK(checkFromAlice(alice, bob, offer, h) == "BAD_SIZE");
        CHECK(h.kind == HandshakeType::OFFER);
    }
    SUBCASE("reply one byte short")
    {
        reply.pop_back();
        IncomingHandshake h{};
        CHECK(checkFromAlice(alice, bob, reply, h) == "BAD_SIZE");
        CHECK(h.kind == HandshakeType::REPLY);
    }
    SUBCASE("reply one byte long")
    {
        reply.push_back(0);
        IncomingHandshake h{};
        CHECK(checkFromAlice(alice, bob, reply, h) == "BAD_SIZE");
        CHECK(h.kind == HandshakeType::REPLY);
    }
    SUBCASE("only the kind byte")
    {
        IncomingHandshake h{};
        CHECK(checkFromAlice(alice, bob, {offer[0]}, h) == "BAD_SIZE");
        CHECK(checkFromAlice(alice, bob, {reply[0]}, h) == "BAD_SIZE");
    }
}

TEST_CASE("checkHandshake: a genuine offer relabelled as a reply (and the reverse) is rejected")
{
    Party alice = makeParty(), bob = makeParty();

    vector<unsigned char> offer = offerPayload(alice, bob, randomKey());
    offer[0] = static_cast<unsigned char>(HandshakeType::REPLY);
    IncomingHandshake h{};
    CHECK(checkFromAlice(alice, bob, offer, h) == "BAD_SIZE");

    vector<unsigned char> reply = replyPayload(alice, bob, randomKey(), randomKey());
    reply[0] = static_cast<unsigned char>(HandshakeType::OFFER);
    CHECK(checkFromAlice(alice, bob, reply, h) == "BAD_SIZE");
}

// ---------- forged or altered handshakes ----------

TEST_CASE("checkHandshake: changing any byte after the kind breaks the signature")
{
    Party alice = makeParty(), bob = makeParty();
    const vector<unsigned char> offer = offerPayload(alice, bob, randomKey());
    const vector<unsigned char> reply = replyPayload(alice, bob, randomKey(), randomKey());

    for (const vector<unsigned char>* original : {&offer, &reply})
    {
        // byte 0 is the kind; every byte after it is key, answered key or signature
        for (size_t i = 1; i < original->size(); ++i)
        {
            vector<unsigned char> changed = *original;
            changed[i] ^= 0x01;
            IncomingHandshake h{};
            CAPTURE(original->size());
            CAPTURE(i);
            REQUIRE(checkFromAlice(alice, bob, changed, h) == "BAD_SIG");
        }
    }
}

TEST_CASE("checkHandshake: a handshake can't be passed off as from someone else or for someone else")
{
    Party alice = makeParty(), bob = makeParty(), carol = makeParty();
    const vector<unsigned char> offer = offerPayload(alice, bob, randomKey());
    const vector<unsigned char> reply = replyPayload(alice, bob, randomKey(), randomKey());
    IncomingHandshake h{};

    for (const vector<unsigned char>* payload : {&offer, &reply})
    {
        // genuine: from alice, to bob
        CHECK(name(checkHandshake(*payload, alice.pid, bob.id.pk, h)) == "OK");
        // the server claims carol sent it
        CHECK(name(checkHandshake(*payload, carol.pid, bob.id.pk, h)) == "BAD_SIG");
        // it is redirected to carol
        CHECK(name(checkHandshake(*payload, alice.pid, carol.id.pk, h)) == "BAD_SIG");
    }
}

TEST_CASE("checkHandshake: a signature made by someone else is rejected")
{
    Party alice = makeParty(), bob = makeParty(), carol = makeParty();
    TestKey offerKey = randomKey();

    // carol signs an offer as if it were from alice
    unsigned char sig[crypto_sign_BYTES];
    REQUIRE(signOffer(carol.id, bob.id.pk, offerKey.data(), sig));
    vector<unsigned char> payload{static_cast<unsigned char>(HandshakeType::OFFER)};
    payload.insert(payload.end(), offerKey.begin(), offerKey.end());
    payload.insert(payload.end(), sig, sig + crypto_sign_BYTES);

    IncomingHandshake h{};
    CHECK(checkFromAlice(alice, bob, payload, h) == "BAD_SIG");
}

// ---------- what a failed check leaves behind ----------

TEST_CASE("checkHandshake: a failed check leaves no unverified keys in h")
{
    Party alice = makeParty(), bob = makeParty();
    vector<unsigned char> reply = replyPayload(alice, bob, randomKey(), randomKey());
    reply.back() ^= 0x01;   // break the signature

    // h starts full of leftovers from an earlier handshake
    IncomingHandshake h{};
    h.key = keyOf(0xEE);
    h.answered = keyOf(0xDD);

    REQUIRE(checkFromAlice(alice, bob, reply, h) == "BAD_SIG");
    CHECK(h.kind == HandshakeType::REPLY);
    CHECK(h.key == TestKey{});
    CHECK(h.answered == TestKey{});
}

TEST_CASE("checkHandshake: an offer after a reply doesn't keep the old answered key")
{
    Party alice = makeParty(), bob = makeParty();
    IncomingHandshake h{};
    REQUIRE(checkFromAlice(alice, bob, replyPayload(alice, bob, randomKey(), keyOf(0x77)), h) == "OK");
    REQUIRE(h.answered == keyOf(0x77));

    REQUIRE(checkFromAlice(alice, bob, offerPayload(alice, bob, randomKey()), h) == "OK");
    CHECK(h.answered == TestKey{});
}

// ---------- check + decide together ----------

TEST_CASE("checkHandshake then decideHandshake: a full offer and reply between two sessions")
{
    Party alice = makeParty(), bob = makeParty();
    Session aliceSession = sessionWith(SessionState::OFFERED, keyOf(0x10), ZERO);   // alice offered 0x10
    Session bobSession;                                                            // bob: no session yet

    // bob receives alice's offer
    IncomingHandshake atBob{};
    REQUIRE(name(checkHandshake(offerPayload(alice, bob, keyOf(0x10)), alice.pid, bob.id.pk, atBob)) == "OK");
    CHECK(name(decideHandshake(bobSession, atBob)) == "REPLY");

    // alice receives bob's reply to 0x10
    IncomingHandshake atAlice{};
    REQUIRE(name(checkHandshake(replyPayload(bob, alice, keyOf(0x20), keyOf(0x10)), bob.pid, alice.id.pk, atAlice)) == "OK");
    CHECK(name(decideHandshake(aliceSession, atAlice)) == "DERIVE");
}
