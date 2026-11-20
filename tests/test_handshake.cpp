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
