#include "doctest.h"
#include "crypto.hpp"

#include <cstring>
#include <string>
#include <vector>

using namespace std;

// Helper: a fresh in-memory identity (no file involved).
static Identity makeIdentity()
{
    Identity id;
    crypto_sign_keypair(id.pk, id.sk);
    return id;
}

// Helper: a 32-byte buffer filled with one repeated byte.
static vector<unsigned char> filled(unsigned char value)
{
    return vector<unsigned char>(32, value);
}

// ---------- buildHandshakeMessage ----------

TEST_CASE("buildHandshakeMessage: offer layout")
{
    vector<unsigned char> sender = filled(0x11);
    vector<unsigned char> recipient = filled(0x22);
    vector<unsigned char> offer = filled(0x33);

    vector<unsigned char> msg = buildHandshakeMessage(OFFER_LABEL, sender.data(), recipient.data(), offer.data());

    const size_t labelLen = OFFER_LABEL.size();
    REQUIRE(labelLen == 16);
    REQUIRE(msg.size() == labelLen + 32 * 3);       // 112

    CHECK(memcmp(msg.data(), OFFER_LABEL.data(), labelLen) == 0);
    CHECK(memcmp(msg.data() + labelLen,      sender.data(),    32) == 0);
    CHECK(memcmp(msg.data() + labelLen + 32, recipient.data(), 32) == 0);
    CHECK(memcmp(msg.data() + labelLen + 64, offer.data(),     32) == 0);
}

TEST_CASE("buildHandshakeMessage: reply layout adds the answered key at the end")
{
    vector<unsigned char> sender = filled(0x11);
    vector<unsigned char> recipient = filled(0x22);
    vector<unsigned char> reply = filled(0x44);
    vector<unsigned char> answered = filled(0x33);

    vector<unsigned char> msg = buildHandshakeMessage(REPLY_LABEL, sender.data(), recipient.data(),
                                                      reply.data(), answered.data());

    const size_t labelLen = REPLY_LABEL.size();
    REQUIRE(labelLen == 16);
    REQUIRE(msg.size() == labelLen + 32 * 4);       // 144

    CHECK(memcmp(msg.data(), REPLY_LABEL.data(), labelLen) == 0);
    CHECK(memcmp(msg.data() + labelLen,      sender.data(),    32) == 0);
    CHECK(memcmp(msg.data() + labelLen + 32, recipient.data(), 32) == 0);
    CHECK(memcmp(msg.data() + labelLen + 64, reply.data(),     32) == 0);
    CHECK(memcmp(msg.data() + labelLen + 96, answered.data(),  32) == 0);
}

TEST_CASE("offer and reply labels differ, so their messages can never be equal")
{
    CHECK(OFFER_LABEL != REPLY_LABEL);

    vector<unsigned char> k = filled(0x55);
    CHECK(buildHandshakeMessage(OFFER_LABEL, k.data(), k.data(), k.data()) !=
          buildHandshakeMessage(REPLY_LABEL, k.data(), k.data(), k.data()));
}

// ---------- deriveSessionKeys ----------

// Helper: build two sessions that completed a handshake with each other.
static void handshakePair(Session& a, Session& b)
{
    a.isInitiator = true;
    b.isInitiator = false;
    makeKeyPair(a);
    makeKeyPair(b);

    string aPk(reinterpret_cast<const char*>(a.pk), crypto_kx_PUBLICKEYBYTES);
    string bPk(reinterpret_cast<const char*>(b.pk), crypto_kx_PUBLICKEYBYTES);

    REQUIRE(deriveSessionKeys(a, bPk));
    REQUIRE(deriveSessionKeys(b, aPk));
}

TEST_CASE("deriveSessionKeys: each side's tx is the other's rx")
{
    Session a, b;
    handshakePair(a, b);

    CHECK(memcmp(a.tx, b.rx, crypto_kx_SESSIONKEYBYTES) == 0);
    CHECK(memcmp(a.rx, b.tx, crypto_kx_SESSIONKEYBYTES) == 0);
    CHECK(memcmp(a.tx, a.rx, crypto_kx_SESSIONKEYBYTES) != 0);   // directions differ

    CHECK(sessionFingerPrint(a) == sessionFingerPrint(b));
}

TEST_CASE("deriveSessionKeys wipes the ephemeral secret key")
{
    Session a, b;
    handshakePair(a, b);

    unsigned char zeros[crypto_kx_SECRETKEYBYTES]{};
    CHECK(memcmp(a.sk, zeros, sizeof(zeros)) == 0);
    CHECK(memcmp(b.sk, zeros, sizeof(zeros)) == 0);
}

TEST_CASE("deriveSessionKeys rejects a wrong-size key")
{
    Session s;
    makeKeyPair(s);

    CHECK_FALSE(deriveSessionKeys(s, string(31, 'x')));
    CHECK_FALSE(deriveSessionKeys(s, string(33, 'x')));
    CHECK_FALSE(deriveSessionKeys(s, string()));
}

TEST_CASE("deriveSessionKeys rejects a session with no key pair")
{
    Session s;   // makeKeyPair never called
    CHECK_FALSE(deriveSessionKeys(s, string(crypto_kx_PUBLICKEYBYTES, 'x')));
}

// ---------- encrypt / decrypt ----------

// Helper: a random 32-byte encryption key.
static vector<unsigned char> randomKey()
{
    vector<unsigned char> key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    randombytes_buf(key.data(), key.size());
    return key;
}

TEST_CASE("encrypt and decrypt round trip")
{
    vector<unsigned char> key = randomKey();
    string message = "alice : hello bob";

    vector<unsigned char> encrypted;
    REQUIRE(encrypt(message, encrypted, key.data()));
    CHECK(encrypted.size() == message.size() + 24 + 16);   // nonce + tag

    vector<unsigned char> decrypted;
    REQUIRE(decrypt(decrypted, string(encrypted.begin(), encrypted.end()), key.data()));
    CHECK(string(decrypted.begin(), decrypted.end()) == message);
}

TEST_CASE("encrypting the same message twice gives different ciphertexts")
{
    vector<unsigned char> key = randomKey();
    vector<unsigned char> first, second;
    REQUIRE(encrypt("same", first, key.data()));
    REQUIRE(encrypt("same", second, key.data()));
    CHECK(first != second);   // random nonce each time
}

TEST_CASE("decrypt rejects a ciphertext with any byte flipped")
{
    vector<unsigned char> key = randomKey();
    vector<unsigned char> encrypted;
    REQUIRE(encrypt("tamper with me", encrypted, key.data()));

    // Try every position: nonce, ciphertext and tag.
    for (size_t i = 0; i < encrypted.size(); ++i)
    {
        CAPTURE(i);   // printed if this iteration fails
        vector<unsigned char> tampered = encrypted;
        tampered[i] ^= 0x01;

        vector<unsigned char> decrypted;
        CHECK_FALSE(decrypt(decrypted, string(tampered.begin(), tampered.end()), key.data()));
    }
}

TEST_CASE("decrypt rejects input shorter than nonce + tag")
{
    vector<unsigned char> key = randomKey();
    vector<unsigned char> decrypted;

    CHECK_FALSE(decrypt(decrypted, string(), key.data()));
    CHECK_FALSE(decrypt(decrypted, string(39, 'x'), key.data()));   // 24 + 16 - 1
}

TEST_CASE("decrypt rejects the wrong key")
{
    vector<unsigned char> key = randomKey();
    vector<unsigned char> otherKey = randomKey();

    vector<unsigned char> encrypted;
    REQUIRE(encrypt("secret", encrypted, key.data()));

    vector<unsigned char> decrypted;
    CHECK_FALSE(decrypt(decrypted, string(encrypted.begin(), encrypted.end()), otherKey.data()));
}

// ---------- signOffer / verifyOffer ----------

TEST_CASE("verifyOffer accepts a valid offer and rejects any change")
{
    Identity alice = makeIdentity();
    Identity bob = makeIdentity();
    Identity carol = makeIdentity();

    unsigned char offer[crypto_kx_PUBLICKEYBYTES];
    randombytes_buf(offer, sizeof(offer));

    // alice offers her key to bob
    unsigned char sig[crypto_sign_BYTES];
    REQUIRE(signOffer(alice, bob.pk, offer, sig));

    SUBCASE("valid offer passes")
    {
        CHECK(verifyOffer(alice.pk, bob.pk, offer, sig));
    }

    SUBCASE("different sender fails")
    {
        CHECK_FALSE(verifyOffer(carol.pk, bob.pk, offer, sig));
    }

    SUBCASE("different recipient fails (offer redirected to carol)")
    {
        CHECK_FALSE(verifyOffer(alice.pk, carol.pk, offer, sig));
    }

    SUBCASE("changed offer key fails")
    {
        unsigned char other[crypto_kx_PUBLICKEYBYTES];
        memcpy(other, offer, sizeof(offer));
        other[0] ^= 0x01;
        CHECK_FALSE(verifyOffer(alice.pk, bob.pk, other, sig));
    }

    SUBCASE("changed signature fails")
    {
        unsigned char badSig[crypto_sign_BYTES];
        memcpy(badSig, sig, sizeof(sig));
        badSig[10] ^= 0x01;
        CHECK_FALSE(verifyOffer(alice.pk, bob.pk, offer, badSig));
    }

    SUBCASE("offer signed by the wrong identity fails")
    {
        unsigned char carolSig[crypto_sign_BYTES];
        REQUIRE(signOffer(carol, bob.pk, offer, carolSig));
        CHECK_FALSE(verifyOffer(alice.pk, bob.pk, offer, carolSig));
    }
}

// ---------- signReply / verifyReply ----------

TEST_CASE("verifyReply accepts a valid reply and rejects any change")
{
    Identity alice = makeIdentity();
    Identity bob = makeIdentity();
    Identity carol = makeIdentity();

    unsigned char offer[crypto_kx_PUBLICKEYBYTES];      // alice's offer
    unsigned char reply[crypto_kx_PUBLICKEYBYTES];      // bob's reply key
    randombytes_buf(offer, sizeof(offer));
    randombytes_buf(reply, sizeof(reply));

    // bob replies to alice's offer
    unsigned char sig[crypto_sign_BYTES];
    REQUIRE(signReply(bob, alice.pk, reply, offer, sig));

    SUBCASE("valid reply passes")
    {
        CHECK(verifyReply(bob.pk, alice.pk, reply, offer, sig));
    }

    SUBCASE("different sender fails")
    {
        CHECK_FALSE(verifyReply(carol.pk, alice.pk, reply, offer, sig));
    }

    SUBCASE("different recipient fails (reply redirected to carol)")
    {
        CHECK_FALSE(verifyReply(bob.pk, carol.pk, reply, offer, sig));
    }

    SUBCASE("changed reply key fails")
    {
        unsigned char other[crypto_kx_PUBLICKEYBYTES];
        memcpy(other, reply, sizeof(reply));
        other[0] ^= 0x01;
        CHECK_FALSE(verifyReply(bob.pk, alice.pk, other, offer, sig));
    }

    SUBCASE("reply checked against a different offer fails (stale or replayed reply)")
    {
        unsigned char newerOffer[crypto_kx_PUBLICKEYBYTES];
        randombytes_buf(newerOffer, sizeof(newerOffer));
        CHECK_FALSE(verifyReply(bob.pk, alice.pk, reply, newerOffer, sig));
    }

    SUBCASE("reply and answered keys swapped fails")
    {
        CHECK_FALSE(verifyReply(bob.pk, alice.pk, offer, reply, sig));
    }

    SUBCASE("changed signature fails")
    {
        unsigned char badSig[crypto_sign_BYTES];
        memcpy(badSig, sig, sizeof(sig));
        badSig[10] ^= 0x01;
        CHECK_FALSE(verifyReply(bob.pk, alice.pk, reply, offer, badSig));
    }

    SUBCASE("reply signed by the wrong identity fails")
    {
        unsigned char carolSig[crypto_sign_BYTES];
        REQUIRE(signReply(carol, alice.pk, reply, offer, carolSig));
        CHECK_FALSE(verifyReply(bob.pk, alice.pk, reply, offer, carolSig));
    }
}

// ---------- offers and replies can't be confused ----------

TEST_CASE("an offer signature is never accepted as a reply, and vice versa")
{
    Identity alice = makeIdentity();
    Identity bob = makeIdentity();

    unsigned char keyA[crypto_kx_PUBLICKEYBYTES];
    unsigned char keyB[crypto_kx_PUBLICKEYBYTES];
    randombytes_buf(keyA, sizeof(keyA));
    randombytes_buf(keyB, sizeof(keyB));

    SUBCASE("offer signature checked as a reply")
    {
        unsigned char offerSig[crypto_sign_BYTES];
        REQUIRE(signOffer(alice, bob.pk, keyA, offerSig));

        CHECK_FALSE(verifyReply(alice.pk, bob.pk, keyA, keyB, offerSig));
        CHECK_FALSE(verifyReply(alice.pk, bob.pk, keyA, keyA, offerSig));
    }

    SUBCASE("reply signature checked as an offer")
    {
        unsigned char replySig[crypto_sign_BYTES];
        REQUIRE(signReply(alice, bob.pk, keyA, keyB, replySig));

        CHECK_FALSE(verifyOffer(alice.pk, bob.pk, keyA, replySig));
        CHECK_FALSE(verifyOffer(alice.pk, bob.pk, keyB, replySig));
    }
}

// ---------- numbered messages (sealMessage / openMessage) ----------

namespace
{
// Two sessions that completed a handshake, plus the two users' identity keys.
struct Conversation
{
    Session alice, bob;
    vector<unsigned char> aliceId = filled(0xA1);
    vector<unsigned char> bobId = filled(0xB0);

    Conversation() { handshakePair(alice, bob); }

    // alice -> bob
    vector<unsigned char> seal(const string& text)
    {
        vector<unsigned char> payload;
        REQUIRE(sealMessage(alice, aliceId.data(), bobId.data(), text, payload));
        return payload;
    }

    OpenResult open(const vector<unsigned char>& payload, string& plain, uint64_t& skipped)
    {
        return openMessage(bob, aliceId.data(), bobId.data(),
                           string(payload.begin(), payload.end()), plain, skipped);
    }
};
}

TEST_CASE("buildMessageAd layout: label, sender, recipient, big-endian counter")
{
    vector<unsigned char> sender = filled(0x11), recipient = filled(0x22);
    vector<unsigned char> ad = buildMessageAd(sender.data(), recipient.data(), 0x0102030405060708ULL);

    const size_t labelLen = MESSAGE_LABEL.size();
    REQUIRE(ad.size() == labelLen + 32 + 32 + 8);
    CHECK(memcmp(ad.data(), MESSAGE_LABEL.data(), labelLen) == 0);
    CHECK(memcmp(ad.data() + labelLen, sender.data(), 32) == 0);
    CHECK(memcmp(ad.data() + labelLen + 32, recipient.data(), 32) == 0);
    const unsigned char counter[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(memcmp(ad.data() + labelLen + 64, counter, 8) == 0);
}

TEST_CASE("sealMessage numbers messages 0, 1, 2 and openMessage accepts them in order")
{
    Conversation c;
    for (uint64_t i = 0; i < 3; ++i)
    {
        CAPTURE(i);
        vector<unsigned char> payload = c.seal("message " + to_string(i));
        REQUIRE(payload.size() == MESSAGE_OVERHEAD + ("message " + to_string(i)).size());
        CHECK(payload[7] == i);   // low byte of the big-endian counter

        string plain;
        uint64_t skipped = 99;
        REQUIRE(c.open(payload, plain, skipped) == OpenResult::OK);
        CHECK(plain == "message " + to_string(i));
        CHECK(skipped == 0);
    }
    CHECK(c.alice.txCounter == 3);
    CHECK(c.bob.rxCounter == 3);
}

TEST_CASE("openMessage rejects a replayed message")
{
    Conversation c;
    vector<unsigned char> payload = c.seal("yes, go ahead");

    string plain;
    uint64_t skipped = 0;
    REQUIRE(c.open(payload, plain, skipped) == OpenResult::OK);

    string again = "untouched";
    CHECK(c.open(payload, again, skipped) == OpenResult::REPLAYED);
    CHECK(again == "untouched");   // nothing is handed out for a rejected message
    CHECK(c.bob.rxCounter == 1);
}

TEST_CASE("openMessage reports dropped messages and rejects late ones")
{
    Conversation c;
    vector<unsigned char> m0 = c.seal("zero"), m1 = c.seal("one"), m2 = c.seal("two");

    string plain;
    uint64_t skipped = 0;
    REQUIRE(c.open(m0, plain, skipped) == OpenResult::OK);

    // m1 is withheld: m2 still arrives, and the gap is reported
    REQUIRE(c.open(m2, plain, skipped) == OpenResult::OK);
    CHECK(plain == "two");
    CHECK(skipped == 1);

    // m1 delivered late: out of order, rejected
    CHECK(c.open(m1, plain, skipped) == OpenResult::REPLAYED);
}

TEST_CASE("openMessage rejects a changed counter, even though it isn't encrypted")
{
    Conversation c;
    c.seal("zero");                                  // used up number 0
    vector<unsigned char> payload = c.seal("one");   // number 1

    // try to renumber it as message 5 (to fake a gap) and as message 0
    for (unsigned char forged : {5, 0})
    {
        CAPTURE(int(forged));
        vector<unsigned char> changed = payload;
        changed[7] = forged;
        string plain;
        uint64_t skipped = 0;
        CHECK(c.open(changed, plain, skipped) == OpenResult::INVALID);
        CHECK(c.bob.rxCounter == 0);   // a forgery never moves the counter
    }
}

TEST_CASE("openMessage rejects a message presented as between other people")
{
    Conversation c;
    vector<unsigned char> payload = c.seal("for bob");
    vector<unsigned char> carol = filled(0xC0);
    string plain;
    uint64_t skipped = 0;

    // claimed sender is carol instead of alice
    CHECK(openMessage(c.bob, carol.data(), c.bobId.data(), string(payload.begin(), payload.end()),
                      plain, skipped) == OpenResult::INVALID);
    // claimed recipient is carol instead of bob
    CHECK(openMessage(c.bob, c.aliceId.data(), carol.data(), string(payload.begin(), payload.end()),
                      plain, skipped) == OpenResult::INVALID);
    // the real pair still works
    CHECK(c.open(payload, plain, skipped) == OpenResult::OK);
}

TEST_CASE("openMessage rejects payloads too short to hold counter, nonce and tag")
{
    Conversation c;
    string plain;
    uint64_t skipped = 0;
    CHECK(c.open({}, plain, skipped) == OpenResult::INVALID);
    CHECK(c.open(vector<unsigned char>(MESSAGE_OVERHEAD - 1, 0), plain, skipped) == OpenResult::INVALID);
}

TEST_CASE("a new handshake restarts the numbering, and old messages don't carry over")
{
    Conversation c;
    vector<unsigned char> old = c.seal("old session");
    string plain;
    uint64_t skipped = 0;
    REQUIRE(c.open(old, plain, skipped) == OpenResult::OK);

    handshakePair(c.alice, c.bob);   // new keys
    CHECK(c.alice.txCounter == 0);
    CHECK(c.bob.rxCounter == 0);

    // the old message has number 0 too, but it was sealed with the old key
    CHECK(c.open(old, plain, skipped) == OpenResult::INVALID);
    REQUIRE(c.open(c.seal("new session"), plain, skipped) == OpenResult::OK);
    CHECK(plain == "new session");
}

TEST_CASE("decrypt fails when the additional data differs")
{
    vector<unsigned char> key = randomKey();
    const unsigned char ad[] = {1, 2, 3};
    const unsigned char otherAd[] = {1, 2, 4};

    vector<unsigned char> encrypted;
    REQUIRE(encrypt("hello", encrypted, key.data(), ad, sizeof(ad)));
    string sealed(encrypted.begin(), encrypted.end());

    vector<unsigned char> plain;
    CHECK(decrypt(plain, sealed, key.data(), ad, sizeof(ad)));
    CHECK_FALSE(decrypt(plain, sealed, key.data(), otherAd, sizeof(otherAd)));
    CHECK_FALSE(decrypt(plain, sealed, key.data()));   // no additional data at all
}
