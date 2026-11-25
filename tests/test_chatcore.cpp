#include "doctest.h"
#include "chatcore.hpp"

#include <cstring>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace std;

// ---------- helpers ----------

namespace
{
// A contacts file path in the system temp folder, deleted (with its .tmp) when the test ends.
struct TempPath
{
    std::string path;

    TempPath()
    {
        unsigned char random[8];
        randombytes_buf(random, sizeof(random));
        char hex[sizeof(random) * 2 + 1];
        sodium_bin2hex(hex, sizeof(hex), random, sizeof(random));
        path = (std::filesystem::temp_directory_path() / ("tango_chatcore_test_" + std::string(hex))).string();
    }

    ~TempPath()
    {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        std::filesystem::remove(path + ".tmp", ec);
    }
};

// Everything main() gives the core, plus the core itself.
// The core holds references to the other members, so they're declared FIRST:
// members are created in declaration order, and destroyed in reverse.
struct Client
{
    Identity id;
    map<PeerId, Session> sessions;
    Contacts contacts;
    set<PeerId> online;
    TempPath contactsFile;
    ChatCore core;

    explicit Client(const string& chatName = "me")
        : core(id, sessions, contacts, online, chatName, contactsFile.path)
    {
        crypto_sign_keypair(id.pk, id.sk);
    }

    // this client's ID, as the server knows it
    PeerId pid() const
    {
        PeerId p{};
        memcpy(p.data(), id.pk, p.size());
        return p;
    }

    Effects receive(MsgType type, const string& body) { return core.onFrame(type, body); }

    // the user typed `line` and pressed Enter
    Effects type(const string& line) { return core.onInput(line); }
};

// an ID filled with one repeated byte
PeerId idOf(unsigned char fill)
{
    PeerId id{};
    id.fill(fill);
    return id;
}

// a PeerId as a frame body
string bodyOf(const PeerId& id)
{
    return string(id.begin(), id.end());
}

// a USER_LIST body: [more flag][IDs]
string userListBody(bool more, const vector<PeerId>& ids)
{
    string body(1, more ? 1 : 0);
    for (const PeerId& id : ids)
    {
        body += bodyOf(id);
    }
    return body;
}

// puts a READY session with `peer` into the client, with a recognisable key
void addReadySession(Client& c, const PeerId& peer)
{
    Session& s = c.sessions[peer];
    s.state = SessionState::READY;
    memset(s.tx, 0x5A, sizeof(s.tx));
}

string kindName(UiEventKind k)
{
    switch (k)
    {
        case UiEventKind::MESSAGE:   return "MESSAGE";
        case UiEventKind::CONNECTED: return "CONNECTED";
        case UiEventKind::NOTICE:    return "NOTICE";
        case UiEventKind::WARNING:   return "WARNING";
        case UiEventKind::INFO:      return "INFO";
        case UiEventKind::SENT:      return "SENT";
        case UiEventKind::CHAT_CHANGED: return "CHAT_CHANGED";
    }
    return "?";
}

// true if any event text contains a byte a terminal would act on
bool hasControlBytes(const Effects& e)
{
    for (const UiEvent& ev : e.events)
    {
        for (const string* s : {&ev.name, &ev.text, &ev.fingerprint})
        {
            for (char ch : *s)
            {
                const unsigned char u = static_cast<unsigned char>(ch);
                if (u < 0x20 || u == 0x7F)
                {
                    return true;
                }
            }
        }
    }
    return false;
}
}

// ---------- ERROR_MSG ----------

TEST_CASE("chatcore ERROR_MSG: one warning with the server's text, nothing sent, not fatal")
{
    Client c;
    Effects e = c.receive(MsgType::ERROR_MSG, "Server full.");

    REQUIRE(e.events.size() == 1);
    CHECK(kindName(e.events[0].kind) == "WARNING");
    CHECK(e.events[0].text == "Server full.");
    CHECK(e.frames.empty());
    CHECK_FALSE(e.fatal);
}

TEST_CASE("chatcore ERROR_MSG: the text is cleaned before it reaches the UI")
{
    Client c;
    Effects e = c.receive(MsgType::ERROR_MSG, "bad\x1b[2J\r\nnews");

    REQUIRE(e.events.size() == 1);
    CHECK_FALSE(hasControlBytes(e));
    CHECK(e.events[0].text.find("news") != string::npos);
}

TEST_CASE("chatcore ERROR_MSG: an empty error is still shown, not fatal")
{
    Client c;
    Effects e = c.receive(MsgType::ERROR_MSG, "");
    REQUIRE(e.events.size() == 1);
    CHECK(kindName(e.events[0].kind) == "WARNING");
    CHECK_FALSE(e.fatal);
}

// ---------- frame types the client never expects after login ----------

TEST_CASE("chatcore: unknown and login-only frame types are fatal, with a warning")
{
    const vector<MsgType> types = {
        static_cast<MsgType>(0),   MsgType::PEER_JOINED, MsgType::PEER_LEFT, MsgType::CHALLENGE,
        MsgType::AUTH,             MsgType::AUTH_OK,     static_cast<MsgType>(99),
        static_cast<MsgType>(255),
    };
    for (MsgType type : types)
    {
        CAPTURE(int(type));
        Client c;
        Effects e = c.receive(type, "anything");
        CHECK(e.fatal);
        REQUIRE(e.events.size() == 1);
        CHECK(kindName(e.events[0].kind) == "WARNING");
        CHECK(e.frames.empty());
    }
}

// ---------- USER_NOT_FOUND ----------

TEST_CASE("chatcore USER_NOT_FOUND: a notice using the contact's saved name")
{
    Client c;
    const PeerId bob = idOf(0xB0);
    c.contacts[bob] = "bob";

    Effects e = c.receive(MsgType::USER_NOT_FOUND, bodyOf(bob));
    REQUIRE(e.events.size() == 1);
    CHECK(kindName(e.events[0].kind) == "NOTICE");
    CHECK(e.events[0].text == "bob is not online.");
    CHECK(e.frames.empty());
    CHECK_FALSE(e.fatal);
}

TEST_CASE("chatcore USER_NOT_FOUND: a stranger is shown by fingerprint")
{
    Client c;
    const PeerId stranger = idOf(0x33);

    Effects e = c.receive(MsgType::USER_NOT_FOUND, bodyOf(stranger));
    REQUIRE(e.events.size() == 1);
    CHECK(e.events[0].text == idFingerPrint(stranger.data()) + " is not online.");
}

TEST_CASE("chatcore USER_NOT_FOUND: ends the session with that user only")
{
    Client c;
    const PeerId bob = idOf(0xB0), carol = idOf(0xC0);
    addReadySession(c, bob);
    addReadySession(c, carol);

    c.receive(MsgType::USER_NOT_FOUND, bodyOf(bob));
    CHECK_FALSE(c.sessions.contains(bob));
    REQUIRE(c.sessions.contains(carol));
    CHECK(c.sessions[carol].state == SessionState::READY);
}

TEST_CASE("chatcore USER_NOT_FOUND: a body that isn't one ID is a warning and changes nothing")
{
    for (size_t size : {size_t{0}, size_t{31}, size_t{33}, size_t{64}})
    {
        CAPTURE(size);
        Client c;
        const PeerId bob = idOf(0xB0);
        addReadySession(c, bob);

        Effects e = c.receive(MsgType::USER_NOT_FOUND, string(size, '\xB0'));
        REQUIRE(e.events.size() == 1);
        CHECK(kindName(e.events[0].kind) == "WARNING");
        CHECK_FALSE(e.fatal);
        CHECK(c.sessions.contains(bob));
    }
}

// ---------- USER_LIST ----------

TEST_CASE("chatcore USER_LIST: fills the online set, with nothing to show")
{
    Client c;
    const PeerId alice = idOf(0xA1), bob = idOf(0xB0);

    Effects e = c.receive(MsgType::USER_LIST, userListBody(false, {alice, bob}));
    CHECK(c.online == set<PeerId>{alice, bob});
    CHECK(e.events.empty());
    CHECK(e.frames.empty());
}

TEST_CASE("chatcore USER_LIST: a list split over several frames adds up")
{
    Client c;
    vector<PeerId> everyone(600);
    for (size_t i = 0; i < everyone.size(); ++i)
    {
        everyone[i][0] = static_cast<unsigned char>(i);
        everyone[i][1] = static_cast<unsigned char>(i >> 8);
    }

    const auto bodies = buildUserListBodies(everyone);
    REQUIRE(bodies.size() > 1);
    for (const auto& body : bodies)
    {
        Effects e = c.receive(MsgType::USER_LIST, string(body.begin(), body.end()));
        CHECK(e.events.empty());
    }
    CHECK(c.online == set<PeerId>(everyone.begin(), everyone.end()));
}

TEST_CASE("chatcore USER_LIST: a malformed list is a warning, not fatal")
{
    Client c;
    for (const string& bad : {string(), string(32, 'x'), string(1, '\0') + string(31, 'x'),
                              string(1, '\x02')})
    {
        CAPTURE(bad.size());
        Effects e = c.receive(MsgType::USER_LIST, bad);
        REQUIRE(e.events.size() == 1);
        CHECK(kindName(e.events[0].kind) == "WARNING");
        CHECK_FALSE(e.fatal);
    }
}

// ---------- USER_ONLINE / USER_OFFLINE ----------

TEST_CASE("chatcore USER_ONLINE: adds the user, with nothing to show")
{
    Client c;
    const PeerId bob = idOf(0xB0);

    Effects e = c.receive(MsgType::USER_ONLINE, bodyOf(bob));
    CHECK(c.online.contains(bob));
    CHECK(e.events.empty());
    CHECK(e.frames.empty());
}

TEST_CASE("chatcore USER_ONLINE: a body that isn't one ID is ignored")
{
    Client c;
    for (size_t size : {size_t{0}, size_t{31}, size_t{33}})
    {
        Effects e = c.receive(MsgType::USER_ONLINE, string(size, 'x'));
        CHECK(e.events.empty());
    }
    CHECK(c.online.empty());
}

TEST_CASE("chatcore USER_OFFLINE: removes the user and ends only their session")
{
    Client c;
    const PeerId bob = idOf(0xB0), carol = idOf(0xC0);
    c.online = {bob, carol};
    addReadySession(c, bob);
    addReadySession(c, carol);

    Effects e = c.receive(MsgType::USER_OFFLINE, bodyOf(bob));
    CHECK(c.online == set<PeerId>{carol});
    CHECK_FALSE(c.sessions.contains(bob));
    CHECK(c.sessions.contains(carol));
    CHECK(e.events.empty());
    CHECK(e.frames.empty());
}

TEST_CASE("chatcore USER_OFFLINE: an unknown user or a bad body changes nothing")
{
    Client c;
    const PeerId bob = idOf(0xB0);
    c.online = {bob};
    addReadySession(c, bob);

    c.receive(MsgType::USER_OFFLINE, bodyOf(idOf(0x99)));   // someone we never saw
    c.receive(MsgType::USER_OFFLINE, string(31, '\xB0'));   // one byte short of bob's ID
    CHECK(c.online == set<PeerId>{bob});
    CHECK(c.sessions.contains(bob));
}

// ---------- presence over time ----------

TEST_CASE("chatcore: list, online and offline together keep the online set right")
{
    Client c;
    const PeerId alice = idOf(0xA1), bob = idOf(0xB0), carol = idOf(0xC0);

    c.receive(MsgType::USER_LIST, userListBody(false, {alice}));
    c.receive(MsgType::USER_ONLINE, bodyOf(bob));
    c.receive(MsgType::USER_ONLINE, bodyOf(carol));
    c.receive(MsgType::USER_OFFLINE, bodyOf(alice));
    c.receive(MsgType::USER_ONLINE, bodyOf(bob));   // a repeat changes nothing

    CHECK(c.online == set<PeerId>{bob, carol});
}

// =====================================================================
// MESSAGE
// =====================================================================

namespace
{
// Gives `a` and `b` matching READY sessions with each other, the way a real handshake ends.
void connect(Client& a, Client& b)
{
    Session& sa = a.sessions[b.pid()];
    Session& sb = b.sessions[a.pid()];
    sa.isInitiator = memcmp(a.id.pk, b.id.pk, crypto_sign_PUBLICKEYBYTES) < 0;
    sb.isInitiator = !sa.isInitiator;
    makeKeyPair(sa);
    makeKeyPair(sb);
    const string aKey(reinterpret_cast<const char*>(sa.pk), crypto_kx_PUBLICKEYBYTES);
    const string bKey(reinterpret_cast<const char*>(sb.pk), crypto_kx_PUBLICKEYBYTES);
    REQUIRE(deriveSessionKeys(sa, bKey));
    REQUIRE(deriveSessionKeys(sb, aKey));
    sa.state = SessionState::READY;
    sb.state = SessionState::READY;
}

// `from` seals `text` for `to` and returns the MESSAGE body as the server delivers it:
// [sender ID][payload] (the server swaps the recipient ID for the sender's)
string sealedFrom(Client& from, Client& to, const string& text)
{
    vector<unsigned char> payload;
    REQUIRE(sealMessage(from.sessions[to.pid()], from.id.pk, to.pid().data(), text, payload));
    const vector<unsigned char> body = buildBody(from.pid(), payload);
    return string(body.begin(), body.end());
}

// the events of one kind, in order
vector<UiEvent> eventsOf(const Effects& e, UiEventKind kind)
{
    vector<UiEvent> found;
    for (const UiEvent& ev : e.events)
    {
        if (ev.kind == kind)
        {
            found.push_back(ev);
        }
    }
    return found;
}
}

TEST_CASE("chatcore MESSAGE: a message from a contact shows their saved name and the text")
{
    Client alice, bob;
    bob.contacts[alice.pid()] = "alice";
    connect(alice, bob);

    Effects e = bob.receive(MsgType::MESSAGE, sealedFrom(alice, bob, "Alice : hi bob"));
    REQUIRE(e.events.size() == 1);
    CHECK(kindName(e.events[0].kind) == "MESSAGE");
    CHECK(e.events[0].name == "alice");
    CHECK(e.events[0].text == "hi bob");
    CHECK(e.frames.empty());
    CHECK_FALSE(e.fatal);
}

TEST_CASE("chatcore MESSAGE: the name inside the message is never shown as the sender")
{
    // alice calls herself "carol" in her message; bob still sees the name he saved
    Client alice, bob;
    bob.contacts[alice.pid()] = "alice";
    connect(alice, bob);

    Effects e = bob.receive(MsgType::MESSAGE, sealedFrom(alice, bob, "carol : it's me, carol"));
    REQUIRE(eventsOf(e, UiEventKind::MESSAGE).size() == 1);
    CHECK(e.events[0].name == "alice");
    CHECK(e.events[0].text == "it's me, carol");
}

TEST_CASE("chatcore MESSAGE: only the first \" : \" separates the name from the text")
{
    Client alice, bob;
    connect(alice, bob);

    Effects e = bob.receive(MsgType::MESSAGE, sealedFrom(alice, bob, "alice : time : 10 : 30"));
    REQUIRE(eventsOf(e, UiEventKind::MESSAGE).size() == 1);
    CHECK(e.events[0].text == "time : 10 : 30");
}

TEST_CASE("chatcore MESSAGE: escape sequences in a message can't reach the terminal")
{
    Client alice, bob;
    bob.contacts[alice.pid()] = "alice";
    connect(alice, bob);

    const string forged = "alice : hi\r\x1b[2K\x1b[94mcarol\x1b[0m : send me the file";
    Effects e = bob.receive(MsgType::MESSAGE, sealedFrom(alice, bob, forged));
    REQUIRE(eventsOf(e, UiEventKind::MESSAGE).size() == 1);
    CHECK_FALSE(hasControlBytes(e));
    CHECK(e.events[0].name == "alice");
}

TEST_CASE("chatcore MESSAGE: a conversation both ways keeps working")
{
    Client alice, bob;
    alice.contacts[bob.pid()] = "bob";
    bob.contacts[alice.pid()] = "alice";
    connect(alice, bob);

    for (int i = 0; i < 5; ++i)
    {
        CAPTURE(i);
        Effects atBob = bob.receive(MsgType::MESSAGE, sealedFrom(alice, bob, "alice : ping " + to_string(i)));
        REQUIRE(eventsOf(atBob, UiEventKind::MESSAGE).size() == 1);
        CHECK(atBob.events[0].text == "ping " + to_string(i));

        Effects atAlice = alice.receive(MsgType::MESSAGE, sealedFrom(bob, alice, "bob : pong " + to_string(i)));
        REQUIRE(eventsOf(atAlice, UiEventKind::MESSAGE).size() == 1);
        CHECK(atAlice.events[0].text == "pong " + to_string(i));
        CHECK(atAlice.events[0].name == "bob");
    }
}

TEST_CASE("chatcore MESSAGE: a repeated message is rejected the second time")
{
    Client alice, bob;
    bob.contacts[alice.pid()] = "alice";
    connect(alice, bob);

    const string frame = sealedFrom(alice, bob, "alice : pay 10");
    REQUIRE(eventsOf(bob.receive(MsgType::MESSAGE, frame), UiEventKind::MESSAGE).size() == 1);

    Effects again = bob.receive(MsgType::MESSAGE, frame);
    CHECK(eventsOf(again, UiEventKind::MESSAGE).empty());
    REQUIRE(again.events.size() == 1);
    CHECK(kindName(again.events[0].kind) == "WARNING");
    CHECK(again.events[0].text.find("alice") != string::npos);   // says who it claimed to be from
    CHECK_FALSE(again.fatal);
}

TEST_CASE("chatcore MESSAGE: when messages go missing, a warning comes first, then the message")
{
    Client alice, bob;
    bob.contacts[alice.pid()] = "alice";
    connect(alice, bob);

    const string m0 = sealedFrom(alice, bob, "alice : zero");
    sealedFrom(alice, bob, "alice : one");     // never delivered
    sealedFrom(alice, bob, "alice : two");     // never delivered
    const string m3 = sealedFrom(alice, bob, "alice : three");

    bob.receive(MsgType::MESSAGE, m0);
    Effects e = bob.receive(MsgType::MESSAGE, m3);
    REQUIRE(e.events.size() == 2);
    CHECK(kindName(e.events[0].kind) == "WARNING");
    CHECK(e.events[0].text.find('2') != string::npos);   // two messages missing
    CHECK(kindName(e.events[1].kind) == "MESSAGE");
    CHECK(e.events[1].text == "three");
}

TEST_CASE("chatcore MESSAGE: no session, or a session not yet READY, is rejected")
{
    Client alice, bob;

    SUBCASE("no session at all")
    {
        connect(alice, bob);
        bob.sessions.clear();
    }
    SUBCASE("session still OFFERED")
    {
        connect(alice, bob);
        bob.sessions[alice.pid()].state = SessionState::OFFERED;
    }

    // seal on alice's side (her session is still READY), deliver to bob
    vector<unsigned char> payload;
    REQUIRE(sealMessage(alice.sessions[bob.pid()], alice.id.pk, bob.pid().data(), "alice : hi", payload));
    const vector<unsigned char> body = buildBody(alice.pid(), payload);

    Effects e = bob.receive(MsgType::MESSAGE, string(body.begin(), body.end()));
    CHECK(eventsOf(e, UiEventKind::MESSAGE).empty());
    REQUIRE(e.events.size() == 1);
    CHECK(kindName(e.events[0].kind) == "WARNING");
}

TEST_CASE("chatcore MESSAGE: a message from someone with no session with us is rejected")
{
    Client alice, bob, carol;
    connect(alice, bob);
    connect(carol, alice);   // carol has a session with alice, not with bob

    Effects e = bob.receive(MsgType::MESSAGE, sealedFrom(carol, alice, "carol : hi"));
    CHECK(eventsOf(e, UiEventKind::MESSAGE).empty());
    CHECK(e.events.size() == 1);
}

TEST_CASE("chatcore MESSAGE: altered or wrongly keyed messages fail to decrypt")
{
    Client alice, bob;
    connect(alice, bob);

    SUBCASE("a byte changed in transit")
    {
        string frame = sealedFrom(alice, bob, "alice : hello");
        frame.back() ^= 0x01;
        Effects e = bob.receive(MsgType::MESSAGE, frame);
        CHECK(eventsOf(e, UiEventKind::MESSAGE).empty());
        REQUIRE(e.events.size() == 1);
        CHECK(kindName(e.events[0].kind) == "WARNING");
    }
    SUBCASE("bob started a new session, so the old keys no longer match")
    {
        const string frame = sealedFrom(alice, bob, "alice : hello");
        Client other;
        connect(other, bob);                                  // throwaway: just to get fresh keys
        bob.sessions[alice.pid()] = bob.sessions[other.pid()];
        Effects e = bob.receive(MsgType::MESSAGE, frame);
        CHECK(eventsOf(e, UiEventKind::MESSAGE).empty());
        CHECK(e.events.size() == 1);
    }
}

TEST_CASE("chatcore MESSAGE: a malformed body is a warning, not fatal")
{
    Client bob;
    for (size_t size : {size_t{0}, size_t{10}, size_t{31}})
    {
        CAPTURE(size);
        Effects e = bob.receive(MsgType::MESSAGE, string(size, 'x'));
        REQUIRE(e.events.size() == 1);
        CHECK(kindName(e.events[0].kind) == "WARNING");
        CHECK_FALSE(e.fatal);
    }
}

TEST_CASE("chatcore MESSAGE: a message without \" : \" isn't shown as a message")
{
    Client alice, bob;
    connect(alice, bob);

    Effects e = bob.receive(MsgType::MESSAGE, sealedFrom(alice, bob, "no separator here"));
    CHECK(eventsOf(e, UiEventKind::MESSAGE).empty());
    CHECK(e.events.size() == 1);
    CHECK_FALSE(e.fatal);
}

// =====================================================================
// HANDSHAKE: two cores talking through a fake server
// =====================================================================

namespace
{
// What the server does with a frame from `from` addressed to `to`: check the address,
// then swap the recipient ID at the front of the body for the sender's ID.
Effects relayFrame(Client& from, Client& to, const OutgoingFrame& frame)
{
    REQUIRE(frame.body.size() >= PeerId{}.size());
    PeerId recipient{};
    memcpy(recipient.data(), frame.body.data(), recipient.size());
    REQUIRE(recipient == to.pid());   // the core addressed it to the right person

    const PeerId sender = from.pid();
    string delivered(sender.begin(), sender.end());
    delivered.append(frame.body.begin() + recipient.size(), frame.body.end());
    return to.receive(frame.type, delivered);
}

// Everything that happened on one side while the relay ran.
struct Seen
{
    vector<UiEvent> atA, atB;
};

// Delivers a's pending frames to b and b's to a, again and again, until nobody sends
// anything more. Like a server forwarding everything as fast as it can.
Seen pump(Client& a, Effects fromA, Client& b, Effects fromB)
{
    Seen seen;
    seen.atA = fromA.events;
    seen.atB = fromB.events;
    for (int round = 0; !fromA.frames.empty() || !fromB.frames.empty(); ++round)
    {
        REQUIRE_MESSAGE(round < 20, "handshake never settled");   // catches endless resends
        Effects nextFromA, nextFromB;
        for (const OutgoingFrame& f : fromA.frames)
        {
            Effects e = relayFrame(a, b, f);
            seen.atB.insert(seen.atB.end(), e.events.begin(), e.events.end());
            nextFromB.frames.insert(nextFromB.frames.end(), e.frames.begin(), e.frames.end());
        }
        for (const OutgoingFrame& f : fromB.frames)
        {
            Effects e = relayFrame(b, a, f);
            seen.atA.insert(seen.atA.end(), e.events.begin(), e.events.end());
            nextFromA.frames.insert(nextFromA.frames.end(), e.frames.begin(), e.frames.end());
        }
        fromA = nextFromA;
        fromB = nextFromB;
    }
    return seen;
}

// alice and bob, each saved in the other's contacts
void makeFriends(Client& alice, Client& bob)
{
    alice.contacts[bob.pid()] = "bob";
    bob.contacts[alice.pid()] = "alice";
}

vector<UiEvent> ofKind(const vector<UiEvent>& events, UiEventKind kind)
{
    vector<UiEvent> found;
    for (const UiEvent& e : events)
    {
        if (e.kind == kind)
        {
            found.push_back(e);
        }
    }
    return found;
}

// both sides READY with matching keys: a message gets through each way
void checkTalking(Client& alice, Client& bob)
{
    REQUIRE(alice.sessions[bob.pid()].state == SessionState::READY);
    REQUIRE(bob.sessions[alice.pid()].state == SessionState::READY);
    CHECK(sessionFingerPrint(alice.sessions[bob.pid()]) == sessionFingerPrint(bob.sessions[alice.pid()]));

    Effects atBob = bob.receive(MsgType::MESSAGE, sealedFrom(alice, bob, "alice : hello bob"));
    REQUIRE(eventsOf(atBob, UiEventKind::MESSAGE).size() == 1);
    CHECK(atBob.events.back().text == "hello bob");

    Effects atAlice = alice.receive(MsgType::MESSAGE, sealedFrom(bob, alice, "bob : hello alice"));
    REQUIRE(eventsOf(atAlice, UiEventKind::MESSAGE).size() == 1);
    CHECK(atAlice.events.back().text == "hello alice");
}
}

TEST_CASE("chatcore makeOfferTo: one HANDSHAKE frame to that peer, session OFFERED")
{
    Client alice, bob;
    makeFriends(alice, bob);

    Effects e = alice.core.makeOfferTo(bob.pid());
    REQUIRE(e.frames.size() == 1);
    CHECK(e.frames[0].type == MsgType::HANDSHAKE);
    CHECK(e.events.empty());
    CHECK(alice.sessions[bob.pid()].state == SessionState::OFFERED);

    // [bob's ID][kind][offer key][sig]
    REQUIRE(e.frames[0].body.size() == PeerId{}.size() + OFFER_PAYLOAD_SIZE);
    CHECK(memcmp(e.frames[0].body.data(), bob.pid().data(), PeerId{}.size()) == 0);
}

TEST_CASE("chatcore HANDSHAKE: offer, reply, both connected with the same fingerprint")
{
    Client alice, bob;
    makeFriends(alice, bob);

    Seen seen = pump(alice, alice.core.makeOfferTo(bob.pid()), bob, Effects{});

    vector<UiEvent> aliceConnected = ofKind(seen.atA, UiEventKind::CONNECTED);
    vector<UiEvent> bobConnected = ofKind(seen.atB, UiEventKind::CONNECTED);
    REQUIRE(aliceConnected.size() == 1);
    REQUIRE(bobConnected.size() == 1);
    CHECK(aliceConnected[0].name == "bob");
    CHECK(bobConnected[0].name == "alice");
    CHECK_FALSE(aliceConnected[0].fingerprint.empty());
    CHECK(aliceConnected[0].fingerprint == bobConnected[0].fingerprint);
    CHECK(ofKind(seen.atA, UiEventKind::WARNING).empty());
    CHECK(ofKind(seen.atB, UiEventKind::WARNING).empty());

    checkTalking(alice, bob);
}

TEST_CASE("chatcore HANDSHAKE: crossed offers settle, and both end up connected")
{
    for (int i = 0; i < 25; ++i)   // fresh random keys each time, so either side may win
    {
        CAPTURE(i);
        Client alice, bob;
        makeFriends(alice, bob);

        // both run /chat before either offer arrives
        Effects aliceOffer = alice.core.makeOfferTo(bob.pid());
        Effects bobOffer = bob.core.makeOfferTo(alice.pid());
        Seen seen = pump(alice, aliceOffer, bob, bobOffer);

        CHECK(ofKind(seen.atA, UiEventKind::CONNECTED).size() >= 1);
        CHECK(ofKind(seen.atB, UiEventKind::CONNECTED).size() >= 1);
        checkTalking(alice, bob);
    }
}

TEST_CASE("chatcore HANDSHAKE: the stuck case connects once both have added each other")
{
    Client alice, bob;
    alice.contacts[bob.pid()] = "bob";   // only alice has saved the other

    // alice offers; bob doesn't know her yet: one notice, no reply
    Seen first = pump(alice, alice.core.makeOfferTo(bob.pid()), bob, Effects{});
    REQUIRE(ofKind(first.atB, UiEventKind::NOTICE).size() == 1);
    CHECK(first.atB[0].text.find(idFingerPrint(alice.id.pk)) != string::npos);
    CHECK(ofKind(first.atA, UiEventKind::CONNECTED).empty());
    CHECK(alice.sessions[bob.pid()].state == SessionState::OFFERED);   // still waiting
    CHECK_FALSE(bob.sessions.contains(alice.pid()));                   // no session for a stranger

    // bob adds alice and starts a chat himself: both are now OFFERED
    bob.contacts[alice.pid()] = "alice";
    Seen second = pump(bob, bob.core.makeOfferTo(alice.pid()), alice, Effects{});
    CHECK(ofKind(second.atA, UiEventKind::CONNECTED).size() >= 1);
    CHECK(ofKind(second.atB, UiEventKind::CONNECTED).size() >= 1);
    checkTalking(alice, bob);
}

TEST_CASE("chatcore HANDSHAKE: the unknown-sender notice appears only once per person")
{
    Client alice, bob, carol;
    alice.contacts[bob.pid()] = "bob";
    carol.contacts[bob.pid()] = "bob";

    Seen one = pump(alice, alice.core.makeOfferTo(bob.pid()), bob, Effects{});
    Seen two = pump(alice, alice.core.makeOfferTo(bob.pid()), bob, Effects{});      // alice retries
    Seen three = pump(alice, alice.core.makeOfferTo(bob.pid()), bob, Effects{});    // and again
    CHECK(ofKind(one.atB, UiEventKind::NOTICE).size() == 1);
    CHECK(two.atB.empty());
    CHECK(three.atB.empty());

    // a different stranger still gets their own notice
    Seen fromCarol = pump(carol, carol.core.makeOfferTo(bob.pid()), bob, Effects{});
    CHECK(ofKind(fromCarol.atB, UiEventKind::NOTICE).size() == 1);
}

TEST_CASE("chatcore HANDSHAKE: retrying /chat while waiting still connects")
{
    Client alice, bob;
    makeFriends(alice, bob);

    // alice sends three offers; all reach bob, and every reply reaches alice
    Effects offers;
    for (int i = 0; i < 3; ++i)
    {
        Effects e = alice.core.makeOfferTo(bob.pid());
        offers.frames.insert(offers.frames.end(), e.frames.begin(), e.frames.end());
    }
    Seen seen = pump(alice, offers, bob, Effects{});

    // only the reply to her latest offer counts; the others are stale
    CHECK(ofKind(seen.atA, UiEventKind::CONNECTED).size() == 1);
    checkTalking(alice, bob);
}

TEST_CASE("chatcore HANDSHAKE: an offer delivered twice is answered once")
{
    Client alice, bob;
    makeFriends(alice, bob);

    Effects offer = alice.core.makeOfferTo(bob.pid());
    REQUIRE(offer.frames.size() == 1);

    Effects firstTime = relayFrame(alice, bob, offer.frames[0]);
    REQUIRE(firstTime.frames.size() == 1);   // bob replies

    Effects secondTime = relayFrame(alice, bob, offer.frames[0]);
    CHECK(secondTime.frames.empty());         // duplicate: no second reply
    CHECK(secondTime.events.empty());
}

TEST_CASE("chatcore HANDSHAKE: an altered handshake is rejected with a warning and no reply")
{
    Client alice, bob;
    makeFriends(alice, bob);

    Effects offer = alice.core.makeOfferTo(bob.pid());
    OutgoingFrame changed = offer.frames[0];
    changed.body.back() ^= 0x01;   // last byte of the signature

    Effects e = relayFrame(alice, bob, changed);
    CHECK(e.frames.empty());
    REQUIRE(e.events.size() == 1);
    CHECK(kindName(e.events[0].kind) == "WARNING");
    CHECK(e.events[0].text.find("Offer") != string::npos);
    CHECK_FALSE(bob.sessions.contains(alice.pid()));
}

TEST_CASE("chatcore HANDSHAKE: a handshake passed off as from someone else is rejected")
{
    Client alice, bob, carol;
    makeFriends(alice, bob);
    bob.contacts[carol.pid()] = "carol";

    // alice's genuine offer, but the "server" says carol sent it
    Effects offer = alice.core.makeOfferTo(bob.pid());
    Effects e = relayFrame(carol, bob, offer.frames[0]);
    CHECK(e.frames.empty());
    REQUIRE(e.events.size() == 1);
    CHECK(kindName(e.events[0].kind) == "WARNING");
    CHECK_FALSE(bob.sessions.contains(carol.pid()));
}

TEST_CASE("chatcore HANDSHAKE: malformed handshake bodies are warnings, never fatal")
{
    Client bob;
    const PeerId alice = idOf(0xA1);
    for (const string& payload : {string(), string(1, '\x07'), string(1, '\x02') + string(10, 'x'),
                                  string(1, '\x01') + string(10, 'x')})
    {
        CAPTURE(payload.size());
        Effects e = bob.receive(MsgType::HANDSHAKE, bodyOf(alice) + payload);
        REQUIRE(e.events.size() == 1);
        CHECK(kindName(e.events[0].kind) == "WARNING");
        CHECK(e.frames.empty());
        CHECK_FALSE(e.fatal);
    }
    Effects tooShort = bob.receive(MsgType::HANDSHAKE, string(10, 'x'));   // not even an ID
    REQUIRE(tooShort.events.size() == 1);
    CHECK(kindName(tooShort.events[0].kind) == "WARNING");
}

TEST_CASE("chatcore HANDSHAKE: after the peer goes offline, a new handshake starts from scratch")
{
    Client alice, bob;
    makeFriends(alice, bob);
    pump(alice, alice.core.makeOfferTo(bob.pid()), bob, Effects{});
    REQUIRE(bob.sessions[alice.pid()].state == SessionState::READY);

    // alice leaves; bob's session with her ends
    bob.receive(MsgType::USER_OFFLINE, bodyOf(alice.pid()));
    CHECK_FALSE(bob.sessions.contains(alice.pid()));

    // she comes back as a fresh client (same identity) and connects again
    alice.sessions.clear();
    Seen again = pump(alice, alice.core.makeOfferTo(bob.pid()), bob, Effects{});
    CHECK(ofKind(again.atA, UiEventKind::CONNECTED).size() == 1);
    checkTalking(alice, bob);
}

// =====================================================================
// typed input: commands and messages (onInput)
// =====================================================================

namespace
{
// true if any event's text contains `part`
bool says(const Effects& e, const string& part)
{
    for (const UiEvent& ev : e.events)
    {
        if (ev.text.find(part) != string::npos)
        {
            return true;
        }
    }
    return false;
}

// the server's USER_LIST for `c`: everyone in `others`
void seesOnline(Client& c, const vector<Client*>& others)
{
    vector<PeerId> ids;
    for (Client* o : others)
    {
        ids.push_back(o->pid());
    }
    c.receive(MsgType::USER_LIST, userListBody(false, ids));
}

// types /users, then /add with whichever number `who` has in the list
Effects typeAdd(Client& c, const Client& who, const string& name)
{
    c.type("/users");
    size_t n = 1;
    for (const PeerId& id : c.online)   // /users lists the online set in order
    {
        if (id == who.pid())
        {
            break;
        }
        ++n;
    }
    return c.type("/add " + to_string(n) + " " + name);
}

// the contacts file as loadContacts reads it
Contacts onDisk(const Client& c)
{
    Contacts loaded;
    vector<string> warnings;
    REQUIRE(loadContacts(c.contactsFile.path, loaded, warnings));
    return loaded;
}

// the longest text `name` can send in one frame:
// [type][recipient ID][counter, nonce, tag][name " : " text] fills MAX_MESSAGE_SIZE exactly
size_t longestText(const string& name)
{
    return MAX_MESSAGE_SIZE - 1 - PeerId{}.size() - MESSAGE_OVERHEAD - (name + " : ").size();
}
}

// ---------- plain text ----------

TEST_CASE("chatcore input: an empty line does nothing")
{
    Client c;
    Effects e = c.type("");
    CHECK(e.events.empty());
    CHECK(e.frames.empty());
}

TEST_CASE("chatcore input: text with no chat selected is a warning, nothing sent")
{
    Client c;
    Effects e = c.type("hello?");
    CHECK(e.frames.empty());
    REQUIRE(e.events.size() == 1);
    CHECK(kindName(e.events[0].kind) == "WARNING");
    CHECK(says(e, "No chat selected"));
}

TEST_CASE("chatcore input: unknown commands are named, and cleaned first")
{
    Client c;
    Effects e = c.type("/chta bob");
    REQUIRE(e.events.size() == 1);
    CHECK(kindName(e.events[0].kind) == "WARNING");
    CHECK(says(e, "/chta"));
    CHECK(e.frames.empty());

    Effects pasted = c.type("/x\x1b[2J\x1b[31m");   // escape codes pasted into the command
    REQUIRE(pasted.events.size() == 1);
    CHECK_FALSE(hasControlBytes(pasted));

    Effects slash = c.type("/");
    CHECK(slash.events.size() == 1);
}

// ---------- /users ----------

TEST_CASE("chatcore /users: one numbered line per online user, saved names where known")
{
    Client me, bob, carol;
    me.contacts[bob.pid()] = "bob";
    seesOnline(me, {&bob, &carol});

    Effects e = me.type("/users");
    REQUIRE(e.events.size() == 2);
    CHECK(e.frames.empty());

    size_t n = 1;
    for (const PeerId& id : me.online)   // same order as the set
    {
        CAPTURE(n);
        const UiEvent& line = e.events[n - 1];
        CHECK(kindName(line.kind) == "INFO");
        const string label = (id == bob.pid()) ? "bob" : idFingerPrint(carol.id.pk);
        CHECK(line.text == to_string(n) + ") " + label);
        ++n;
    }
}

// ---------- /add ----------

TEST_CASE("chatcore /add: saves the contact in memory and in the file")
{
    Client me, bob;
    seesOnline(me, {&bob});

    Effects e = typeAdd(me, bob, "bob");
    CHECK(says(e, "Saved bob"));
    CHECK(says(e, idFingerPrint(bob.id.pk)));
    CHECK(e.frames.empty());
    CHECK(me.contacts == Contacts{{bob.pid(), "bob"}});
    CHECK(onDisk(me) == me.contacts);
}

TEST_CASE("chatcore /add: the number refers to the last /users list")
{
    Client me, bob;
    seesOnline(me, {&bob});

    SUBCASE("before any /users")
    {
        Effects e = me.type("/add 1 bob");
        CHECK(says(e, "No such user"));
        CHECK(me.contacts.empty());
    }
    SUBCASE("a number past the end of the list")
    {
        me.type("/users");
        Effects e = me.type("/add 2 bob");
        CHECK(says(e, "No such user"));
        CHECK(me.contacts.empty());
    }
    SUBCASE("not a number")
    {
        me.type("/users");
        CHECK(says(me.type("/add one bob"), "No such user"));
        CHECK(me.contacts.empty());
    }
}

TEST_CASE("chatcore /add: wrong number of words shows the usage")
{
    Client me;
    for (const string& line : {string("/add"), string("/add 1"), string("/add 1 bob extra")})
    {
        CAPTURE(line);
        Effects e = me.type(line);
        CHECK(says(e, "Usage: /add"));
        CHECK(e.frames.empty());
    }
}

TEST_CASE("chatcore /add: the contact rules still apply, and nothing is saved")
{
    Client me, bob, carol;
    seesOnline(me, {&bob, &carol});
    REQUIRE(says(typeAdd(me, bob, "bob"), "Saved bob"));

    SUBCASE("the same name again")
    {
        CHECK(says(typeAdd(me, bob, "bob"), "already saved"));
    }
    SUBCASE("a second name for the same person (no renaming)")
    {
        CHECK(says(typeAdd(me, bob, "robert"), "Could not add contact"));
        CHECK(me.contacts.at(bob.pid()) == "bob");
    }
    SUBCASE("a name someone else already has")
    {
        CHECK(says(typeAdd(me, carol, "bob"), "Could not add contact"));
        CHECK_FALSE(me.contacts.contains(carol.pid()));
    }
    SUBCASE("an invalid name")
    {
        CHECK(says(typeAdd(me, carol, "../carol"), "Could not add contact"));
        CHECK_FALSE(me.contacts.contains(carol.pid()));
    }
    CHECK(onDisk(me) == Contacts{{bob.pid(), "bob"}});
}

TEST_CASE("chatcore /add: if the file can't be written, memory is left as it was")
{
    Client me, bob;
    seesOnline(me, {&bob});
    // a contacts path whose folder doesn't exist
    me.contactsFile.path += "_missing_dir/contacts";
    ChatCore core(me.id, me.sessions, me.contacts, me.online, "me", me.contactsFile.path);

    core.onInput("/users");
    Effects e = core.onInput("/add 1 bob");
    CHECK(says(e, "Could not save"));
    CHECK(me.contacts.empty());
}

// ---------- /contacts ----------

TEST_CASE("chatcore /contacts: online contacts are marked with *")
{
    Client me, bob, carol;
    me.contacts[bob.pid()] = "bob";
    me.contacts[carol.pid()] = "carol";
    seesOnline(me, {&bob});   // carol is offline

    Effects e = me.type("/contacts");
    REQUIRE(e.events.size() == 2);
    CHECK(says(e, "* bob [" + idFingerPrint(bob.id.pk) + "]"));
    CHECK(says(e, "  carol [" + idFingerPrint(carol.id.pk) + "]"));
    CHECK_FALSE(says(e, "* carol"));
}

TEST_CASE("chatcore /contacts: none yet, or extra words")
{
    Client me;
    CHECK(says(me.type("/contacts"), "No contacts yet"));
    CHECK(says(me.type("/contacts bob"), "Usage: /contacts"));
}

// ---------- /chat ----------

TEST_CASE("chatcore /chat: selects the contact and sends one offer")
{
    Client me, bob;
    me.contacts[bob.pid()] = "bob";
    seesOnline(me, {&bob});

    Effects e = me.type("/chat bob");
    vector<UiEvent> changed = eventsOf(e, UiEventKind::CHAT_CHANGED);
    REQUIRE(changed.size() == 1);
    CHECK(changed[0].name == "bob");
    CHECK(says(e, "Establishing secure connection"));

    REQUIRE(e.frames.size() == 1);
    CHECK(e.frames[0].type == MsgType::HANDSHAKE);
    CHECK(memcmp(e.frames[0].body.data(), bob.pid().data(), PeerId{}.size()) == 0);
    CHECK(me.sessions[bob.pid()].state == SessionState::OFFERED);
}

TEST_CASE("chatcore /chat: again while waiting sends a fresh offer")
{
    Client me, bob;
    me.contacts[bob.pid()] = "bob";
    seesOnline(me, {&bob});

    Effects first = me.type("/chat bob");
    Effects second = me.type("/chat bob");
    CHECK(says(second, "No reply yet"));
    REQUIRE(second.frames.size() == 1);
    CHECK(second.frames[0].body != first.frames[0].body);   // a new key, not a copy
}

TEST_CASE("chatcore /chat: already connected selects the chat but sends nothing")
{
    Client me, bob;
    me.contacts[bob.pid()] = "bob";
    seesOnline(me, {&bob});
    connect(me, bob);

    Effects e = me.type("/chat bob");
    CHECK(says(e, "Already connected to bob"));
    CHECK(eventsOf(e, UiEventKind::CHAT_CHANGED).size() == 1);
    CHECK(e.frames.empty());
    CHECK(me.sessions[bob.pid()].state == SessionState::READY);   // the session is kept
}

TEST_CASE("chatcore /chat: refused cases select nothing and send nothing")
{
    Client me, bob, carol;
    me.contacts[carol.pid()] = "carol";   // a contact who is offline
    seesOnline(me, {&bob});

    for (const string& line : {string("/chat"), string("/chat bob"), string("/chat carol"),
                               string("/chat carol extra")})
    {
        CAPTURE(line);
        Effects e = me.type(line);
        CHECK(e.frames.empty());
        CHECK(eventsOf(e, UiEventKind::CHAT_CHANGED).empty());
        CHECK(e.events.size() == 1);
    }
    CHECK(says(me.type("/chat carol"), "no longer online"));
    CHECK(says(me.type("/chat bob"), "No such contact"));   // online, but not saved
    CHECK(me.sessions.empty());

    Client lonely;
    CHECK(says(lonely.type("/chat bob"), "No contacts yet"));
}

// ---------- /remove ----------

TEST_CASE("chatcore /remove: deletes the contact, ends the session, closes the chat")
{
    Client me, bob;
    seesOnline(me, {&bob});
    REQUIRE(says(typeAdd(me, bob, "bob"), "Saved bob"));
    connect(me, bob);
    me.type("/chat bob");

    Effects e = me.type("/remove bob");
    CHECK(says(e, "Contact removed: bob"));
    CHECK(says(e, "Chat with bob closed"));
    vector<UiEvent> changed = eventsOf(e, UiEventKind::CHAT_CHANGED);
    REQUIRE(changed.size() == 1);
    CHECK(changed[0].name.empty());   // no chat selected

    CHECK(me.contacts.empty());
    CHECK(onDisk(me).empty());
    CHECK_FALSE(me.sessions.contains(bob.pid()));
    CHECK(says(me.type("hello?"), "No chat selected"));
}

TEST_CASE("chatcore /remove: someone you're not chatting with leaves the chat alone")
{
    Client me, bob, carol;
    seesOnline(me, {&bob, &carol});
    REQUIRE(says(typeAdd(me, bob, "bob"), "Saved"));
    REQUIRE(says(typeAdd(me, carol, "carol"), "Saved"));
    connect(me, bob);
    me.type("/chat bob");

    Effects e = me.type("/remove carol");
    CHECK(says(e, "Contact removed: carol"));
    CHECK(eventsOf(e, UiEventKind::CHAT_CHANGED).empty());
    CHECK(me.type("still here").frames.size() == 1);   // still chatting with bob
}

TEST_CASE("chatcore /remove: usage, none saved, unknown name")
{
    Client me, bob;
    CHECK(says(me.type("/remove"), "Usage: /remove"));
    CHECK(says(me.type("/remove bob"), "No contacts yet"));
    me.contacts[bob.pid()] = "bob";
    CHECK(says(me.type("/remove carol"), "No such contact"));
    CHECK(me.contacts.size() == 1);
}

// ---------- sending text ----------

TEST_CASE("chatcore send: text in a secured chat becomes one encrypted MESSAGE frame")
{
    Client alice("alice"), bob("bob");
    makeFriends(alice, bob);
    seesOnline(alice, {&bob});
    connect(alice, bob);
    alice.type("/chat bob");

    Effects e = alice.type("hello bob");
    REQUIRE(e.frames.size() == 1);
    CHECK(e.frames[0].type == MsgType::MESSAGE);

    // addressed to bob, and the words never appear in clear
    const vector<unsigned char>& body = e.frames[0].body;
    CHECK(memcmp(body.data(), bob.pid().data(), PeerId{}.size()) == 0);
    const string wire(body.begin(), body.end());
    CHECK(wire.find("hello bob") == string::npos);
    CHECK(wire.find("alice") == string::npos);

    // echoed to alice as SENT, with just what she typed
    vector<UiEvent> sent = eventsOf(e, UiEventKind::SENT);
    REQUIRE(sent.size() == 1);
    CHECK(sent[0].text == "hello bob");

    // bob reads it under the name he saved
    Effects atBob = relayFrame(alice, bob, e.frames[0]);
    vector<UiEvent> got = eventsOf(atBob, UiEventKind::MESSAGE);
    REQUIRE(got.size() == 1);
    CHECK(got[0].name == "alice");
    CHECK(got[0].text == "hello bob");
}

TEST_CASE("chatcore send: before the handshake finishes, nothing is sent")
{
    Client me, bob;
    me.contacts[bob.pid()] = "bob";
    seesOnline(me, {&bob});
    me.type("/chat bob");   // offer sent, no reply yet

    Effects e = me.type("hi");
    CHECK(e.frames.empty());
    CHECK(says(e, "not secured yet"));
    CHECK(eventsOf(e, UiEventKind::SENT).empty());
}

TEST_CASE("chatcore send: the longest message that fits is sent; one more character isn't")
{
    Client alice("alice"), bob("bob");
    makeFriends(alice, bob);
    seesOnline(alice, {&bob});
    connect(alice, bob);
    alice.type("/chat bob");

    Effects fits = alice.type(string(longestText("alice"), 'x'));
    REQUIRE(fits.frames.size() == 1);
    CHECK(1 + fits.frames[0].body.size() == MAX_MESSAGE_SIZE);   // exactly the limit
    REQUIRE(eventsOf(relayFrame(alice, bob, fits.frames[0]), UiEventKind::MESSAGE).size() == 1);

    Effects tooLong = alice.type(string(longestText("alice") + 1, 'x'));
    CHECK(tooLong.frames.empty());
    CHECK(says(tooLong, "too long"));
}

TEST_CASE("chatcore send: a message that's too long uses no number, so nothing looks lost")
{
    Client alice("alice"), bob("bob");
    makeFriends(alice, bob);
    seesOnline(alice, {&bob});
    connect(alice, bob);
    alice.type("/chat bob");

    const uint64_t before = alice.sessions[bob.pid()].txCounter;
    alice.type(string(9000, 'x'));
    CHECK(alice.sessions[bob.pid()].txCounter == before);

    Effects next = alice.type("short one");
    REQUIRE(next.frames.size() == 1);
    Effects atBob = relayFrame(alice, bob, next.frames[0]);
    REQUIRE(atBob.events.size() == 1);                           // no "never arrived" warning
    CHECK(kindName(atBob.events[0].kind) == "MESSAGE");
}

TEST_CASE("chatcore send: after the peer goes offline, typing is refused")
{
    Client alice("alice"), bob("bob");
    makeFriends(alice, bob);
    seesOnline(alice, {&bob});
    connect(alice, bob);
    alice.type("/chat bob");

    alice.receive(MsgType::USER_OFFLINE, bodyOf(bob.pid()));
    Effects e = alice.type("are you there?");
    CHECK(e.frames.empty());
    CHECK(says(e, "not secured yet"));
}

// ---------- a whole conversation, typed ----------

TEST_CASE("chatcore: two users meet and talk using only typed commands")
{
    Client alice("alice"), bob("bob");
    seesOnline(alice, {&bob});
    seesOnline(bob, {&alice});

    // each adds the other from /users
    REQUIRE(says(typeAdd(alice, bob, "bob"), "Saved bob"));
    REQUIRE(says(typeAdd(bob, alice, "alice"), "Saved alice"));

    // alice opens the chat; the "server" relays until the handshake settles
    Seen hello = pump(alice, alice.type("/chat bob"), bob, Effects{});
    vector<UiEvent> atAlice = ofKind(hello.atA, UiEventKind::CONNECTED);
    vector<UiEvent> atBob = ofKind(hello.atB, UiEventKind::CONNECTED);
    REQUIRE(atAlice.size() == 1);
    REQUIRE(atBob.size() == 1);
    CHECK(atAlice[0].fingerprint == atBob[0].fingerprint);

    // bob hasn't picked a chat yet, so he picks alice: already connected, no new offer
    Effects pick = bob.type("/chat alice");
    CHECK(pick.frames.empty());

    // a few lines each way
    for (int i = 0; i < 3; ++i)
    {
        CAPTURE(i);
        Effects fromAlice = alice.type("ping " + to_string(i));
        REQUIRE(fromAlice.frames.size() == 1);
        vector<UiEvent> b = eventsOf(relayFrame(alice, bob, fromAlice.frames[0]), UiEventKind::MESSAGE);
        REQUIRE(b.size() == 1);
        CHECK(b[0].name == "alice");
        CHECK(b[0].text == "ping " + to_string(i));

        Effects fromBob = bob.type("pong " + to_string(i));
        REQUIRE(fromBob.frames.size() == 1);
        vector<UiEvent> a = eventsOf(relayFrame(bob, alice, fromBob.frames[0]), UiEventKind::MESSAGE);
        REQUIRE(a.size() == 1);
        CHECK(a[0].name == "bob");
        CHECK(a[0].text == "pong " + to_string(i));
    }
}

TEST_CASE("chatcore: both type /chat at the same moment and still end up talking")
{
    for (int i = 0; i < 10; ++i)
    {
        CAPTURE(i);
        Client alice("alice"), bob("bob");
        seesOnline(alice, {&bob});
        seesOnline(bob, {&alice});
        REQUIRE(says(typeAdd(alice, bob, "bob"), "Saved"));
        REQUIRE(says(typeAdd(bob, alice, "alice"), "Saved"));

        pump(alice, alice.type("/chat bob"), bob, bob.type("/chat alice"));

        Effects a = alice.type("hi");
        REQUIRE(a.frames.size() == 1);
        CHECK(eventsOf(relayFrame(alice, bob, a.frames[0]), UiEventKind::MESSAGE).size() == 1);
        Effects b = bob.type("hey");
        REQUIRE(b.frames.size() == 1);
        CHECK(eventsOf(relayFrame(bob, alice, b.frames[0]), UiEventKind::MESSAGE).size() == 1);
    }
}
