#include "doctest.h"
#include "chatcore.hpp"

#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace std;

// ---------- helpers ----------

namespace
{
// Everything main() gives the core, plus the core itself.
// The core holds references to the other members, so they're declared FIRST:
// members are created in declaration order, and destroyed in reverse.
struct Client
{
    Identity id;
    map<PeerId, Session> sessions;
    Contacts contacts;
    set<PeerId> online;
    ChatCore core{id, sessions, contacts, online};

    Client() { crypto_sign_keypair(id.pk, id.sk); }

    // this client's ID, as the server knows it
    PeerId pid() const
    {
        PeerId p{};
        memcpy(p.data(), id.pk, p.size());
        return p;
    }

    Effects receive(MsgType type, const string& body) { return core.onFrame(type, body); }
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
