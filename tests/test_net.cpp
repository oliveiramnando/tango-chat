#include "doctest.h"
#include "net.hpp"

#include <cstring>
#include <set>
#include <string>
#include <vector>

using namespace std;

// Helper: a PeerId filled with one repeated byte, so different IDs are easy to tell apart.
static PeerId makeId(unsigned char fill)
{
    PeerId id{};
    id.fill(fill);
    return id;
}

// ---------- buildBody / parseBody ----------

TEST_CASE("buildBody and parseBody round trip")
{
    PeerId id = makeId(0xAB);
    vector<unsigned char> payload = {1, 2, 3, 4, 5};

    vector<unsigned char> body = buildBody(id, payload);
    CHECK(body.size() == id.size() + payload.size());

    PeerId parsedId{};
    vector<unsigned char> parsedPayload;
    REQUIRE(parseBody(string(body.begin(), body.end()), parsedId, parsedPayload));
    CHECK(parsedId == id);
    CHECK(parsedPayload == payload);
}

TEST_CASE("buildBody and parseBody round trip with an empty payload")
{
    PeerId id = makeId(0x01);
    vector<unsigned char> body = buildBody(id, {});
    CHECK(body.size() == id.size());

    PeerId parsedId{};
    vector<unsigned char> parsedPayload = {9, 9};   // must be replaced, not appended to
    REQUIRE(parseBody(string(body.begin(), body.end()), parsedId, parsedPayload));
    CHECK(parsedId == id);
    CHECK(parsedPayload.empty());
}

TEST_CASE("parseBody rejects a body shorter than an ID")
{
    PeerId id{};
    vector<unsigned char> payload;
    CHECK_FALSE(parseBody(string(31, 'x'), id, payload));
    CHECK_FALSE(parseBody(string(), id, payload));
}

// ---------- user lists ----------

namespace
{
// A USER_LIST body: the "more follows" flag, then the IDs.
string userListBody(bool more, const vector<PeerId>& ids)
{
    string body(1, more ? 1 : 0);
    for (const PeerId& id : ids)
    {
        body.append(reinterpret_cast<const char*>(id.data()), id.size());
    }
    return body;
}

vector<PeerId> manyIds(size_t n)
{
    vector<PeerId> ids(n);
    for (size_t i = 0; i < n; ++i)
    {
        ids[i][0] = static_cast<unsigned char>(i);        // unique for any n < 65536
        ids[i][1] = static_cast<unsigned char>(i >> 8);
    }
    return ids;
}
}

TEST_CASE("parseUserList accepts an empty list")
{
    set<PeerId> ids;
    bool more = true;
    REQUIRE(parseUserList(userListBody(false, {}), ids, more));
    CHECK(ids.empty());
    CHECK_FALSE(more);
}

TEST_CASE("parseUserList reads three IDs and the flag")
{
    PeerId a = makeId(0x01), b = makeId(0x02), c = makeId(0x03);

    set<PeerId> ids;
    bool more = false;
    REQUIRE(parseUserList(userListBody(true, {a, b, c}), ids, more));
    CHECK(more);
    CHECK(ids == set<PeerId>{a, b, c});
}

TEST_CASE("parseUserList adds to what's there, so a split list accumulates")
{
    PeerId a = makeId(0x01), b = makeId(0x02);
    set<PeerId> ids;
    bool more = false;
    REQUIRE(parseUserList(userListBody(true, {a}), ids, more));
    REQUIRE(parseUserList(userListBody(false, {b}), ids, more));
    CHECK(ids == set<PeerId>{a, b});
    CHECK_FALSE(more);
}

TEST_CASE("parseUserList rejects malformed bodies")
{
    set<PeerId> ids;
    bool more = false;
    CHECK_FALSE(parseUserList(string(), ids, more));                     // no flag byte
    CHECK_FALSE(parseUserList(string(1, '\x02'), ids, more));            // flag must be 0 or 1
    CHECK_FALSE(parseUserList(string(1, '\0') + string(31, 'x'), ids, more));
    CHECK_FALSE(parseUserList(string(1, '\0') + string(33, 'x'), ids, more));
    CHECK_FALSE(parseUserList(string(32, 'x'), ids, more));               // IDs without a flag
}

TEST_CASE("buildUserListBodies: an empty list is one frame with no IDs")
{
    auto bodies = buildUserListBodies({});
    REQUIRE(bodies.size() == 1);
    CHECK(bodies[0] == vector<unsigned char>{0});
}

TEST_CASE("buildUserListBodies splits long lists and parseUserList puts them back together")
{
    for (size_t n : {size_t{1}, USER_LIST_MAX_IDS, USER_LIST_MAX_IDS + 1, size_t{600}})
    {
        CAPTURE(n);
        const vector<PeerId> original = manyIds(n);
        auto bodies = buildUserListBodies(original);
        CHECK(bodies.size() == (n + USER_LIST_MAX_IDS - 1) / USER_LIST_MAX_IDS);

        set<PeerId> ids;
        for (size_t i = 0; i < bodies.size(); ++i)
        {
            // every frame fits: length field counts the type byte + body
            CHECK(1 + bodies[i].size() <= MAX_MESSAGE_SIZE);

            bool more = false;
            REQUIRE(parseUserList(string(bodies[i].begin(), bodies[i].end()), ids, more));
            CHECK(more == (i + 1 < bodies.size()));   // only the last says "no more"
        }
        CHECK(ids == set<PeerId>(original.begin(), original.end()));
    }
}
