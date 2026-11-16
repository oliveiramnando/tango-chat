#include "doctest.h"
#include "../src/util.hpp"

#include <string>

using namespace std;

TEST_CASE("isValidName accepts safe names")
{
    CHECK(isValidName("alice"));
    CHECK(isValidName("Bob_2"));
    CHECK(isValidName("test-user"));
    CHECK(isValidName(string(32, 'a')));   // exactly the limit
}

TEST_CASE("isValidProfileName rejects unsafe names")
{
    CHECK_FALSE(isValidName("../x"));      // path traversal
    CHECK_FALSE(isValidName("a/b"));
    CHECK_FALSE(isValidName(".."));
    CHECK_FALSE(isValidName(""));          // empty
    CHECK_FALSE(isValidName("a b"));       // space
    CHECK_FALSE(isValidName(string(33, 'a')));   // one over the limit
    CHECK_FALSE(isValidName("caf\xc3\xa9"));     // non-ASCII (é)
}

TEST_CASE("splitWords splits on any amount of whitespace")
{
    CHECK(splitWords("/add 2 bob") == vector<string>{"/add", "2", "bob"});
    CHECK(splitWords("   /add   2  bob  ") == vector<string>{"/add", "2", "bob"});
    CHECK(splitWords("/users") == vector<string>{"/users"});
    CHECK(splitWords("").empty());
    CHECK(splitWords("    ").empty());
}

TEST_CASE("parseListNumber accepts 1..count and returns a 0-based index")
{
    REQUIRE(parseListNumber("1", 3).has_value());
    CHECK(*parseListNumber("1", 3) == 0);
    CHECK(*parseListNumber("3", 3) == 2);
}

TEST_CASE("parseListNumber rejects everything else")
{
    CHECK_FALSE(parseListNumber("0", 3).has_value());
    CHECK_FALSE(parseListNumber("4", 3).has_value());
    CHECK_FALSE(parseListNumber("1", 0).has_value());           // empty list
    CHECK_FALSE(parseListNumber("", 3).has_value());
    CHECK_FALSE(parseListNumber("2abc", 3).has_value());        // stoul alone would accept this
    CHECK_FALSE(parseListNumber("-1", 3).has_value());
    CHECK_FALSE(parseListNumber(" 2", 3).has_value());
    CHECK_FALSE(parseListNumber("99999999999999999999", 3).has_value());   // would overflow
}
