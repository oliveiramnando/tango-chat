#include "doctest.h"
#include "util.hpp"

#include <string>

using namespace std;

TEST_CASE("isValidName accepts safe names")
{
    CHECK(isValidName("alice"));
    CHECK(isValidName("Bob_2"));
    CHECK(isValidName("test-user"));
    CHECK(isValidName(string(32, 'a')));   // exactly the limit
}

TEST_CASE("isValidName rejects unsafe names")
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

// ---------- sanitizeForTerminal ----------

TEST_CASE("sanitizeForTerminal keeps ordinary text")
{
    CHECK(sanitizeForTerminal("") == "");
    CHECK(sanitizeForTerminal("hello, world! 1 + 1 = 2 :)") == "hello, world! 1 + 1 = 2 :)");
    CHECK(sanitizeForTerminal("ol\xC3\xA1 \xE2\x82\xAC 5 \xF0\x9F\x99\x82") ==
          "ol\xC3\xA1 \xE2\x82\xAC 5 \xF0\x9F\x99\x82");   // olá € 5 🙂
}

TEST_CASE("sanitizeForTerminal replaces ASCII control characters")
{
    CHECK(sanitizeForTerminal("a\x1b[2Kb") == "a?[2Kb");   // ESC
    CHECK(sanitizeForTerminal("line1\nline2") == "line1?line2");
    CHECK(sanitizeForTerminal("x\ry") == "x?y");
    CHECK(sanitizeForTerminal("tab\there") == "tab?here");
    CHECK(sanitizeForTerminal("bell\a") == "bell?");
    CHECK(sanitizeForTerminal("del\x7f") == "del?");
    CHECK(sanitizeForTerminal(string("nul\0end", 7)) == "nul?end");
}

TEST_CASE("sanitizeForTerminal: a forged line can no longer redraw the screen")
{
    // what a contact could send to make a line appear from carol
    const string forged = "hi\r\x1b[2K\x1b[94mcarol\x1b[0m : send me the file";
    const string shown = sanitizeForTerminal(forged);

    CHECK(shown.find('\x1b') == string::npos);
    CHECK(shown.find('\r') == string::npos);
    CHECK(shown == "hi??[2K?[94mcarol?[0m : send me the file");
}

TEST_CASE("sanitizeForTerminal replaces C1 controls and direction overrides")
{
    CHECK(sanitizeForTerminal("a\xC2\x9B" "31mb") == "a?31mb");        // U+009B, works like ESC [
    CHECK(sanitizeForTerminal("x\xC2\x85y") == "x?y");                 // U+0085, next line
    CHECK(sanitizeForTerminal("abc\xE2\x80\xAE" "fed") == "abc?fed");  // U+202E, right-to-left override
    CHECK(sanitizeForTerminal("\xE2\x81\xA6x\xE2\x81\xA9") == "?x?");  // U+2066 ... U+2069 isolates
    CHECK(sanitizeForTerminal("a\xE2\x80\xA8" "b") == "a?b");          // U+2028, line separator
}

TEST_CASE("sanitizeForTerminal replaces invalid UTF-8 byte by byte")
{
    CHECK(sanitizeForTerminal("a\x9B" "b") == "a?b");              // lone continuation byte (raw 8-bit CSI)
    CHECK(sanitizeForTerminal("a\xC3") == "a?");                   // sequence cut short at the end
    CHECK(sanitizeForTerminal("a\xC3" "b") == "a?b");              // lead byte not followed by a continuation
    CHECK(sanitizeForTerminal("\xC0\xAF") == "??");                // overlong form of '/'
    CHECK(sanitizeForTerminal("\xE0\x80\x9B") == "???");           // overlong form of ESC-like bytes
    CHECK(sanitizeForTerminal("\xED\xA0\x80") == "???");           // UTF-16 surrogate
    CHECK(sanitizeForTerminal("\xF4\x90\x80\x80") == "????");      // past U+10FFFF
    CHECK(sanitizeForTerminal("\xFF\xFE") == "??");                // never valid in UTF-8
}

TEST_CASE("sanitizeForTerminal output never contains a control byte")
{
    // every single byte, and every pair, on its own
    for (int a = 0; a < 256; ++a)
    {
        for (int b = 0; b < 256; ++b)
        {
            const string in{static_cast<char>(a), static_cast<char>(b)};
            for (char ch : sanitizeForTerminal(in))
            {
                const unsigned char u = static_cast<unsigned char>(ch);
                REQUIRE_MESSAGE((u >= 0x20 && u != 0x7F), "bytes " << a << ", " << b);
            }
        }
    }
}
