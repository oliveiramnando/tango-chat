#include "util.hpp"
#include <cctype>
#include <sstream>
#include <cstdint>

using namespace std;

// profile names become folder names, so allow only safe characters
bool isValidName(const string& name)
{
    if (name.empty() || name.size() > 32)
    {
        return false;
    }
    for (char c : name)
    {
        if (!isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_')
        {
            return false;
        }
    }
    return true;
}

vector<string> splitWords(const string& text)
{
    vector<string> words; 
    stringstream in(text);
    string word;
    while (in >> word)
    {
        words.push_back(word);
    }
    return words;
}

optional<size_t> parseListNumber(const string& text, size_t count)
{
    if (text.empty() || text.size() > 9)
    {
        return nullopt;
    }

    for (char ch : text)
    {
        if (!isdigit(static_cast<unsigned char>(ch)))
        {
            return nullopt;
        }
    }

    size_t number = stoul(text);
    if (number < 1 || number > count)
    {
        return nullopt;
    }
    return number - 1; // Convert to 0-based index
}

// code points a terminal acts on instead of showing
static bool isUnsafeCodePoint(uint32_t cp)
{
    return (cp >= 0x80 && cp <= 0x9F)          // C1 controls (U+009B works like ESC [)
        || cp == 0x061C                        // arabic letter mark
        || cp == 0x200E || cp == 0x200F        // left-to-right / right-to-left marks
        || (cp >= 0x2028 && cp <= 0x2029)      // line / paragraph separators
        || (cp >= 0x202A && cp <= 0x202E)      // direction embeddings and overrides
        || (cp >= 0x2066 && cp <= 0x2069);     // direction isolates
}

string sanitizeForTerminal(const string& text)
{
    string out;
    out.reserve(text.size());

    size_t i = 0;
    while (i < text.size())
    {
        const unsigned char c = static_cast<unsigned char>(text[i]);

        // ascii: keep printable characters, replace control characters (ESC, \r, \n, tab, DEL...)
        if (c < 0x80)
        {
            out += (c >= 0x20 && c != 0x7F) ? static_cast<char>(c) : '?';
            ++i;
            continue;
        }

        // utf-8: sequence length from the first byte, and the smallest code point that length may encode
        size_t len = 0;
        uint32_t cp = 0;
        uint32_t minCp = 0;
        if ((c & 0xE0) == 0xC0)      { len = 2; cp = c & 0x1F; minCp = 0x80; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; minCp = 0x800; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; minCp = 0x10000; }

        bool valid = len > 0 && i + len <= text.size();
        for (size_t k = 1; valid && k < len; ++k)
        {
            const unsigned char next = static_cast<unsigned char>(text[i + k]);
            if ((next & 0xC0) != 0x80)
            {
                valid = false;      // not a continuation byte
            }
            cp = (cp << 6) | (next & 0x3F);
        }
        // reject overlong forms, surrogates and anything past U+10FFFF
        valid = valid && cp >= minCp && cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF);

        if (!valid)
        {
            out += '?';     // one '?' per bad byte, then carry on with the next byte
            ++i;
            continue;
        }

        if (isUnsafeCodePoint(cp))
        {
            out += '?';
        }
        else
        {
            out.append(text, i, len);
        }
        i += len;
    }
    return out;
}

