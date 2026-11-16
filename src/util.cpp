#include "util.hpp"
#include <cctype>
#include <sstream>

using namespace std;

// Profile names become folder names, so allow only safe characters.
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

