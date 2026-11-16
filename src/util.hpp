#ifndef UTIL_HPP
#define UTIL_HPP

#include <string>
#include <vector>
#include <optional>

bool isValidName(const std::string& name);

std::vector<std::string> splitWords(const std::string& text);
std::optional<size_t> parseListNumber(const std::string& text, size_t count);

#endif
