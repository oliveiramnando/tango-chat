#ifndef HANDSHAKE_HPP
#define HANDSHAKE_HPP

#include <array>

#include "crypto.hpp"

using HandshakeKey = std::array<unsigned char, 32>;

enum class HandshakeAction
{
    REPLY,
    RESEND_OFFER,
    DERIVE,
    IGNORE,
};

struct IncomingHandshake
{
    HandshakeType kind;
    HandshakeKey key{};         // their offer key, or reply key
    HandshakeKey answered{};    // reply key only: offer key answered by this key
};

HandshakeAction decideHandshake(const Session& s, const IncomingHandshake& h);


#endif
