#ifndef HANDSHAKE_HPP
#define HANDSHAKE_HPP

#include <array>

#include "crypto.hpp"

using Key = std::array<unsigned char, 32>;

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
    Key key;    // their offer key, or reply key
    Key answered;   // reply key only: offer key answered by this key
};

HandshakeAction decideHandshake(const Session& s, const IncomingHandshake& h);


#endif
