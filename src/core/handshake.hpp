#ifndef HANDSHAKE_HPP
#define HANDSHAKE_HPP

#include <array>
#include <vector>

#include "crypto.hpp"

using HandshakeKey = std::array<unsigned char, crypto_kx_PUBLICKEYBYTES>;

enum class HandshakeAction
{
    REPLY,
    RESEND_OFFER,
    DERIVE,
    IGNORE,
};

enum class HandshakeCheck
{
    OK,
    EMPTY,
    UNKNOWN,
    BAD_SIZE,
    BAD_SIG,
};

struct IncomingHandshake
{
    HandshakeType kind;
    HandshakeKey key{};         // their offer key, or reply key
    HandshakeKey answered{};    // reply key only: offer key answered by this key
};

HandshakeCheck checkHandshake(const std::vector<unsigned char>& payload, const PeerId& sender, const unsigned char* myPk, IncomingHandshake& h);

HandshakeAction decideHandshake(const Session& s, const IncomingHandshake& h);


#endif
