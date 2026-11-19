#include "handshake.hpp"


HandshakeAction decideHandshake(const Session& s, const IncomingHandshake& h)
{
    if (h.kind == HandshakeType::OFFER)
    {
        if (s.state == SessionState::READY && memcmp(h.key.data(), s.pk, crypto_kx_PUBLICKEYBYTES) == 0)   // duplicate offer
        {
            return HandshakeAction::IGNORE;
        }
        if (s.state == SessionState::OFFERED && memcmp(h.key.data(), s.pk, crypto_kx_PUBLICKEYBYTES) < 0)   // have offer; there's smaller
        {
            return HandshakeAction::RESEND_OFFER;
        }
        return HandshakeAction::REPLY;
    }
    
    if (s.state == SessionState::OFFERED && h.kind == HandshakeType::REPLY && memcmp(h.key.data(), s.pk, crypto_kx_PUBLICKEYBYTES) == 0)    // have offer and they replied to it
    {
        return HandshakeAction::DERIVE;
    }

    return HandshakeAction::IGNORE;
}

