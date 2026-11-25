#include "handshake.hpp"

#include <cstring>
#include <vector>

using namespace std;

HandshakeCheck checkHandshake(const vector<unsigned char>& payload, const PeerId& sender, const unsigned char* myPk, IncomingHandshake& h)
{
    h = IncomingHandshake();
    if (payload.empty())
    {
        return HandshakeCheck::EMPTY;
    }

    h.kind = static_cast<HandshakeType>(payload[0]);

    const unsigned char* peerKey = nullptr;
    const unsigned char* answeredKey = nullptr;

    if (h.kind == HandshakeType::OFFER)
    {
        if (payload.size() != OFFER_PAYLOAD_SIZE)
        {
            return HandshakeCheck::BAD_SIZE;
        }

        peerKey = payload.data() + 1;
        const unsigned char* sig = payload.data() + 1 + crypto_kx_PUBLICKEYBYTES;

        if (!verifyOffer(sender.data(), myPk, peerKey, sig))
        {
            return HandshakeCheck::BAD_SIG;
        }

        memcpy(h.key.data(), peerKey, crypto_kx_PUBLICKEYBYTES);
    }
    else if (h.kind == HandshakeType::REPLY)
    {
        if (payload.size() != REPLY_PAYLOAD_SIZE)
        {
            return HandshakeCheck::BAD_SIZE;
        }

        peerKey = payload.data() + 1;
        answeredKey = payload.data() + 1 + crypto_kx_PUBLICKEYBYTES;
        const unsigned char* sig = payload.data() + 1 + crypto_kx_PUBLICKEYBYTES*2;

        if (!verifyReply(sender.data(), myPk, peerKey, answeredKey, sig))
        {
            return HandshakeCheck::BAD_SIG;
        }

        memcpy(h.key.data(), peerKey, crypto_kx_PUBLICKEYBYTES);
        memcpy(h.answered.data(), answeredKey, crypto_kx_PUBLICKEYBYTES);
    }
    else
    {
        return HandshakeCheck::UNKNOWN;
    }

    return HandshakeCheck::OK;
}


HandshakeAction decideHandshake(const Session& s, const IncomingHandshake& h)
{
    if (h.kind == HandshakeType::OFFER)
    {
        if (s.state == SessionState::READY && memcmp(h.key.data(), s.peerPk, crypto_kx_PUBLICKEYBYTES) == 0)   // duplicate offer
        {
            return HandshakeAction::IGNORE;
        }
        if (s.state == SessionState::OFFERED && memcmp(s.pk, h.key.data(), crypto_kx_PUBLICKEYBYTES) < 0)   // crossed offers; ours is lower
        {
            return HandshakeAction::RESEND_OFFER;
        }
        return HandshakeAction::REPLY;
    }
    
    if (s.state == SessionState::OFFERED && h.kind == HandshakeType::REPLY && memcmp(h.answered.data(), s.pk, crypto_kx_PUBLICKEYBYTES) == 0)    // have offer and they replied to it
    {
        return HandshakeAction::DERIVE;
    }

    return HandshakeAction::IGNORE;
}

