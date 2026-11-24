#include "chatcore.hpp"

#include <cstring>

#include "util.hpp"
#include "net.hpp"

using namespace std;


Effects ChatCore::onFrame(MsgType type, const std::string& body)
{
    Effects out;

    switch (type)
    {
        case MsgType::MESSAGE:
            onMessage(body, out);
            break;
        case MsgType::HANDSHAKE:
            onHandshake(body, out);
            break;
        case MsgType::ERROR_MSG:
            onError(body, out);
            break;
        case MsgType::USER_NOT_FOUND:
            onUserNotFound(body, out);
            break;
        case MsgType::USER_LIST:
            onUserList(body, out);
            break;
        case MsgType::USER_ONLINE:
            onUserOnline(body, out);
            break;
        case MsgType::USER_OFFLINE:
            onUserOffline(body, out);
            break;
        default:
        {
            UiEvent err{};
            err.kind = UiEventKind::WARNING;
            err.text = "Invalid Message Type.";
            out.events.push_back(err);
            out.fatal = true;
            break;
        }
            
    }
    return out;
}


void ChatCore::onMessage(const string& body, Effects& out) 
{
    PeerId sender{};
    vector<unsigned char> payload;
    if (!parseBody(body, sender, payload))
    {
        UiEvent warn{};
        warn.kind = UiEventKind::WARNING;
        warn.text = "Malformed MESSAGE received.";
        out.events.push_back(warn);
        return;
    }

    // find that sender's session
    auto it = sessions.find(sender);
    if (it == sessions.end() || it->second.state != SessionState::READY)
    {
        UiEvent warn{};
        warn.kind = UiEventKind::WARNING;
        warn.text = "Message from unknown or unsecured peer rejected.";
        out.events.push_back(warn);
        return;
    }

    // decrypt message here with sender's rx jey
    string nameAndMessage;
    uint64_t skipped = 0;
    OpenResult result = openMessage(it->second, sender.data(), me.pk, string(payload.begin(), payload.end()), nameAndMessage, skipped);
    if (result == OpenResult::INVALID)
    {
        UiEvent warn{};
        warn.kind = UiEventKind::WARNING;
        warn.text = "Failed to decrypt message.";
        out.events.push_back(warn);
        return;
    }
    if (result == OpenResult::REPLAYED)
    {
        UiEvent warn{};
        warn.kind = UiEventKind::WARNING;
        warn.text = "Rejected a repeated or out-of-order message from " + displayName(contacts, sender) + ".";
        out.events.push_back(warn);
        return;
    }
    if (skipped > 0)
    {
        UiEvent warn{};
        warn.kind = UiEventKind::WARNING;
        warn.text = "Warning: " + to_string(skipped) + " earlier message(s) from " + displayName(contacts, sender) + " never arrived.";
        out.events.push_back(warn);
    }

    size_t colonIdx = nameAndMessage.find(" : ");
    if (colonIdx == string::npos)
    {
        UiEvent warn{};
        warn.kind = UiEventKind::WARNING;
        warn.text = "Client sender does not have a name.";
        out.events.push_back(warn);        
        return;
    }
       
    UiEvent message{};
    message.kind = UiEventKind::MESSAGE;
    message.name = displayName(contacts, sender);
    message.text = sanitizeForTerminal(nameAndMessage.substr(colonIdx + 3));

    out.events.push_back(message);
}

void ChatCore::onHandshake(const string& body, Effects& out) 
{
    
}

void ChatCore::onError(const string& body, Effects& out) 
{
    UiEvent err{};
    err.kind = UiEventKind::WARNING;
    err.text = sanitizeForTerminal(body);
    out.events.push_back(err);
}

void ChatCore::onUserNotFound(const string& body, Effects& out) 
{
    // server couldn't deliver to this user: they're not online
    PeerId missing{};
    if (body.size() != missing.size())
    {
        UiEvent warn{};
        warn.kind = UiEventKind::WARNING;
        warn.text = "Malformed USER_NOT_FOUND received.";
        out.events.push_back(warn);
        return;
    }
    memcpy(missing.data(), body.data(), missing.size());

    UiEvent notfound{};
    notfound.kind = UiEventKind::NOTICE;
    notfound.text = displayName(contacts, missing) + " is not online.";
    out.events.push_back(notfound);
    
    // any session with them is stale
    auto it = sessions.find(missing);
    if (it != sessions.end())
    {
        wipeSession(it->second);
        sessions.erase(it);
    }
}

void ChatCore::onUserList(const string& body, Effects& out) 
{
    bool more = false;
    if (!parseUserList(body, userIds, more))
    {
        UiEvent warn{};
        warn.kind = UiEventKind::WARNING;
        warn.text =  "Failed to parse list of online users.";
        out.events.push_back(warn);
    }
}

void ChatCore::onUserOnline(const string& body, [[maybe_unused]] Effects& out) 
{
    PeerId id{};
    if (body.size() != PeerId{}.size())
    {
        return;
    }

    memcpy(id.data(), body.data(), PeerId{}.size());
    userIds.insert(id);
}

void ChatCore::onUserOffline(const string& body, [[maybe_unused]] Effects& out) 
{
    PeerId id{};
    if (body.size() != PeerId{}.size())
    {
        return;
    }
    memcpy(id.data(), body.data(), PeerId{}.size());
    userIds.erase(id);
    
    auto it = sessions.find(id);
    if (it != sessions.end())
    {
        wipeSession(it->second);
        sessions.erase(it);
    }
}


bool ChatCore::amInitiator(const PeerId& peer)
{
    return memcmp(me.pk, peer.data(), crypto_sign_PUBLICKEYBYTES) < 0;
}

bool ChatCore::makeReply(const PeerId& peer, Session& s, const unsigned char* offerPk, Effects& out)
{
    wipeSession(s);
    s.isInitiator = amInitiator(peer);
    makeKeyPair(s);

    if (!deriveSessionKeys(s, string(offerPk, offerPk + crypto_kx_PUBLICKEYBYTES)))
    {
        return false;
    }

    unsigned char sig[crypto_sign_BYTES];
    if (!signReply(me, peer.data(), s.pk, offerPk, sig))
    {
        return false;
    }

    vector<unsigned char> handshakePayload{static_cast<unsigned char>(HandshakeType::REPLY)};       // [type]
    handshakePayload.insert(handshakePayload.end(), s.pk, s.pk + crypto_kx_PUBLICKEYBYTES);         // [type][key]
    handshakePayload.insert(handshakePayload.end(), offerPk, offerPk + crypto_kx_PUBLICKEYBYTES);   // [type][key][offer]
    handshakePayload.insert(handshakePayload.end(), sig, sig + crypto_sign_BYTES);                  // [type][key][offer][sig]

    vector<unsigned char> body = buildBody(peer, handshakePayload);

    OutgoingFrame reply{};
    reply.type = MsgType::HANDSHAKE;
    reply.body = body;

    out.frames.push_back(reply);

    s.state = SessionState::READY;

    return true;
}

bool ChatCore::makeResendOffer(const PeerId& peer, const Session& s, Effects& out)
{
    if (s.state != SessionState::OFFERED)
    {
        return false;
    }

    unsigned char sig[crypto_sign_BYTES];
    if (!signOffer(me, peer.data(), s.pk, sig))
    {
        return false;
    }

    vector<unsigned char> handshakePayload{static_cast<unsigned char>(HandshakeType::OFFER)};   // [type]
    handshakePayload.insert(handshakePayload.end(), s.pk, s.pk + crypto_kx_PUBLICKEYBYTES);     // [type][key]
    handshakePayload.insert(handshakePayload.end(), sig, sig + crypto_sign_BYTES);              // [type][key][sig]

    vector<unsigned char> body = buildBody(peer, handshakePayload);

    OutgoingFrame resend{};
    resend.type = MsgType::HANDSHAKE;
    resend.body = body;

    out.frames.push_back(resend);

    return true;
}

bool ChatCore::makeOffer(const PeerId& peer, Session& s, Effects& out)
{
    wipeSession(s);
    s.isInitiator = amInitiator(peer);
    makeKeyPair(s);

    unsigned char sig[crypto_sign_BYTES];
    if (!signOffer(me, peer.data(), s.pk, sig))
    {
        return false;
    }

    vector<unsigned char> handshakePayload{static_cast<unsigned char>(HandshakeType::OFFER)};   // [Type]
    handshakePayload.insert(handshakePayload.end(), s.pk, s.pk + crypto_kx_PUBLICKEYBYTES);     // [Type][Key]
    handshakePayload.insert(handshakePayload.end(), sig, sig + crypto_sign_BYTES);              // [Type][key][sig]

    vector<unsigned char> body = buildBody(peer, handshakePayload);

    OutgoingFrame offer{};
    offer.type = MsgType::HANDSHAKE;
    offer.body = body;

    out.frames.push_back(offer);

    s.state = SessionState::OFFERED;

    return true;
}

