#include "chatcore.hpp"

#include <cstring>
#include <string>

#include "util.hpp"
#include "net.hpp"
#include "handshake.hpp"

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

Effects ChatCore::onInput(const std::string& line)
{
    Effects out;

    if (line.starts_with('/'))
    {
        vector<string> cmdArgs = splitWords(line);
        string fcmd = cmdArgs[0];
        if      (fcmd == "/users")     { cmdUsers(out); }
        else if (fcmd == "/contacts")  { cmdContacts(cmdArgs, out); }
        else if (fcmd == "/add")       { cmdAdd(cmdArgs, out); }
        else if (fcmd == "/remove")    { cmdRemove(cmdArgs, out); }
        else if (fcmd == "/chat")      { cmdChat(cmdArgs, out); }
        else 
        { 
            UiEvent warn{};
            warn.kind = UiEventKind::WARNING;
            warn.text = "Invalid command: " + sanitizeForTerminal(fcmd);
            out.events.push_back(warn);
        }
    }
    else
    {
        sendText(line, out);
    }

    return out;
}

Effects ChatCore::makeOfferTo(const PeerId& peer)
{
    Effects out{};

    if (!makeOffer(peer, sessions[peer], out))
    {
        wipeSession(sessions[peer]);
        sessions.erase(peer);

        UiEvent warn{};
        warn.kind = UiEventKind::WARNING;
        warn.text = "Failed to send handshake to " + displayName(contacts, peer) + ".";
        out.events.push_back(warn);
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
    // parse body here to extract sender
    PeerId sender{};
    vector<unsigned char> payload;
    if (!parseBody(body, sender, payload))
    {
        UiEvent warn{};
        warn.kind = UiEventKind::WARNING;
        warn.text = "Malformed HANDSHAKE received.";
        out.events.push_back(warn);
        return;
    }

    IncomingHandshake h{};
    switch (checkHandshake(payload, sender, me.pk, h))
    {
        case HandshakeCheck::OK:
            break;
        case HandshakeCheck::EMPTY:
        {
            UiEvent warn{};
            warn.kind = UiEventKind::WARNING;
            warn.text = "Malformed payload received.";
            out.events.push_back(warn);
            return;
        }
        case HandshakeCheck::UNKNOWN:
        {
            UiEvent warn{};
            warn.kind = UiEventKind::WARNING;
            warn.text = "Unknown handshake type. Rejected.";
            out.events.push_back(warn);
            return;
        }
        case HandshakeCheck::BAD_SIZE:
        {
            UiEvent warn{};
            warn.kind = UiEventKind::WARNING;
            warn.text = string("Malformed ") + (h.kind == HandshakeType::OFFER ? "Offer" : "Reply") + " payload received.";
            out.events.push_back(warn);
            return;
        }
        case HandshakeCheck::BAD_SIG:
        {
            UiEvent warn{};
            warn.kind = UiEventKind::WARNING;
            warn.text = string((h.kind == HandshakeType::OFFER ? "Offer" : "Reply")) + " signature invalid. Rejected.";
            out.events.push_back(warn);
            return;
        }
    }

    if (!contacts.contains(sender))
    {
        if (!notifiedUnknown.contains(sender))
        {
            UiEvent notice{};
            notice.kind = UiEventKind::NOTICE;
            notice.text = "Unknown [" + idFingerPrint(sender.data()) + "] wants to chat. Compare fingerprints, then /users and /add them.";
            out.events.push_back(notice);

            notifiedUnknown.insert(sender);
        }
        
        return;
    }

    Session& s = sessions[sender];
    switch (decideHandshake(s, h))
    {
        case HandshakeAction::REPLY:
            if (!makeReply(sender, s, h.key.data(), out))
            {
                UiEvent warn{};
                warn.kind = UiEventKind::WARNING;
                warn.text = "Failed to reply to handshake.";
                out.events.push_back(warn);

                wipeSession(s);
                sessions.erase(sender);
                return;
            }
            break;
        case HandshakeAction::RESEND_OFFER:
            if (!makeResendOffer(sender, s, out))
            {
                UiEvent warn{};
                warn.kind = UiEventKind::WARNING;
                warn.text = "Failed to resend offer.";
                out.events.push_back(warn);

                wipeSession(s);
                sessions.erase(sender);
            }
            return;
        case HandshakeAction::DERIVE:
            if (!deriveSessionKeys(s, string(h.key.data(), h.key.data() + crypto_kx_PUBLICKEYBYTES)))
            {
                UiEvent warn{};
                warn.kind = UiEventKind::WARNING;
                warn.text = "Failed to derive session keys. Handshake rejected.";
                out.events.push_back(warn);

                wipeSession(s);
                sessions.erase(sender);
                return;
            }
            s.state = SessionState::READY;
            break;
        case HandshakeAction::IGNORE:
            return;
    }

    UiEvent conn{};
    conn.kind = UiEventKind::CONNECTED;
    conn.name = displayName(contacts, sender);
    conn.fingerprint = sessionFingerPrint(s);

    out.events.push_back(conn);
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


void ChatCore::cmdUsers(Effects& out)
{
    userList.clear();
    int n = 1;
    for (const auto& uid : userIds)
    { 
        UiEvent info{};
        info.kind = UiEventKind::INFO;
        info.text = to_string(n) + ") " + displayName(contacts, uid);

        out.events.push_back(info);
        userList.push_back(uid);
        n++;
    }
}

void ChatCore::cmdContacts(const std::vector<std::string>& cmdArgs, Effects& out)
{
    if (cmdArgs.size() != 1)
    {
        UiEvent notice{};
        notice.kind = UiEventKind::NOTICE;
        notice.text = "Usage: /contacts";
        out.events.push_back(notice);
    }
    else if (contacts.empty())
    {
        UiEvent notice{};
        notice.kind = UiEventKind::NOTICE;
        notice.text = "No contacts yet. Type /users, then /add n name.";
        out.events.push_back(notice);
    }
    else
    {
        for (const auto& [contactId, contactName] : contacts)
        {
            if (userIds.contains(contactId))
            {
                UiEvent info{};
                info.kind = UiEventKind::INFO;
                info.text = "* " + contactName + " [" + idFingerPrint(contactId.data()) + "]";
                out.events.push_back(info);
            }
            else
            {
                UiEvent info{};
                info.kind = UiEventKind::INFO;
                info.text = "  " + contactName + " [" + idFingerPrint(contactId.data()) + "]";
                out.events.push_back(info);
            }
        }
    }
}

void ChatCore::cmdAdd(const std::vector<std::string>& cmdArgs, Effects& out)
{
    optional<size_t> index;
    if (cmdArgs.size() == 3)
    {
        index = parseListNumber(cmdArgs[1], userList.size());
    }

    if (cmdArgs.size() != 3)
    {
        UiEvent notice{};
        notice.kind = UiEventKind::NOTICE;
        notice.text = "Usage: /add <number from /users> <name>";
        out.events.push_back(notice);
    }
    else if (!index)
    {
        UiEvent notice{};
        notice.kind = UiEventKind::NOTICE;
        notice.text = "No such user. Type /users to see the list.";
        out.events.push_back(notice);
    }
    else
    {
        const PeerId selected = userList[*index];
        const string& newName = cmdArgs[2];

        auto existing = contacts.find(selected);
        if (existing != contacts.end() && existing->second == newName)
        {
            UiEvent notice{};
            notice.kind = UiEventKind::NOTICE;
            notice.text = newName + " is already saved.";
            out.events.push_back(notice);
        }
        else
        {
            string error;
            if (!addContact(contacts, selected, newName, error))
            {
                UiEvent notice{};
                notice.kind = UiEventKind::NOTICE;
                notice.text = "Could not add contact: " + error;
                out.events.push_back(notice);
            }
            else if (!saveContacts(contactsPath, contacts))
            {
                contacts.erase(selected);          // keep memory in step with the file

                UiEvent notice{};
                notice.kind = UiEventKind::NOTICE;
                notice.text = "Could not save the contacts file.";
                out.events.push_back(notice);
            }
            else
            {
                UiEvent info{};
                info.kind = UiEventKind::INFO;
                info.text = "Saved " + newName + " (" + idFingerPrint(selected.data()) + ").";
                out.events.push_back(info);
                
                info.kind = UiEventKind::INFO;
                info.text = "Only trust this if it matches what " + newName + " sees as 'Your fingerprint'.";
                out.events.push_back(info);
            }
        }
    }
}

void ChatCore::cmdRemove(const std::vector<std::string>& cmdArgs, Effects& out)
{
    optional<PeerId> contactId;
    if (cmdArgs.size() == 2)
    {
        contactId = findByName(contacts, cmdArgs[1]);
    }

    if (cmdArgs.size() != 2)
    {
        UiEvent notice{};
        notice.kind = UiEventKind::NOTICE;
        notice.text = "Usage: /remove <contact name>";
        out.events.push_back(notice);
    }
    else if (contacts.empty())
    {
        UiEvent notice{};
        notice.kind = UiEventKind::NOTICE;
        notice.text = "No contacts yet. Type /users, then /add n name.";
        out.events.push_back(notice);
    }
    else if (!contactId)
    {
        UiEvent notice{};
        notice.kind = UiEventKind::NOTICE;
        notice.text = "No such contact. Type /contacts to see the list.";
        out.events.push_back(notice);
    }
    else
    {
        string contactName = cmdArgs[1];
        contacts.erase(*contactId);

        if (!saveContacts(contactsPath, contacts))
        {
            contacts[*contactId] = contactName;         // keep memory in step with the file
            UiEvent notice{};
            notice.kind = UiEventKind::NOTICE;
            notice.text = "Could not save the contacts file.";
            out.events.push_back(notice);
        }
        else
        {
            UiEvent info{};
            info.kind = UiEventKind::INFO;
            info.text =  "Contact removed: " + contactName + " (" + idFingerPrint(contactId->data()) + ")";
            out.events.push_back(info);

            // end any session with them
            auto it = sessions.find(*contactId);
            if (it != sessions.end())
            {
                wipeSession(it->second);
                sessions.erase(it);
            }

            // deselect them only if they're the person we're currently chatting with.
            if (currentPeer && *currentPeer == *contactId)
            {
                currentPeer.reset();
                UiEvent chatChange{};
                chatChange.kind = UiEventKind::CHAT_CHANGED;
                out.events.push_back(chatChange);

                info.text =  "Chat with " + contactName + " closed.";
                out.events.push_back(info);
            }
        }
        
    }
}

void ChatCore::cmdChat(const std::vector<std::string>& cmdArgs, Effects& out)
{
    optional<PeerId> contactId;
    if (cmdArgs.size() == 2)
    {
        contactId = findByName(contacts, cmdArgs[1]);
    }

    if (cmdArgs.size() != 2)
    {
        UiEvent notice{};
        notice.kind = UiEventKind::NOTICE;
        notice.text = "Usage: /chat <contact name>";
        out.events.push_back(notice);
    }
    else if (contacts.empty())
    {
        UiEvent notice{};
        notice.kind = UiEventKind::NOTICE;
        notice.text = "No contacts yet. Type /users, then /add n name.";
        out.events.push_back(notice);
    }
    else if (!contactId)
    {
        UiEvent notice{};
        notice.kind = UiEventKind::NOTICE;
        notice.text = "No such contact. Type /contacts to see the list.";
        out.events.push_back(notice);
    }
    else
    {
        PeerId selected = *contactId;
        
        if (!userIds.contains(selected))
        {
            UiEvent notice{};
            notice.kind = UiEventKind::NOTICE;
            notice.text = "That user is no longer online.";
            out.events.push_back(notice);
        }
        else
        {
            const string peerName = displayName(contacts, selected);

            UiEvent info{};
            info.kind = UiEventKind::INFO;
            info.text = "Now chatting with " + peerName;
            out.events.push_back(info);

            currentPeer = selected;

            UiEvent chatChange{};
            chatChange.kind = UiEventKind::CHAT_CHANGED;
            chatChange.name = peerName;
            out.events.push_back(chatChange);

            auto it = sessions.find(selected);

            if (it != sessions.end() && it->second.state == SessionState::READY)
            {
                UiEvent info{};
                info.kind = UiEventKind::INFO;
                info.text = "Already connected to " + peerName + ".";
                out.events.push_back(info);
            }
            else
            {
                // NONE (or no session yet): start a handshake.
                // OFFERED: send a fresh offer; safe at any time, a reply to the old one is ignored as stale.
                const bool retrying = (it != sessions.end() && it->second.state == SessionState::OFFERED);
                UiEvent notice{};
                notice.kind = UiEventKind::NOTICE;
                notice.text = (retrying ? "No reply yet, sending a new offer..." : "Establishing secure connection...");
                out.events.push_back(notice);

                Effects offer = makeOfferTo(selected);
                out.frames.insert(out.frames.end(), offer.frames.begin(), offer.frames.end());
                out.events.insert(out.events.end(), offer.events.begin(), offer.events.end());
            }
        }
    }
}

void ChatCore::sendText(const string& line, Effects& out)
{
    if (line.empty())
    {
        return; 
    }

    if (!currentPeer)
    {
        UiEvent warn{};
        warn.kind = UiEventKind::WARNING;
        warn.text = "No chat selected. Type /contacts, then /chat <name>.";
        out.events.push_back(warn);
        return;
    }

    auto it = sessions.find(*currentPeer);
    if (it == sessions.end() || it->second.state != SessionState::READY)
    {
        UiEvent warn{};
        warn.kind = UiEventKind::WARNING;
        warn.text = "Connection not secured yet. Wait for the fingerprint.";
        out.events.push_back(warn);
        return;
    }

    string message = myName + " : " + line; 

    if (1 + PeerId{}.size() + MESSAGE_OVERHEAD + message.size() > MAX_MESSAGE_SIZE)
    {
        UiEvent warn{};
        warn.kind = UiEventKind::WARNING;
        warn.text = "Message too long.";
        out.events.push_back(warn);
        return;
    }

    vector<unsigned char> encrypted{};
    if (!sealMessage(it->second, me.pk, currentPeer->data(), message, encrypted))
    {
        UiEvent warn{};
        warn.kind = UiEventKind::WARNING;
        warn.text = "Failed to encrypt message.";
        out.events.push_back(warn);
        return;
    }
    
    vector<unsigned char> frameBody = buildBody(*currentPeer, encrypted);

    OutgoingFrame send{};
    send.type = MsgType::MESSAGE;
    send.body = frameBody;
    out.frames.push_back(send);

    UiEvent sent{};
    sent.kind = UiEventKind::SENT;
    sent.text = line;
    out.events.push_back(sent);
}

