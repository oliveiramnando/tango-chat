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
        warn.text =  "Malformed USER_NOT_FOUND received.";
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

