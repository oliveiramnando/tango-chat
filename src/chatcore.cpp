#include "chatcore.hpp"

#include "util.hpp"

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
    
}

void ChatCore::onUserList(const string& body, Effects& out) 
{
    
}

void ChatCore::onUserOnline(const string& body, Effects& out) 
{
    
}

void ChatCore::onUserOffline(const string& body, Effects& out) 
{
    
}

