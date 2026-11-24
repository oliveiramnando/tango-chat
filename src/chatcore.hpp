#ifndef CHATCORE_HPP
#define CHATCORE_HPP

#include <vector>
#include <string>
#include <map>
#include <set>

#include "net.hpp"
#include "crypto.hpp"
#include "contacts.hpp"

struct OutgoingFrame
{
    MsgType type;
    std::vector<unsigned char> body;
};

enum class UiEventKind
{
    MESSAGE,    // message from contact
    CONNECTED,  // a secure session was set up
    NOTICE,     // neutral information;; no warning; unknown sender goes here
    WARNING,    // something went wrong or looks suspicious
};

struct UiEvent
{
    UiEventKind kind;
    std::string name;
    std::string text;
    std::string fingerprint;
};

struct Effects
{
    std::vector<OutgoingFrame> frames;
    std::vector<UiEvent> events;
    bool fatal = false;
};


class ChatCore 
{
public:
    ChatCore(const Identity& id, std::map<PeerId, Session>& s, Contacts& c, std::set<PeerId>& uids) : me(id), sessions(s), contacts(c), userIds(uids) {}

    Effects onFrame(MsgType type, const std::string& body);
    Effects makeOfferTo(const PeerId& peer);

private:
    const Identity& me;
    std::map<PeerId, Session>& sessions;
    Contacts& contacts;
    std::set<PeerId>& userIds;
    std::set<PeerId> notifiedUnknown;

    void onMessage(const std::string& body, Effects& out);
    void onHandshake(const std::string& body, Effects& out);
    void onError(const std::string& body, Effects& out);
    void onUserNotFound(const std::string& body, Effects& out);
    void onUserList(const std::string& body, Effects& out);
    void onUserOnline(const std::string& body, Effects& out);
    void onUserOffline(const std::string& body, Effects& out);

    bool amInitiator(const PeerId& peer);

    bool makeReply(const PeerId& peer, Session& s, const unsigned char* offerPk, Effects& out);
    bool makeResendOffer(const PeerId& peer, const Session& s, Effects& out);
    bool makeOffer(const PeerId& peer, Session& s, Effects& out);
};

#endif