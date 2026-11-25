#ifndef CHATCORE_HPP
#define CHATCORE_HPP

#include <vector>
#include <string>
#include <map>
#include <set>
#include <optional>

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

    INFO,           // cout cmd outputs
    SENT,           // msg you sent echoed
    CHAT_CHANGED,   // set promptTarget to event's name
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
    ChatCore(const Identity& id, std::map<PeerId, Session>& s, Contacts& c, std::set<PeerId>& uids, const std::string& myName, const std::string& contactsPath) 
    : me(id), sessions(s), contacts(c), userIds(uids), myName(myName), contactsPath(contactsPath) {}

    Effects onFrame(MsgType type, const std::string& body);     // frame arrvied from server
    Effects makeOfferTo(const PeerId& peer);

private:
    const Identity& me;
    std::map<PeerId, Session>& sessions;
    Contacts& contacts;
    std::set<PeerId>& userIds;
    std::set<PeerId> notifiedUnknown;

    std::string myName;
    std::string contactsPath;
    std::optional<PeerId> currentPeer;
    std::vector<PeerId> userList;

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

    void cmdUsers(Effects& out);
    void cmdContacts(const std::vector<std::string>& cmdArgs, Effects& out);
    void cmdAdd(const std::vector<std::string>& cmdArgs, Effects& out);
    void cmdRemove(const std::vector<std::string>& cmdArgs, Effects& out);
    void cmdChat(const std::vector<std::string>& cmdArgs, Effects& out);
    void sendText(const std::string& line, Effects& out);
};

#endif