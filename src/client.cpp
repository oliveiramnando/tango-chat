#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <cerrno>
#include <cstdlib>
#include <vector>
#include <cstring>
#include <cstdint>
#include <set>
#include <map>
#include <optional>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string>
#include <thread>
#include <mutex>
#include <atomic>

#include <termios.h>
#include <csignal>

#include <sodium.h>

#include <filesystem>
#include <cctype>

#include "net.hpp"
#include "crypto.hpp"
#include "util.hpp"
#include "contacts.hpp"
#include "handshake.hpp"
#include "chatcore.hpp"

using namespace std;

string inputBuffer;
mutex terminalMutex;
mutex userIdsMutex;
termios origTerminal{};
atomic<bool> quitting = false;

set<PeerId> userIds;

string promptTarget;

void redrawPrompt()     // caller must hold terminalMutex.
{
    cout << "\r\033[K\033[92myou\033[0m";
    if (!promptTarget.empty())
    {
        cout << " -> \033[94m" << promptTarget << "\033[0m";
    }
    cout << " > " << inputBuffer << flush;
}

void restoreTerminal()
{
    tcsetattr(STDIN_FILENO, TCSANOW, &origTerminal);
}

bool prepareProfileDir(const string& profile, string& dir)
{
    dir = "profiles/" + profile;

    error_code ec;
    filesystem::create_directories(dir, ec);
    if (ec)
    {
        return false;
    }

    filesystem::permissions(dir, filesystem::perms::owner_all, filesystem::perm_options::replace, ec);
    return !ec;
}

bool amInitiator(const Identity& me, const PeerId& peer)
{
    return memcmp(me.pk, peer.data(), 32) < 0;
}

bool sendOffer(int sock, const Identity& me, const PeerId& peer, Session& s)
{
    wipeSession(s);
    s.isInitiator = amInitiator(me, peer);
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

    if(!sendFrame(sock, MsgType::HANDSHAKE, body))
    {
        return false;
    }

    s.state = SessionState::OFFERED;

    return true;
}

bool sendReply(int sock, const Identity& me, const PeerId& peer, Session& s, const unsigned char* offerPk)
{
    wipeSession(s);
    s.isInitiator = amInitiator(me, peer);
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

    if (!sendFrame(sock, MsgType::HANDSHAKE, body))
    {
        return false;
    }

    s.state = SessionState::READY;

    return true;
}

bool resendOffer(int sock, const Identity& me, const PeerId& peer, const Session& s)
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
    return sendFrame(sock, MsgType::HANDSHAKE, body);
}

void showEvent(const UiEvent& event)
{
    // caller must hold terminal mutex
    switch (event.kind)
    {
        case UiEventKind::MESSAGE:
            cout << "\033[94m" << event.name << "\033[0m : " << event.text << endl;
            break;
        case UiEventKind::CONNECTED:
            cout << "Verified secure connection with " << event.name << endl;
            cout << "Session fingerprint: " << event.fingerprint << endl;
            break;
        case UiEventKind::NOTICE:
            cerr << event.text << endl;
            break;
        case UiEventKind::WARNING:
            cerr << event.text << endl;
            break;
    }
}


void receiveMsg(int clientSocket, map<PeerId, Session>& sessions, const Identity& id, Contacts& contacts)
{
    set<PeerId> notifiedUnknown;
    while (true)
    {
        MsgType type;
        string body{};
        if(!receiveFrame(clientSocket, type, body))
        {
            if (quitting) { break; }
            {
                lock_guard<mutex> lock(terminalMutex);
                cout << "\r\033[K";
                cerr << "Error receiving frame." << endl;
            }
            exit(0);
        }

        // branch by type here
        switch(type)
        {
            case MsgType::MESSAGE:
                {
                    lock_guard<mutex> lock(terminalMutex);
                    cout << "\r\033[K";

                    PeerId sender{};
                    vector<unsigned char> payload;
                    if (!parseBody(body, sender, payload))
                    {
                        cerr << "Malformed MESSAGE received." << endl;
                        redrawPrompt();
                        continue;
                    }

                    // find taht sender's session
                    auto it = sessions.find(sender);
                    if (it == sessions.end() || it->second.state != SessionState::READY)
                    {
                        cerr << "Message from unknown or unsecured peer rejected." << endl;
                        redrawPrompt();
                        continue;
                    }

                    // decrypt message here with sender's rx jey
                    string nameAndMessage;
                    uint64_t skipped = 0;
                    OpenResult result = openMessage(it->second, sender.data(), id.pk, string(payload.begin(), payload.end()), nameAndMessage, skipped);
                    if (result == OpenResult::INVALID)
                    {
                        cerr << "Failed to decrypt message." << endl;
                        redrawPrompt();
                        continue;
                    }
                    if (result == OpenResult::REPLAYED)
                    {
                        cerr << "Rejected a repeated or out-of-order message from " << displayName(contacts, sender) << "." << endl;
                        redrawPrompt();
                        continue;
                    }
                    if (skipped > 0)
                    {
                        cerr << "Warning: " << skipped << " earlier message(s) from " << displayName(contacts, sender) << " never arrived." << endl;
                    }

                    size_t colonIdx = nameAndMessage.find(" : ");
                    if (colonIdx == string::npos)
                    {
                        cout << "\r\033[K";
                        cerr << "Client sender does not have a name" << endl;
                        redrawPrompt();
                        
                        continue;
                    }
                    string name = nameAndMessage.substr(0, colonIdx);
                    string message = nameAndMessage.substr(colonIdx + 3);
                        
                    cout << "\033[94m" << displayName(contacts, sender) << "\033[0m : " << sanitizeForTerminal(message) << endl;
                    redrawPrompt();
                }
                continue;
            case MsgType::HANDSHAKE:
                {
                    lock_guard<mutex> lock(terminalMutex);

                    cout << "\r\033[K";
        
                    // parse body here to extract sender
                    PeerId sender{};
                    vector<unsigned char> payload;
                    if (!parseBody(body, sender, payload))
                    {
                        cerr << "Malformed HANDSHAKE received." << endl;
                        redrawPrompt();
                        continue;
                    }

                    IncomingHandshake h{};
                    switch (checkHandshake(payload, sender, id.pk, h))
                    {
                        case HandshakeCheck::OK:
                            break;
                        case HandshakeCheck::EMPTY:
                            cerr << "Malformed payload received." << endl;
                            redrawPrompt();
                            continue;
                        case HandshakeCheck::UNKNOWN:
                            cerr << "Unknown handshake type. Rejected." << endl;
                            redrawPrompt();
                            continue;
                        case HandshakeCheck::BAD_SIZE:
                            cerr << "Malformed " << (h.kind == HandshakeType::OFFER ? "Offer" : "Reply") << " payload received." << endl;
                            redrawPrompt();
                            continue;
                        case HandshakeCheck::BAD_SIG:
                            cerr << (h.kind == HandshakeType::OFFER ? "Offer" : "Reply") << " signature invalid. Rejected." << endl;
                            redrawPrompt();
                            continue;
                    }

                    if (!contacts.contains(sender))
                    {
                        if (!notifiedUnknown.contains(sender))
                        {
                            cerr << "Unknown [" << idFingerPrint(sender.data()) << "] wants to chat. Compare fingerprints, then /users and /add them." << endl;
                            notifiedUnknown.insert(sender);
                        }
                        redrawPrompt();
                        continue;
                    }

                    Session& s = sessions[sender];

                    switch (decideHandshake(s, h))
                    {
                        case HandshakeAction::REPLY:
                            if (!sendReply(clientSocket,id, sender, s, h.key.data()))
                            {
                                cerr << "Failed to reply to handshake." << endl;
                                wipeSession(s);
                                sessions.erase(sender);
                                redrawPrompt();
                                continue;
                            }
                            break;
                        case HandshakeAction::RESEND_OFFER:
                            if (!resendOffer(clientSocket, id, sender, s))
                            {
                                cerr << "Failed to resend offer." << endl;
                                wipeSession(s);
                                sessions.erase(sender);
                            }  
                            redrawPrompt();
                            continue;
                        case HandshakeAction::DERIVE:
                            if (!deriveSessionKeys(s, string(h.key.data(), h.key.data() + crypto_kx_PUBLICKEYBYTES)))
                            {
                                cerr << "Failed to derive session keys. Handshake rejected." << endl;
                                wipeSession(s);
                                sessions.erase(sender);
                                redrawPrompt();
                                continue;
                            }
                            s.state = SessionState::READY;
                            break;
                        case HandshakeAction::IGNORE:
                            redrawPrompt();
                            continue;
                    }

                    cout << "Verified secure connection with " << displayName(contacts, sender) << endl;

                    string fingerPrint = sessionFingerPrint(s);
                    cout << "Session fingerprint: " << fingerPrint << endl;

                    redrawPrompt();
                }
                continue;
            case MsgType::ERROR_MSG:
                {
                    lock_guard<mutex> lock(terminalMutex);
                    cout << "\r\033[K";
                    cerr << sanitizeForTerminal(body) << endl;
                    redrawPrompt();
                }
                continue;
            case MsgType::USER_NOT_FOUND:
                {
                    // server couldn't deliver to this user: they're not online
                    lock_guard<mutex> lock(terminalMutex);
                    cout << "\r\033[K";
                    PeerId missing{};
                    if (body.size() != missing.size())
                    {
                        cerr << "Malformed USER_NOT_FOUND received." << endl;
                        redrawPrompt();
                        continue;
                    }
                    memcpy(missing.data(), body.data(), missing.size());
                    cerr << displayName(contacts, missing) << " is not online." << endl;

                    // any session with them is stale
                    auto it = sessions.find(missing);
                    if (it != sessions.end())
                    {
                        wipeSession(it->second);
                        sessions.erase(it);
                    }
                    redrawPrompt();
                }
                continue;
            case MsgType::USER_LIST:
                {
                    lock_guard<mutex> lockTerm(terminalMutex);
                    lock_guard<mutex> lockUid(userIdsMutex);
                    bool more = false;
                    if (!parseUserList(body, userIds, more))
                    {
                        cerr << "Failed to parse list of online users." << endl;
                        redrawPrompt();
                        continue;
                    }
                    redrawPrompt();
                }
                continue;
            case MsgType::USER_ONLINE:
                // convert body into peer id and push back to vector
                {
                    lock_guard<mutex> lock(userIdsMutex);
                    PeerId id{};
                    if (body.size() != PeerId{}.size())
                    {
                        // print error here
                        continue;
                    }

                    memcpy(id.data(), body.data(), PeerId{}.size());
                    userIds.insert(id);
                }
                continue;
            case MsgType::USER_OFFLINE:
                {
                    lock_guard<mutex> lockTerm(terminalMutex);
                    lock_guard<mutex> lockUid(userIdsMutex);
                    PeerId id{};
                    if (body.size() != PeerId{}.size())
                    {
                        // cerr
                        continue;
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
                continue;
            default:
                {
                    lock_guard<mutex> lock(terminalMutex);
                    cout << "\r\033[K";
                    cerr << "INVALID MESSAGE TYPE" << endl;
                }
                exit(1);
        }
    }
}

void sendMsg(int clientSocket, const string& name, map<PeerId, Session>& sessions, const Identity& id, Contacts& contacts, const string& contactsPath)
{
    {
        lock_guard<mutex> lock(terminalMutex);
        redrawPrompt();
    }

    char ch;

    vector<PeerId> userIdVector;
    optional<PeerId> currentPeer;

    while (read(STDIN_FILENO, &ch, 1) == 1)
    {
        if (quitting) { break; }
        {
            lock_guard<mutex> lock(terminalMutex);

            // enter or ctrl+c
            if (ch == '\n' || ch == '\r' || ch == 3)
            {
                if (inputBuffer == "q()" || ch == 3)
                {
                    cout << "\r\033[2K";
                    cout << "Exiting program..." << endl;
                    quitting = true;
                    shutdown(clientSocket, SHUT_RDWR);
                    break;
                }

                // display list of user ids when prompted
                if (inputBuffer == "/users")
                {
                    userIdVector.clear();
                    lock_guard<mutex> lock(userIdsMutex);
                    cout << "\r\033[2K";
                    // all print user ids to terminal here
                    int n = 1;
                    for (const auto& uid : userIds)
                    { 
                        userIdVector.push_back(uid);
                        cout << n << ") " << displayName(contacts, uid) << endl;
                        n++;
                    }
                    inputBuffer.clear();
                    redrawPrompt();
                    continue;
                }
                
                vector<string> words = splitWords(inputBuffer);

                if (!words.empty() && words[0] == "/add")
                {
                    cout << "\r\033[K";

                    optional<size_t> index;
                    if (words.size() == 3)
                    {
                        index = parseListNumber(words[1], userIdVector.size());
                    }

                    if (words.size() != 3)
                    {
                        cerr << "Usage: /add <number from /users> <name>" << endl;
                    }
                    else if (!index)
                    {
                        cerr << "No such user. Type /users to see the list." << endl;
                    }
                    else
                    {
                        const PeerId selected = userIdVector[*index];
                        const string& newName = words[2];

                        auto existing = contacts.find(selected);
                        if (existing != contacts.end() && existing->second == newName)
                        {
                            cout << newName << " is already saved." << endl;
                        }
                        else
                        {
                            string error;
                            if (!addContact(contacts, selected, newName, error))
                            {
                                cerr << "Could not add contact: " << error << endl;
                            }
                            else if (!saveContacts(contactsPath, contacts))
                            {
                                contacts.erase(selected);          // keep memory in step with the file
                                cerr << "Could not save the contacts file." << endl;
                            }
                            else
                            {
                                cout << "Saved " << newName << " (" << idFingerPrint(selected.data()) << ")." << endl;
                                cout << "Only trust this if it matches what " << newName << " sees as 'Your fingerprint'." << endl;
                            }
                        }
                    }

                    inputBuffer.clear();
                    redrawPrompt();
                    continue;
                }

                if (!words.empty() && words[0] == "/remove")
                {
                    cout << "\r\033[K";

                    optional<PeerId> contactId;
                    if (words.size() == 2)
                    {
                        contactId = findByName(contacts, words[1]);
                    }

                    if (words.size() != 2)
                    {
                        cerr << "Usage: /remove <contact name>" << endl;
                    }
                    else if (contacts.empty())
                    {
                        cerr << "No contacts yet. Type /users, then /add n name." << endl;
                    }
                    else if (!contactId)
                    {
                        cerr << "No such contact. Type /contacts to see the list." << endl;
                    }
                    else
                    {
                        string contactName = words[1];
                        contacts.erase(*contactId);
        
                        if (!saveContacts(contactsPath, contacts))
                        {
                            contacts[*contactId] = contactName;         // keep memory in step with the file
                            cerr << "Could not save the contacts file." << endl;
                        }
                        else
                        {
                            cout << "Contact removed: " << contactName << " (" << idFingerPrint(contactId->data()) << ")" << endl;

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
                                promptTarget.clear();
                                cout << "Chat with " << contactName << " closed." << endl;
                            }
                        }
                        
                    }

                    inputBuffer.clear();
                    redrawPrompt();
                    continue;
                }

                if (!words.empty() && words[0] == "/contacts")
                {
                    cout << "\r\033[K";

                
                    if (words.size() != 1)
                    {
                        cerr << "Usage: /contacts" << endl;
                    }
                    else if (contacts.empty())
                    {
                        cout << "No contacts yet. Type /users, then /add n name." << endl;
                    }
                    else
                    {
                        lock_guard<mutex> lockUid(userIdsMutex);

                        for (const auto& [contactId, contactName] : contacts)
                        {
                            if (userIds.contains(contactId))
                            {
                                cout << "* " << contactName << " [" << idFingerPrint(contactId.data()) << "]" << endl;
                            }
                            else
                            {
                                cout << "  " << contactName << " [" << idFingerPrint(contactId.data()) << "]" << endl;
                            }
                        }
                    }

                    inputBuffer.clear();
                    redrawPrompt();
                    continue;
                }

                if (!words.empty() && words[0] == "/chat")
                {
                    cout << "\r\033[K";

                    optional<PeerId> contactId;
                    if (words.size() == 2)
                    {
                        contactId = findByName(contacts, words[1]);
                    }

                    if (words.size() != 2)
                    {
                        cerr << "Usage: /chat <contact name>" << endl;
                    }
                    else if (contacts.empty())
                    {
                        cerr << "No contacts yet. Type /users, then /add n name." << endl;
                    }
                    else if (!contactId)
                    {
                        cerr << "No such contact. Type /contacts to see the list." << endl;
                    }
                    else
                    {
                        PeerId selected = *contactId;
                        bool online;
                        {
                            lock_guard<mutex> lockUid(userIdsMutex);
                            online = userIds.contains(selected);
                        }
                        if (!online)
                        {
                            cout << "That user is no longer online." << endl;
                        }
                        else
                        {
                            cout << "Now chatting with " << displayName(contacts, selected) << endl;
                            currentPeer = selected;

                            const string peerName = displayName(contacts, selected);
                            promptTarget = peerName;
                            auto it = sessions.find(selected);

                            if (it != sessions.end() && it->second.state == SessionState::READY)
                            {
                                cout << "Already connected to " << peerName << "." << endl;
                            }
                            else
                            {
                                // NONE (or no session yet): start a handshake.
                                // OFFERED: send a fresh offer; safe at any time, a reply to the old one is ignored as stale.
                                const bool retrying = (it != sessions.end() && it->second.state == SessionState::OFFERED);
                                cout << (retrying ? "No reply yet, sending a new offer..." : "Establishing secure connection...") << endl;

                                if (!sendOffer(clientSocket, id, selected, sessions[selected]))
                                {
                                    sessions.erase(selected);
                                    cerr << "Failed to send handshake to " << peerName << "." << endl;
                                }
                            }
                        }
                    }

                    inputBuffer.clear();
                    redrawPrompt();
                    continue;                    
                }


                if (inputBuffer.empty())
                {
                    continue; 
                }

                if (!currentPeer)
                {
                    cout << "\r\033[K";
                    cerr << "No chat selected. Type /contacts, then /chat <name>." << endl;
                    redrawPrompt();
                    continue;
                }

                auto it = sessions.find(*currentPeer);
                if (it == sessions.end() || it->second.state != SessionState::READY)
                {
                    cout << "\r\033[K";
                    cerr << "Connection not secured yet. Wait for the fingerprint." << endl;
                    redrawPrompt();
                    continue;
                }

                cout << "\r\033[2K";

                string message = name + " : " + inputBuffer; 

                vector<unsigned char> encrypted{};
                if (!sealMessage(it->second, id.pk, currentPeer->data(), message, encrypted))
                {
                    cerr << "Failed to encrypt" << endl;
                    redrawPrompt();
                    continue;
                }
                
                vector<unsigned char> frameBody = buildBody(*currentPeer, encrypted);
                if (frameBody.size() + 1 > MAX_MESSAGE_SIZE)
                {
                    cerr << "Invalid Message Length" << endl;
                    redrawPrompt();
                    continue;
                }              

                MsgType msg = MsgType::MESSAGE;
                if (!sendFrame(clientSocket, msg, frameBody))
                {
                    cerr << "Failed to send frame" << endl;
                    redrawPrompt();
                    continue;
                }

                // print sent message
                cout << "\r\033[K";
                cout << "\033[92myou\033[0m : " << inputBuffer << endl;
                inputBuffer.clear();
                redrawPrompt();
                continue;
            }

            // backspace
            if (ch == 127 || ch == '\b')
            {
                if (!inputBuffer.empty())
                { 
                    inputBuffer.pop_back();
                }
            }
            // char
            else if (ch >= 32 && ch <= 126)
            {
                inputBuffer += ch;
            }

	        redrawPrompt();
        }
    }
}


int main(int argc, char* argv[])
{
    signal(SIGPIPE, SIG_IGN); // ignore SIGPIPE signal to prevent abrupt termination

    if (sodium_init() < 0)
    {
        cerr << "Failed to initialize libsodium." << endl;
        return 1;
    }

    string profile = "default";
    if (argc > 3)
    {
        profile = argv[3];
    }

    if (!isValidName(profile))
    {
        cerr << "Invalid profile name. Use 1-32 letters, digits, '-' or '_'." << endl;
        return 1;
    }

    string profileDir;
    if (!prepareProfileDir(profile, profileDir))
    {
        cerr << "Failed to create profile folder: profiles/" << profile << endl;
        return 1;
    }

    cout << "Profile: " << profile << endl;

    Identity id;
    if (!loadOrCreateIdentity(profileDir + "/identity.key", id))
    {
        cerr << "Failed to load identity." << endl;
        return 1;
    }

    cout << "Your fingerprint: " << idFingerPrint(id.pk) << endl;

    // Loading contacts
    Contacts contacts;

    const string contactsPath = profileDir + '/' + CONTACTS_FILE;
    vector<string> contactsWarning;

    if (!loadContacts(contactsPath, contacts, contactsWarning))
    {
        cerr << "Failed to read contacts file: " << contactsPath << endl;
        return 1;
    }

    for (const string& warning : contactsWarning)
    {
        cerr << "contacts: " << warning << endl;
    }
    cout << "Loaded " << contacts.size() << " contact(s)." << endl;

    // create client socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0)
    {
		perror("Failed to create client socket");
		return 1;
    }

    cout << "Client socket created" << endl;

    const char* serverIp = "127.0.0.1"; // default : this computer
    int portNum = 8080;                 // default : 8080
    if (argc > 1)
    {
        serverIp = argv[1];
    }

    if (argc > 2)
    {
        try
        {
            portNum = stoi(argv[2]);
        }
        catch (const exception& e)
        {
            cerr << "Invalid port: " << argv[2] << e.what() << endl;
            return 1;
        }
        if (portNum < 1 || portNum > 65535)
        {
            cerr << "Port must be between 1 and 65535" << endl;
            return 1;
        }
    }

    // define server address
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(portNum);

    if (inet_pton(AF_INET, serverIp, &serverAddr.sin_addr) <= 0)
    {
        cerr << "Invalid server address:" << serverIp << endl;
        return 1;
    }

    // connect to server
    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
    {
		cerr << "Failed to connect to server" << endl;
		return 1;
    }

    if (!setNoDelay(clientSocket))
    {
        cerr << "Warning: could not set TCP_NODELAY" << endl;
    }

    cout << "Connected to server" << endl;

    MsgType type;
    string body;

    if (!receiveFrame(clientSocket, type, body) || type != MsgType::CHALLENGE || body.size() != CHALLENGE_BYTES)
    {
        cerr << "Login failed: unexpected reply from server." << endl;
        return 1;
    }

    array<unsigned char, CHALLENGE_BYTES> challenge{};
    memcpy(challenge.data(), body.data(), challenge.size());
    
    // sign label and challenge
    unsigned char signature[crypto_sign_BYTES];
    if (!signLogin(id, challenge, signature))
    {
        cerr << "Login failed: Could not sign challenge." << endl;
        return 1;
    }

    vector<unsigned char> auth(id.pk, id.pk + crypto_sign_PUBLICKEYBYTES);
    auth.insert(auth.end(), signature, signature + crypto_sign_BYTES);

    if (!sendFrame(clientSocket, MsgType::AUTH, auth))
    {
        cerr << "Login failed: could not send AUTH." << endl;
        return 1;
    }

    // wait for AUTH_OK (or the server's error message)
    if (!receiveFrame(clientSocket, type, body))
    {
        cerr << "Login failed: server closed the connection." << endl;
        return 1;
    }
    if (type == MsgType::ERROR_MSG)
    {
        cerr << "Login failed: " << sanitizeForTerminal(body) << endl;
        return 1;
    }
    if (type != MsgType::AUTH_OK)
    {
        cerr << "Login failed: unexpected reply from server." << endl;
        return 1;
    }

    cout << "Logged in." << endl;

    cout << "Enter your chat name: ";
    string name;
    getline(cin, name);

    cout << endl;

    cout << "Type /users to see who's online..." << endl;

    // set terminal to raw mode
    tcgetattr(STDIN_FILENO, &origTerminal);
    atexit(restoreTerminal);
    termios modTerminal = origTerminal;
    modTerminal.c_lflag &= ~(ICANON | ECHO | ISIG);
    modTerminal.c_cc[VMIN] = 1;

    tcsetattr(STDIN_FILENO, TCSANOW, &modTerminal);

    map<PeerId, Session> sessions;
    ChatCore chatcore(id, sessions, contacts, userIds);

    // threads
    thread threadReceive(receiveMsg, clientSocket, ref(sessions), cref(id), ref(contacts));
    thread threadSend(sendMsg, clientSocket, name, ref(sessions), cref(id), ref(contacts), contactsPath);

    threadReceive.join();
    threadSend.join();

    sodium_memzero(id.sk, sizeof(id.sk));

    // restore terminal settings
    restoreTerminal();
    cout << "\nTerminal settings restored" << endl;

    // close client socket
    if (close(clientSocket) < 0)
    {
		perror("Failed to close client socket");
		return 1;
    }

    cout << "Client socket closed" << endl;
    
    return 0;
}



