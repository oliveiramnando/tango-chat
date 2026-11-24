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

bool applyEffects(int clientSocket, const Effects& e)
{
    // caller must hold terminal mutex
    for (const auto& frame : e.frames)
    {
        sendFrame(clientSocket, frame.type, frame.body);    // failed send == connections gone; receipe loop will notice
    }

    cout << "\r\033[K";

    for (const auto& event : e.events)
    {
        showEvent(event);
    }

    redrawPrompt();
    return !e.fatal;
}


void receiveMsg(int clientSocket, ChatCore& core)
{
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
        bool keepGoing;
        {
            lock_guard<mutex> lock(terminalMutex);
            keepGoing = applyEffects(clientSocket, core.onFrame(type, body));
        }
        if (!keepGoing) 
        {
            exit(1);
        }
    }
}

void sendMsg(int clientSocket, const string& name, map<PeerId, Session>& sessions, const Identity& id, Contacts& contacts, const string& contactsPath, ChatCore& core)
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

                                applyEffects(clientSocket, core.makeOfferTo(selected));
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
    ChatCore core(id, sessions, contacts, userIds);

    // threads
    thread threadReceive(receiveMsg, clientSocket, ref(core));
    thread threadSend(sendMsg, clientSocket, name, ref(sessions), cref(id), ref(contacts), contactsPath, ref(core));

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



