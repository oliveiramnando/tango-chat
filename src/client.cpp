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
        case UiEventKind::INFO:
            cout << event.text << endl;
            break;
        case UiEventKind::SENT:
            cout << "\033[92myou\033[0m : " << event.text << endl;
            break;
        case UiEventKind::CHAT_CHANGED:
            promptTarget = event.name;
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

void sendMsg(int clientSocket, ChatCore& core)
{
    {
        lock_guard<mutex> lock(terminalMutex);
        redrawPrompt();
    }

    char ch;

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

                string line(inputBuffer.begin(), inputBuffer.end());
                inputBuffer.clear();
                applyEffects(clientSocket, core.onInput(line));

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
    ChatCore core(id, sessions, contacts, userIds, name, contactsPath);

    // threads
    thread threadReceive(receiveMsg, clientSocket, ref(core));
    thread threadSend(sendMsg, clientSocket, ref(core));

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
