#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <cerrno>
#include <cstring>

#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h>

#include <vector>
#include <thread>
#include <mutex>
#include <csignal>

#include <sodium.h>

#include <map>
#include <memory>
#include <set>
#include <atomic>

#include "net.hpp"
#include "crypto.hpp"

using namespace std;

struct Connection
{
    int sock;
    mutex sendMutex;

    explicit Connection(int s) : sock(s) {}
    ~Connection() { close(sock); }

    // one connection per socket
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    // ends connection NOW
    void shutdown() { ::shutdown(sock, SHUT_RDWR); }

    bool send(MsgType type, const vector<unsigned char>& body)
    {
        lock_guard<mutex> lock(sendMutex);
        return sendLocked(type, body);
    }

    bool sendLocked(MsgType type, const vector<unsigned char>& body)
    {
        if (!sendFrame(sock, type, body))
        {
            shutdown();
            return false;
        }
        return true;
    }
};

using ClientMap = map<PeerId, shared_ptr<Connection>>;   // logged-in user ID -> connection

// A send blocked this long fails, and the client is dropped (see Connection::send).
constexpr int SEND_TIMEOUT_MS = 2000;

// new connection must finish logging in (send a valid AUTH) within this time
constexpr int LOGIN_TIMEOUT_MS = 10000;

constexpr int MAX_CONNECTIONS = 1000;
atomic<int> activeConnections{0};

// sets how long a receive on `sock` may wait (0 = forever)
bool setReceiveTimeout(int sock, int ms)
{
    timeval t{ms / 1000, (ms % 1000) * 1000};
    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t)) == 0;
}

mutex clientsMutex;
mutex coutMutex;

// users whose disconnect is still being announced; can't log in again until that's done
set<PeerId> leaving;

vector<shared_ptr<Connection>> othersLocked(const ClientMap& clients, const PeerId& self)
{
    vector<shared_ptr<Connection>> others;
    others.reserve(clients.size());
    for (const auto& [id, conn] : clients)
    {
        if (id != self)
        {
            others.push_back(conn);
        }
    }
    return others;
}

// send the same frame to each connection
void broadcast(const vector<shared_ptr<Connection>>& to, MsgType type,
               const vector<unsigned char>& body)
{
    for (const auto& conn : to)
    {
        conn->send(type, body);
    }
}

void rejectClient(Connection& conn, const string& reason)
{
    vector<unsigned char> msg(reason.begin(), reason.end());
    conn.send(MsgType::ERROR_MSG, msg);
}

// Every logged-in ID except `self`, for the USER_LIST. Call with clientsMutex held.
vector<PeerId> userIdsLocked(const PeerId& self, const ClientMap& clients)
{
    vector<PeerId> ids;
    ids.reserve(clients.size());
    for (const auto& [id, conn] : clients)
    {
        if (id != self)
        {
            ids.push_back(id);
        }
    }
    return ids;
}


void clientHandler(int clientSocket, ClientMap& clients)
{
    // main() counted this connection; count it out however this function ends
    struct Slot { ~Slot() { --activeConnections; } } slot;

    auto conn = make_shared<Connection>(clientSocket);

    // until login is done, every receive gives up after LOGIN_TIMEOUT_MS
    setReceiveTimeout(clientSocket, LOGIN_TIMEOUT_MS);

    // send challenge 
    array<unsigned char, CHALLENGE_BYTES> challenge{};
    randombytes_buf(challenge.data(), challenge.size());

    vector<unsigned char> challengePayload(challenge.begin(), challenge.end());
    if (!conn->send(MsgType::CHALLENGE, challengePayload))
    {
        lock_guard<mutex> lock(coutMutex);
        cerr << "Failed to send challenge to client" << endl;
        return;   // conn destroyed here; closes the socket
    }

    // receive auth and verify against login_label + challenge
    constexpr size_t AUTH_BODY_BYTES = crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES;  // 32+ 64 bytes

    MsgType type;
    string authBody;
    if(!receiveFrame(clientSocket, type, authBody) || type != MsgType::AUTH || authBody.size() != AUTH_BODY_BYTES)
    {
        {
            lock_guard<mutex> lock(coutMutex);
            cout << "\r\033[K";
            cerr << "Client disconnected or Error receiving frame." << endl;
        }
        // reject client 
        rejectClient(*conn, "Error receiving Auth.");
        return;
    }

    // split into pk and sig
    PeerId clientId{};
    unsigned char signature[crypto_sign_BYTES];
    memcpy(clientId.data(), authBody.data(), clientId.size());
    memcpy(signature, authBody.data() + clientId.size(), crypto_sign_BYTES);

    // rebuild what client should've sent
    vector<unsigned char> message = buildLoginMessage(challenge);

    // verify
    if (crypto_sign_verify_detached(signature, message.data(), message.size(), clientId.data()) != 0)
    {
        rejectClient(*conn, "Error on verifying signature.");
        return;
    }

    // hold our own send lock from before anyone can find us in the map until our login frames are out
    unique_lock<mutex> loginFrames(conn->sendMutex);

    bool duplicate = false;
    vector<PeerId> userList;
    vector<shared_ptr<Connection>> others;   // who to tell that we're online
    {
        lock_guard<mutex> lock(clientsMutex);
        if (clients.count(clientId) > 0 || leaving.count(clientId) > 0)
        {
            duplicate = true;
        }
        else
        {
            userList = userIdsLocked(clientId, clients);
            others = othersLocked(clients, clientId);
            clients[clientId] = conn;
        }
    }

    if (duplicate)
    {
        loginFrames.unlock();
        rejectClient(*conn, "Already logged in.");
        return;
    }

    // AUTH_OK, then the user list, split over as many USER_LIST frames as it needs
    bool sent = conn->sendLocked(MsgType::AUTH_OK, {});
    for (const auto& body : buildUserListBodies(userList))
    {
        sent = sent && conn->sendLocked(MsgType::USER_LIST, body);
    }
    if (!sent)
    {
        // noone was told we're online yet, so just take us out of the map again
        lock_guard<mutex> lock(clientsMutex);
        clients.erase(clientId);
        return;
    }
    loginFrames.unlock();

    // logged in: a chat client may stay quiet for as long as it likes
    setReceiveTimeout(clientSocket, 0);

    vector<unsigned char> idPayload(clientId.begin(), clientId.end());
    broadcast(others, MsgType::USER_ONLINE, idPayload);

    {
		lock_guard<mutex> lock(coutMutex);
		cout << "Logged in: " << idFingerPrint(clientId.data()) << endl;
	}

    while (true)
    {
		MsgType type;
        string payload{};
        if(!receiveFrame(clientSocket, type, payload))
        {
            {
                lock_guard<mutex> lock(coutMutex);
                cout << "\r\033[K";
                cerr << "Client disconnected or Error receiving frame." << endl;
            }
            break;
        }

        if ((type != MsgType::MESSAGE) && (type !=  MsgType::HANDSHAKE))
        {
            break;
        }

        // parse body, get the recipient and payload (in this case encrypted) sub the 
        vector<unsigned char> encrypted;
        PeerId recipientId;
        if (!parseBody(payload, recipientId, encrypted))
        {
            break;
        }
        
        vector<unsigned char> sendBody = buildBody(clientId, encrypted);

        // copy recipient's shared_ptr under the lock, then send without it; the copy keeps the Connection alive even if the recipient leaves
        shared_ptr<Connection> recipient;
        {
            lock_guard<mutex> lock(clientsMutex);
            auto it = clients.find(recipientId);
            if (it != clients.end())
            {   
                recipient = it->second;
            }
        }

        if (!recipient)
        {
            vector<unsigned char> missingId(recipientId.begin(), recipientId.end());
            if (!conn->send(MsgType::USER_NOT_FOUND, missingId))
            {
                break;
            }
            continue;
        }

        if (!recipient->send(type, sendBody))
        {
            cerr << "Failed to send message to client" << endl;
        }
    }

    // cut connection now so client sees it closed even if another thread still holds shared_ptr to it
    conn->shutdown();

    // leave the map under the lock; announce it after unlocking.
    vector<shared_ptr<Connection>> remaining;
    {
        lock_guard<mutex> lock(clientsMutex);
        clients.erase(clientId);
        leaving.insert(clientId);
        remaining = othersLocked(clients, clientId);
    }
    broadcast(remaining, MsgType::USER_OFFLINE, idPayload);
    {
        lock_guard<mutex> lock(clientsMutex);
        leaving.erase(clientId);   // now the same user may log in again
    }

    {
        lock_guard<mutex> lock(coutMutex);
        cout << "Client disconnected" << endl;
    }
}

int main(int argc, char* argv[])
{
	signal(SIGPIPE, SIG_IGN); // ignore SIGPIPE signal to prevent abrupt termination

    if (sodium_init() < 0)
    {
        cerr << "Failed to initialize libsodium" << endl;
        return 1;
    }
    // create server socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket < 0)
    {
		perror("Failed to create server socket");
		return 1;
    }

    cout << "Server socket created!" << endl;

    int portNum = 8080;                 // default : 8080
    if (argc > 1)
    {
        try
        {
            portNum = stoi(argv[1]);
        }
        catch (const exception& e)
        {
            cerr << "Invalid port: " << argv[1] << e.what() << endl;
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
    serverAddr.sin_addr.s_addr = INADDR_ANY; 	// works only on server, where it means "listen on all my address"
	int yes = 1;
	if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
	{
		perror("Failed to set socket option");
		return 1;
	}
    
    // bind socket to address
    if (::bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
    {
		perror("Failed to bind socket to server address");
		return 1;
    }

    cout << "Socket bound to address" << endl;

    // listen for incoming connections
    if (listen(serverSocket, SOMAXCONN) < 0)
    {
		perror("Failed to listen for incoming connections");
		return 1;
    }

    ClientMap clients;

    while (true)
    {	
		int clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket < 0)
        {
            perror("Accept");
            continue;
        }
        if (!setNoDelay(clientSocket))
        {
            perror("setsockopt(TCP_NODELAY)");
        }

        // client that stops reading can't hold up a thread forever.
        timeval sendTimeout{SEND_TIMEOUT_MS / 1000, (SEND_TIMEOUT_MS % 1000) * 1000};
        if (setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, &sendTimeout, sizeof(sendTimeout)) < 0)
        {
            perror("setsockopt(SO_SNDTIMEO)");
        }

        if (activeConnections >= MAX_CONNECTIONS)
        {
            // turned away here, before a thread is started for it
            const string reason = "Server full.";
            sendFrame(clientSocket, MsgType::ERROR_MSG, vector<unsigned char>(reason.begin(), reason.end()));
            close(clientSocket);
            continue;
        }
        ++activeConnections;   // counted out by the handler's Slot

		thread cli(clientHandler, clientSocket, ref(clients));
		cli.detach();
    }

    // close socket
    close(serverSocket);

    cout << "Server socket closed" << endl;

    return 0;
}

