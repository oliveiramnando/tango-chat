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
        return sendFrame(sock, type, body);
    }
};

using ClientMap = map<PeerId, shared_ptr<Connection>>;   // logged-in user ID -> connection

mutex clientsMutex;
mutex coutMutex;

void rejectClient(Connection& conn, const string& reason)
{
    vector<unsigned char> msg(reason.begin(), reason.end());
    conn.send(MsgType::ERROR_MSG, msg);
}

bool sendUserList(Connection& conn, const PeerId& selfId, const ClientMap& inputMap)
{
    vector<unsigned char> payload;
    payload.reserve(inputMap.size() * 32);
    for (auto& cli : inputMap) 
    {   
        if (cli.first == selfId) { continue; }
        payload.insert(payload.end(), cli.first.begin(), cli.first.end());
    }

    return conn.send(MsgType::USER_LIST, payload);
}


void clientHandler(int clientSocket, ClientMap& clients)
{
    auto conn = make_shared<Connection>(clientSocket);

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

    {
        lock_guard<mutex> lock(clientsMutex);

        if (clients.count(clientId) > 0)
        {
            rejectClient(*conn, "Already logged in.");
            return;
        }

        if (!conn->send(MsgType::AUTH_OK, {}))
        {
            return;
        }

        clients[clientId] = conn;
        // send user list of all clients
        if (!sendUserList(*conn, clientId, clients))
        {   
            clients.erase(clientId);
            return;
        }

        // send every other user that the curr user is online 
        vector<unsigned char> idPayload(clientId.begin(), clientId.end());
        for (const auto & [otherId, other] : clients)
	    {
            if (otherId == clientId) { continue; }
	    	if (!other->send(MsgType::USER_ONLINE, idPayload))
	    	{
                lock_guard<mutex> lock(coutMutex);
	    		cerr << "Failed to send message to client" << endl;
	    	}
	    }
    }

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
            if (!conn->send(MsgType::ERROR_MSG, missingId))
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

	{
		lock_guard<mutex> lock(clientsMutex);
		clients.erase(clientId);

        // send USER OFFLINE to remaining clients
        vector<unsigned char> idPayload(clientId.begin(), clientId.end());
        for (const auto & [otherId, other] : clients)
	    {
	    	if (!other->send(MsgType::USER_OFFLINE, idPayload))
	    	{
                lock_guard<mutex> lock(coutMutex);
	    		cerr << "Failed to send message to client" << endl;
	    	}
	    }
	}

    // cut connection now so client sees it closed even if another thread still holds shared_ptr to it
    conn->shutdown();
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

		thread cli(clientHandler, clientSocket, ref(clients));
		cli.detach();
    }

    // close socket
    close(serverSocket);

    cout << "Server socket closed" << endl;

    return 0;
}

