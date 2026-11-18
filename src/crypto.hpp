#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <sodium.h>

#include "net.hpp"

constexpr std::size_t OFFER_PAYLOAD_SIZE = 1 + crypto_kx_PUBLICKEYBYTES + crypto_sign_BYTES;  // 97
constexpr std::size_t REPLY_PAYLOAD_SIZE = 1 + crypto_kx_PUBLICKEYBYTES*2 + crypto_sign_BYTES;  // 129 

struct Identity
{
    unsigned char pk[crypto_sign_PUBLICKEYBYTES]{}; 
    unsigned char sk[crypto_sign_SECRETKEYBYTES]{};
};

enum class SessionState {
    NONE,
    READY,
    OFFERED,
};

struct Session
{
    unsigned char pk[crypto_kx_PUBLICKEYBYTES]{}; 
    unsigned char sk[crypto_kx_SECRETKEYBYTES]{};
    unsigned char rx[crypto_kx_SESSIONKEYBYTES]{};
    unsigned char tx[crypto_kx_SESSIONKEYBYTES]{};

    unsigned char peerPk[crypto_kx_PUBLICKEYBYTES]{};

    bool hasKeyPair = false;

    bool isInitiator = false;

    SessionState state = SessionState::NONE;
};

bool loadOrCreateIdentity(const std::string& path, Identity& id);

std::vector<unsigned char> buildHandshakeMessage(std::string_view label, const unsigned char* senderPk, const unsigned char* recipientPk, const unsigned char* ephPk, const unsigned char* answeredPk = nullptr);
bool signOffer(const Identity& me, const unsigned char* recipientPk, const unsigned char* offerPk, unsigned char sig[crypto_sign_BYTES]);
bool verifyOffer(const unsigned char* senderPk, const unsigned char* recipientPk, const unsigned char* offerPk, const unsigned char* sig);

bool signReply(const Identity& me, const unsigned char* recipientPk, const unsigned char* replyPk, const unsigned char* answeredPk, unsigned char sig[crypto_sign_BYTES]);
bool verifyReply(const unsigned char* senderPk, const unsigned char* recipientPk, const unsigned char* replyPk, const unsigned char* answeredPk, const unsigned char* sig);


bool signLogin(const Identity& id, const std::array<unsigned char, CHALLENGE_BYTES>& challenge, unsigned char signature[crypto_sign_BYTES]);

std::string idFingerPrint(const unsigned char* pk);

void makeKeyPair(Session& s);
bool deriveSessionKeys(Session& s, const std::string& peerPk);

void wipeSession(Session& s);

std::string sessionFingerPrint(const Session& s);

bool encrypt(const std::string& message, std::vector<unsigned char>& encrypted, const unsigned char* key);
bool decrypt(std::vector<unsigned char>& decryptedMessage, const std::string& encryptedMessage, const unsigned char* key);

#endif
