#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <sodium.h>

#include "net.hpp"

constexpr std::size_t OFFER_PAYLOAD_SIZE = 1 + crypto_kx_PUBLICKEYBYTES + crypto_sign_BYTES;  // 97
constexpr std::size_t REPLY_PAYLOAD_SIZE = 1 + crypto_kx_PUBLICKEYBYTES*2 + crypto_sign_BYTES;  // 129 

// message payload: [8-byte counter][24-byte nonce][ciphertext][16-byte tag]
// ad: "tcpchat-msg-v1" || sender ID || recipient ID || counter
constexpr std::size_t MESSAGE_COUNTER_BYTES = 8;
constexpr std::size_t MESSAGE_OVERHEAD = MESSAGE_COUNTER_BYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES;  // 48

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

    // message counters; reset whenever new session keys are derived
    uint64_t txCounter = 0;   // number of the next message we send
    uint64_t rxCounter = 0;   // lowest number we still accept from the peer
};

enum class OpenResult {
    OK,         // genuine and new
    INVALID,    // malformed, or failed authentication
    REPLAYED,   // genuine, but already seen or out of order
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

// ad is authenticated but not encrypted
bool encrypt(const std::string& message, std::vector<unsigned char>& encrypted, const unsigned char* key, const unsigned char* ad = nullptr, std::size_t adLen = 0);
bool decrypt(std::vector<unsigned char>& decryptedMessage, const std::string& encryptedMessage, const unsigned char* key, const unsigned char* ad = nullptr, std::size_t adLen = 0);

std::vector<unsigned char> buildMessageAd(const unsigned char* senderPk, const unsigned char* recipientPk, uint64_t counter);

// encrypts as message number s.txCounter, then advances it
bool sealMessage(Session& s, const unsigned char* myPk, const unsigned char* peerPk, const std::string& plain, std::vector<unsigned char>& payload);

// authenticates first, then checks the number; on OK, skipped = how many earlier messages never arrived
OpenResult openMessage(Session& s, const unsigned char* peerPk, const unsigned char* myPk, const std::string& payload, std::string& plain, uint64_t& skipped);

#endif
