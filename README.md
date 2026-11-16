# TCP Chat
![CI](https://github.com/oliveiramnando/tcp-chat/actions/workflows/ci.yml/badge.svg)

A terminal-based, end-to-end encrypted TCP chat application written in **C++20**. Clients log in to a multithreaded relay server with a long-term **Ed25519** identity key, save the people they trust as contacts, and open private one-to-one conversations with them. Each conversation uses its own ephemeral **X25519** key exchange, signed with both users' identity keys, and **XChaCha20-Poly1305** authenticated encryption via [libsodium](https://doc.libsodium.org/).

The server authenticates users and routes frames, but it never holds conversation keys and cannot read chat content. Because every handshake is signed and conversations are only possible with saved contacts, the server also cannot swap in its own keys or pass off another identity as one of your contacts.

> **Project status:** Work in progress, built for learning systems programming and applied cryptography. It has not been audited and is **not suitable for protecting sensitive communication**. See [Security Considerations](#security-considerations).

## Features

- **Persistent identity profiles:** Each client runs under a named profile. On first use it creates an Ed25519 identity key pair in `profiles/<name>/identity.key` with owner-only permissions, and reuses it afterwards. A user's ID is their 32-byte public key, shown as a short fingerprint.
- **Challenge-response login:** The server sends a random 32-byte challenge, and the client proves it owns its identity by signing it. No passwords are involved, and duplicate logins with the same identity are rejected.
- **Contacts:** After comparing fingerprints with someone out of band, you save their ID under a name with `/add`. Contacts are stored per profile and shown by name everywhere: in `/users`, in connection messages and on every incoming message.
- **Contacts-only conversations:** `/chat` only accepts saved contacts, and handshakes from anyone else are ignored, with a one-line notice. Both people must add each other before they can talk, which makes the fingerprint check a required step.
- **Trustworthy sender labels:** Incoming messages are labeled with the name *you* saved for the sender's ID, not a name the sender chose.
- **Live presence:** The server sends the list of online users at login, then notifies clients as users come online or go offline.
- **Signed handshakes:** Each side signs its ephemeral public key with its identity key, bound to both users' IDs. The receiver verifies the signature before touching any session, so forged, altered or redirected handshakes are rejected and cannot disturb an existing conversation.
- **Handshake retry:** If a handshake gets no reply (for example because the peer had not added you yet), running `/chat` again after 5 seconds starts a fresh one.
- **End-to-end encryption:** XChaCha20-Poly1305 authenticated encryption with a fresh random 24-byte nonce for every message.
- **Ephemeral key exchange per conversation:** A new key pair for every session, with directional `rx`/`tx` keys derived using libsodium's `crypto_kx` API. Ephemeral secret keys are wiped as soon as session keys are derived, and session keys are wiped when the peer goes offline or is removed from your contacts.
- **Session fingerprints:** After each handshake, both clients print a hash of the two ephemeral public keys, which can be compared as an extra check.
- **Addressed, relay-only routing:** The server forwards only `HANDSHAKE` and `MESSAGE` frames, and only to the addressed recipient. It stamps every relayed frame with the authenticated sender's ID, so clients cannot impersonate each other. A client that sends any other frame type is disconnected.
- **Input validation:** Frame lengths, message types, IDs, public-key sizes, signatures, ciphertext sizes, profile and contact names, command arguments and contacts-file lines are checked before use. Malformed or unauthenticated data is rejected without crashing.
- **Tests and CI:** [doctest](https://github.com/doctest/doctest) unit tests for framing, cryptography, contacts and input parsing, plus integration tests that start the real server and talk to it over TCP. All tests run with AddressSanitizer and UndefinedBehaviorSanitizer, on Ubuntu and macOS, on every push through GitHub Actions.
- **Terminal chat interface:** Colored messages, live line editing, prompt redraw when messages arrive, and terminal settings restored on every exit path.
- **Configurable host, port and profile:** Set from the command line, defaulting to `127.0.0.1:8080` and the `default` profile.

## Tech Stack

| Component | Technology |
| --- | --- |
| Language | C++20 |
| Transport | POSIX TCP sockets |
| Concurrency | `std::thread`, `std::mutex`, `std::atomic` |
| Cryptography | libsodium (Ed25519 `crypto_sign`, X25519 `crypto_kx`, XChaCha20-Poly1305, BLAKE2b via `crypto_generichash`) |
| Terminal | `termios`, ANSI escape sequences |
| Testing | doctest, AddressSanitizer, UndefinedBehaviorSanitizer |
| CI | GitHub Actions (Ubuntu with `g++`, macOS with `clang`) |
| Build | GNU Make, `g++` |

## Getting Started

### Prerequisites

- **Linux or macOS** (uses POSIX sockets and terminal APIs; on Windows, use WSL)
- A C++20-compatible `g++` and `make`
- **libsodium** and its development headers

On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install build-essential libsodium-dev
```

On macOS with Homebrew:

```bash
brew install libsodium
```

### Build

```bash
git clone https://github.com/oliveiramnando/tcp-chat.git
cd tcp-chat
make
```

This produces two executables: `server` and `client`. Both link against libsodium: the client for all of its cryptography, and the server only to verify login signatures.

If the compiler or linker cannot find a Homebrew-installed libsodium on macOS:

```bash
make CXXFLAGS="-std=c++20 -Wall -Wextra -g -Isrc -I$(brew --prefix libsodium)/include" \
     LDLIBS="-L$(brew --prefix libsodium)/lib -lsodium"
```

To remove the binaries:

```bash
make clean
```

### Test

```bash
make test
```

This builds the server, then builds `run_tests` from every `tests/test_*.cpp` file with AddressSanitizer and UndefinedBehaviorSanitizer enabled, and runs it:

- **Unit tests** cover framing, handshake signing and verification, key derivation, encryption, the contacts file, and name and command parsing.
- **Integration tests** start `./server` on a free port and connect headless clients to it. They check login, presence, signed handshakes, private message delivery, rejected logins, offline recipients, and that malformed frames close only the offending connection while the server keeps running. The server's output during these tests is written to `server_test.log`.

The sanitizers fail the run at the first out-of-bounds memory access or undefined behavior, even if every check would otherwise pass.

### Run

```text
./server [port]
./client [server-ip] [port] [profile]
```

| Program | Argument | Default |
| --- | --- | --- |
| `server` | `port` | `8080` |
| `client` | `server-ip` | `127.0.0.1` |
| `client` | `port` | `8080` |
| `client` | `profile` | `default` |

A profile name may contain 1–32 letters, digits, `-` or `_`. Each profile keeps its own identity and contacts in `profiles/<name>/`, so several users can run from the same folder.

**On one computer**, start the server, then a client with a different profile in each of two other terminals:

```bash
./server
./client 127.0.0.1 8080 alice
./client 127.0.0.1 8080 bob
```

**Across computers**, pass the server machine's address:

```bash
./server 9000                        # on the server machine
./client 192.168.1.20 9000 alice     # on each client machine
```

Then, the first time you talk to someone:

1. On startup, the client prints **`Your fingerprint:`**. This is your identity and stays the same as long as you keep your profile.
2. After **`Logged in.`**, enter a chat name.
3. Type **`/users`** to see a numbered list of who is online, with their fingerprints.
4. **Compare fingerprints** with the person you want to talk to, in person, by phone or through another trusted channel: their entry in your `/users` list must match the **`Your fingerprint:`** line on their screen.
5. Save them with **`/add n name`**, where `n` is their number in the list. They do the same for you.
6. Type **`/chat name`** to start the conversation. The signed key exchange runs automatically; wait for **`Verified secure connection with name`**.
7. Type a message and press Enter to send it to the selected contact. Messages from your other contacts appear as they arrive, labeled with the names you saved.

From then on, just use `/chat name`. Your contacts are remembered between runs.

If someone who has not added you tries to talk to you, you see a notice with their fingerprint instead of a conversation. If you started a chat before the other person added you, run `/chat name` again once they have, and the client sends a fresh handshake.

| Command | Action |
| --- | --- |
| `/users` | List online users, by contact name or fingerprint |
| `/add n name` | Save user `n` from the last `/users` list as a contact |
| `/contacts` | List saved contacts with their fingerprints; `*` marks those online |
| `/chat name` | Start or switch to a conversation with a saved contact |
| `/remove name` | Delete a contact and end any conversation with them |
| `q()` or **Ctrl+C** | Leave the chat |

> Keep the `profiles/` folder private and out of version control. Anyone with a profile's `identity.key` can log in as that user. Deleting a profile's folder creates a new identity the next time it is used, and your contacts will need to add you again.

**Networking notes:**

- The server listens on **all interfaces**, so other machines can reach it, provided the firewall allows the port.
- When the server runs inside **WSL**, other machines can't reach it by default. Enable WSL's mirrored networking mode, or run the server on another machine.
- On **macOS**, only `127.0.0.1` is a working loopback address by default. Other `127.x.x.x` addresses that work on Linux will fail there.

## How It Works

```text
Client A                    Relay Server                    Client B
   |                             |                              |
   |<--------- CHALLENGE --------|-------- CHALLENGE ---------->|
   |--- AUTH (id pk, signature)->|<-(id pk, signature) AUTH ----|
   |<---------- AUTH_OK ---------|---------- AUTH_OK ---------->|
   |<--- USER_LIST / USER_ONLINE-|-- USER_LIST / USER_ONLINE -->|
   |                             |                              |
   |  (both: compare fingerprints out of band, then /add)       |
   |                             |                              |
   |  /chat B                    |                              |
   |-HANDSHAKE [B][eph A][sig A]>|-HANDSHAKE [A][eph A][sig A]->|
   |                             |      verify sig, A is a contact
   |<HANDSHAKE [B][eph B][sig B]-|<HANDSHAKE [A][eph B][sig B]--|
   |  verify sig, B is a contact |                              |
   |                             |                              |
   |  derive rx/tx, wipe secret  |  derive rx/tx, wipe secret   |
   |                             |                              |
   |--- MESSAGE [B][ciphertext]->|--- MESSAGE [A][ciphertext]-->|
```

### Login

1. When a client connects, the server sends a `CHALLENGE` of 32 random bytes.
2. The client signs `"tcpchat-login-v1" || challenge` with its Ed25519 identity key and replies with `AUTH`: its 32-byte public key followed by the 64-byte signature. The label keeps a login signature from being reusable in any other context.
3. The server verifies the signature. If it is valid and that identity is not already online, the server sends `AUTH_OK`, registers the client, sends it a `USER_LIST`, and sends `USER_ONLINE` to everyone else. Otherwise it sends `ERROR_MSG` and closes the connection.
4. When a client disconnects, the server removes it and sends `USER_OFFLINE` to everyone else.

### Contacts

Contacts are saved in `profiles/<name>/contacts`, a plain-text file with one contact per line:

```text
3f9a...c41e bob
a07d...92b0 carol
```

Each line is the contact's full 64-character hex ID, a space, and the name. Names follow the same rules as profile names, and no ID or name may appear twice. Blank lines and lines starting with `#` are ignored. When the file is loaded, a bad line is skipped with a warning naming its line number, and the rest of the file is still used.

The file is rewritten in full on every `/add` and `/remove`. The client writes `contacts.tmp` with owner-only permissions, then renames it over `contacts`, so an interrupted save leaves the previous file intact rather than a half-written one. If saving fails, the change is undone in memory too, so the running client and the file never disagree.

### Conversations

1. The client keeps a separate session for each peer, indexed by the peer's ID.
2. `crypto_kx` requires the two sides to take different roles. Each client decides without asking the server: the side whose identity public key compares lower (byte by byte) is the **initiator**, and the other is the **responder**. Both sides always reach the same answer.
3. `/chat name` looks the contact up and checks they are online. It then generates a fresh ephemeral key pair for that peer and signs it with the identity key over:

   ```text
   "tcpchat-handshake-v1" || sender ID || recipient ID || ephemeral public key
   ```

   The client sends the ephemeral public key and the 64-byte signature in a `HANDSHAKE` addressed to the peer. The signed message itself is never sent; the receiver rebuilds it.
4. On receiving a `HANDSHAKE`, the client checks that the payload is exactly 96 bytes, then rebuilds the signed message from the sender's ID (stamped by the server), its own ID and the received key, and verifies the signature against the sender's ID. If verification fails, the frame is dropped **before any session is looked up or changed**. Including both IDs means a handshake meant for one user cannot be redirected to another, and the label keeps login and handshake signatures from being confused.
5. If the signature is valid but the sender is **not a saved contact**, the client prints a notice with their fingerprint and ignores the handshake: no session is created and no reply is sent.
6. If the sender is a contact and the client has not started a handshake with them, it creates a session and replies with its own signed key. If it already has a completed session, it treats the frame as a re-key and replies with a new key pair.
7. Each client derives a **receive (`rx`)** and **transmit (`tx`)** key and wipes its ephemeral secret key. One side's `tx` equals the other side's `rx`. Both print the peer's name and a session fingerprint (a BLAKE2b hash of both ephemeral keys, in initiator-then-responder order).
8. If a handshake is still unanswered when `/chat` is run again, the client waits until 5 seconds have passed since it was sent, then replaces it with a fresh one. The delay keeps a reply that is already on its way from being thrown away.
9. Messages (`name : message`) are encrypted with that peer's `tx` and a new random nonce, sent addressed to the peer, and decrypted by the recipient with its `rx` for the sender. The recipient displays the name it saved for the sender's ID and ignores the name inside the message. Messages from peers without a completed session, or that fail authentication, are rejected.
10. When a peer goes offline, or is removed from your contacts, the client wipes and removes that peer's session.

### TCP Frame Format

Each frame is encoded as:

```text
+----------------------+-------------------+-------------------------+
| Length (4 bytes)     | Type (1 byte)     | Body (variable length)  |
+----------------------+-------------------+-------------------------+
```

- **Length:** Unsigned 32-bit integer in network byte order, counting the type byte and body (not the length prefix itself). Frames shorter than 1 byte or longer than the maximum are rejected and the connection is closed.
- **Type:** One of the values below.
- **Limit:** The maximum frame length is **8,192 bytes**, including the type byte. The 32-byte peer ID and 40 bytes of encryption overhead leave room for about 8,100 bytes of plaintext per message, including the sender's chat name.

Relayed frames carry an **addressed body**: `[32-byte peer ID][payload]`. From client to server, the ID is the **recipient**; the server replaces it with the authenticated **sender's** ID before forwarding. The server never inspects the payload.

| Type | Value | Sent by | Body |
| --- | --- | --- | --- |
| `MESSAGE` | 1 | client (relayed) | `[peer ID][24-byte nonce][ciphertext][16-byte tag]` |
| `HANDSHAKE` | 2 | client (relayed) | `[peer ID][32-byte X25519 ephemeral public key][64-byte Ed25519 signature]` |
| — | 3, 4 | — | Reserved (formerly `PEER_JOINED`/`PEER_LEFT`, no longer used) |
| `ERROR_MSG` | 5 | server only | Error text, or the 32-byte ID of a recipient who is not online |
| `CHALLENGE` | 6 | server only | 32 random bytes |
| `AUTH` | 7 | client only | `[32-byte Ed25519 public key][64-byte signature]` |
| `AUTH_OK` | 8 | server only | Empty |
| `USER_LIST` | 9 | server only | Concatenated 32-byte IDs of the other online users |
| `USER_ONLINE` | 10 | server only | 32-byte ID |
| `USER_OFFLINE` | 11 | server only | 32-byte ID |

The `readNBytes()` and `sendAll()` helpers handle reads and writes that transfer fewer bytes than requested, since TCP does not preserve message boundaries. `sendFrame()`, `receiveFrame()`, `buildBody()` and `parseBody()` build and parse frames, and are shared by the client and server so both always use the same format.

### Encryption

`crypto.cpp` uses **XChaCha20-Poly1305** with a random **24-byte nonce** per message. The encrypted payload is structured as:

```text
[24-byte nonce][ciphertext][16-byte authentication tag]
```

The tag lets the recipient reject any message that was altered, truncated or encrypted with a different key. Because each direction of each conversation has its own key, a message cannot be reflected back to its sender or replayed into a different conversation. The only key stored on disk is each profile's long-term identity key; all conversation keys exist only in memory for the length of a session.

## Project Structure

```text
tcp-chat/
├── .github/
│   └── workflows/
│       └── ci.yml          # Build and test on Ubuntu and macOS on every push
├── src/
│   ├── client.cpp          # Profiles, login, commands, per-peer sessions, terminal UI, send/receive threads
│   ├── server.cpp          # Login verification, user registry, presence updates, addressed routing
│   ├── crypto.cpp          # Identity keys, login and handshake signing, session keys, fingerprints, AEAD helpers
│   ├── crypto.hpp          # Identity and Session structures, cryptography declarations
│   ├── contacts.cpp        # Contact rules, hex IDs, loading and safely saving the contacts file
│   ├── contacts.hpp
│   ├── net.cpp             # Framing, addressed bodies, user lists, complete socket read/write helpers
│   ├── net.hpp             # Message types, peer IDs, labels, limits, networking declarations
│   ├── util.cpp            # Name validation and command parsing
│   └── util.hpp
├── tests/
│   ├── doctest.h           # Test framework (single header)
│   ├── test_main.cpp       # Initializes libsodium and runs all tests
│   ├── test_net.cpp        # Framing and user-list parsing
│   ├── test_crypto.cpp     # Handshake signing, key derivation, encryption
│   ├── test_contacts.cpp   # Hex IDs, contact rules, saving and loading the contacts file
│   ├── test_util.cpp       # Name validation and command parsing
│   └── test_integration.cpp  # Real server over TCP: login, routing, malformed frames
├── experiments/
│   └── terminal_test.cpp   # Early terminal input experiments (not built)
├── Makefile                # Build, test and clean targets
├── .gitignore
├── LICENSE                 # MIT license
└── README.md
```

## Security Considerations

This is an experimental application, **not an audited or production-ready secure messenger**.

- **Contacts are only as good as the first fingerprint check:** The client trusts whatever ID you save with `/add`. If you add someone without comparing fingerprints, a malicious server could have shown you an identity it controls. Comparing fingerprints out of band once, before adding, is what makes a contact trustworthy.
- **Handshakes can get out of step:** The protocol does not mark a handshake as an offer or a reply; each client infers this from its own state. When one side ignores a handshake (because the sender is not yet a contact), the two sides can disagree about the session until someone runs `/chat` again after the 5-second retry delay. Messages sent in that window are rejected, not exposed.
- **Old handshakes can be replayed:** A malicious server could resend an earlier, genuinely signed handshake. It cannot read any messages this way, because that handshake's ephemeral secret was wiped long ago, but it would break the session until one side runs `/chat` again.
- **Local files are protected only by permissions:** Each `identity.key` and `contacts` file is protected only by file and folder permissions (`0600` and `0700`). Anyone who can write to your profile folder could swap a contact's ID or steal your identity.
- **No replay protection for messages:** A captured valid message could be re-sent, and messages could be dropped or reordered, without detection.
- **Message type not bound to ciphertext:** The frame type is not yet included as authenticated additional data.
- **Unknown-sender notices are not rate-limited:** Anyone online can repeatedly send handshakes and fill your screen with "wants to chat" notices.
- **Metadata is visible to the server:** It sees who is online, who talks to whom, and message sizes and timing, though not message content.
- **No offline delivery or history:** Messages to users who are not online are not stored, and no chat history is kept.

Do not rely on this project to protect sensitive information.

## Roadmap

- [x] Client-to-client key exchange with ephemeral keys
- [x] Session fingerprints for detecting man-in-the-middle attacks
- [x] Server relays only client frame types; control messages come only from the server
- [x] Make server address and port configurable
- [x] Improve disconnect, terminal and error handling
- [x] Long-term Ed25519 identity keys
- [x] Challenge-response login to the server
- [x] Addressed frames, multi-user routing and online presence
- [x] Multiple independent one-to-one conversations
- [x] Sign handshake keys with identity keys so peers are authenticated automatically
- [x] Named profiles, so several identities can run from one folder
- [x] Unit tests with sanitizers (`make test`)
- [x] Continuous integration with GitHub Actions on Ubuntu and macOS
- [x] Integration and malformed-input tests against the real server
- [x] Contacts (`/add`, `/remove`, `/contacts`, `/chat name`), contacts-only conversations and labels from saved names
- [ ] Mark handshakes as offers or replies, with each reply bound to the offer it answers
- [ ] Show each unknown-sender notice only once per person
- [ ] Dedicated "user not found" frame type instead of `ERROR_MSG`
- [ ] Show the current conversation in the prompt
- [ ] Bind the frame type to each ciphertext as authenticated additional data
- [ ] Add message counters for replay and reordering detection
- [ ] Full-screen terminal UI
- [ ] `make install`, standard config and data paths, releases and a Homebrew tap
- [ ] Group chat
- [ ] Replace thread-per-client with `poll()`, and add load and latency benchmarks

## License

Licensed under the [MIT License](LICENSE).
