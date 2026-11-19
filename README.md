# Tango
![CI](https://github.com/oliveiramnando/tango-chat/actions/workflows/ci.yml/badge.svg)

A terminal-based, end-to-end encrypted TCP chat application written in **C++20**. Clients log in to a multithreaded relay server with a long-term **Ed25519** identity key, save the people they trust as contacts, and open private one-to-one conversations with them. Each conversation uses its own ephemeral **X25519** key exchange, signed with both users' identity keys, and **XChaCha20-Poly1305** authenticated encryption via [libsodium](https://doc.libsodium.org/).

The server authenticates users and routes frames, but it never holds conversation keys and cannot read chat content. Because every handshake is signed and conversations are only possible with saved contacts, the server also cannot swap in its own keys or pass off another identity as one of your contacts.

> **Project status:** Work in progress, built for learning systems programming and applied cryptography. It has not been audited and is **not suitable for protecting sensitive communication**. See [Security Considerations](#security-considerations).

## Features

- **Persistent identity profiles:** Each client runs under a named profile. On first use it creates an Ed25519 identity key pair in `profiles/<name>/identity.key` with owner-only permissions, and reuses it afterwards. A user's ID is their 32-byte public key, shown as a short fingerprint.
- **Challenge-response login:** The server sends a random 32-byte challenge, and the client proves it owns its identity by signing it. No passwords are involved, and duplicate logins with the same identity are rejected.
- **Contacts:** After comparing fingerprints with someone out of band, you save their ID under a name with `/add`. Contacts are stored per profile and shown by name everywhere: in `/users`, in connection messages and on every incoming message.
- **Contacts-only conversations:** `/chat` only accepts saved contacts, and handshakes from anyone else are ignored, with a one-time notice per person. Both people must add each other before they can talk, which makes the fingerprint check a required step.
- **Trustworthy sender labels:** Incoming messages are labeled with the name *you* saved for the sender's ID, not a name the sender chose.
- **Safe terminal output:** Text from other users and from the server is cleaned before it is printed. Control characters (such as escape sequences and newlines), Unicode direction overrides and invalid UTF-8 are shown as `?`, so a message can't redraw the screen, fake a line from another contact, or fake a security notice.
- **Live presence:** The server sends the list of online users at login (split over several frames when it is long), then notifies clients as users come online or go offline, always in order.
- **Signed offer/reply handshakes:** A conversation starts with a signed *offer* and is answered with a signed *reply* that names the offer it answers, so neither side ever has to guess what a handshake means. Both are bound to both users' IDs, and the receiver verifies the signature before touching any session, so forged, altered, redirected or stale handshakes are rejected and cannot disturb an existing conversation.
- **Reliable connection setup:** If both people start a chat at the same moment, the two offers are resolved the same way on both sides. If a handshake gets no reply (for example because the peer had not added you yet), running `/chat` again sends a fresh offer straight away.
- **End-to-end encryption:** XChaCha20-Poly1305 authenticated encryption with a fresh random 24-byte nonce for every message.
- **Replay and reordering protection:** Every message carries a number that is authenticated together with both users' IDs. Repeated or out-of-order messages are rejected, and missing ones are reported.
- **Ephemeral key exchange per conversation:** A new key pair for every session, with directional `rx`/`tx` keys derived using libsodium's `crypto_kx` API. Ephemeral secret keys are wiped as soon as session keys are derived, and session keys are wiped when the peer goes offline or is removed from your contacts.
- **Session fingerprints:** After each handshake, both clients print a hash of the two ephemeral public keys, which can be compared as an extra check.
- **Addressed, relay-only routing:** The server forwards only `HANDSHAKE` and `MESSAGE` frames, and only to the addressed recipient. It stamps every relayed frame with the authenticated sender's ID, so clients cannot impersonate each other. A client that sends any other frame type is disconnected.
- **Robust multithreaded server:** One thread per client, with a send lock per connection so frames never interleave, connections shared through `shared_ptr` and closed only when no thread can still use them, no network sends while the user registry is locked, send and login timeouts, and a connection cap. A client that stops reading is dropped instead of stalling everyone else.
- **Input validation:** Frame lengths, message types, IDs, public-key sizes, signatures, ciphertext sizes, profile and contact names, command arguments and contacts-file lines are checked before use. Malformed or unauthenticated data is rejected without crashing.
- **Load generator:** `loadgen` drives the server with hundreds of headless clients doing real logins, handshakes and encrypted messages, and reports correctness (lost, reordered and misdelivered messages), throughput, latency percentiles and fairness. Modes for paced load, many-to-one traffic, constant reconnects and clients that stop reading reproduced several concurrency bugs, which are now fixed. Results are in [`docs/benchmarks.md`](docs/benchmarks.md).
- **Tests and CI:** [doctest](https://github.com/doctest/doctest) unit tests for framing, cryptography, contacts and input parsing, plus integration tests that start the real server and talk to it over TCP. All tests run with AddressSanitizer and UndefinedBehaviorSanitizer, on Ubuntu and macOS, on every push through GitHub Actions.
- **Terminal chat interface:** Colored messages, live line editing, a prompt that shows who you are talking to (`you -> bob >`) and is redrawn when messages arrive, and terminal settings restored on every exit path.
- **Configurable host, port and profile:** Set from the command line, defaulting to `127.0.0.1:8080` and the `default` profile.

## Tech Stack

| Component | Technology |
| --- | --- |
| Language | C++20 |
| Transport | POSIX TCP sockets |
| Concurrency | `std::thread`, `std::mutex`, `std::atomic`, `std::shared_ptr`, `std::latch` |
| Cryptography | libsodium (Ed25519 `crypto_sign`, X25519 `crypto_kx`, XChaCha20-Poly1305, BLAKE2b via `crypto_generichash`) |
| Terminal | `termios`, ANSI escape sequences |
| Testing | doctest, AddressSanitizer, UndefinedBehaviorSanitizer, custom load generator |
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
git clone https://github.com/oliveiramnando/tango-chat.git
cd tango-chat
make
```

This produces two executables: `server` and `client`. Both link against libsodium: the client for all of its cryptography, and the server only to verify login signatures. The load generator is built separately with `make loadgen` (see [Load Testing](#load-testing)).

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

- **Unit tests** cover framing, handshake signing and verification, key derivation, encryption, message numbering (replays, gaps, altered counters and IDs), the contacts file, name and command parsing, and cleaning received text for the terminal.
- **Integration tests** start `./server` on a free port and connect headless clients to it. They check login, presence, signed offers and replies, private message delivery, rejection of a message delivered twice, rejected logins, offline recipients (`USER_NOT_FOUND`), a user list too long for one frame (300 users), and that malformed frames close only the offending connection while the server keeps running. The server's output during these tests is written to `server_test.log`.

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
6. Type **`/chat name`** to start the conversation. The prompt changes to `you -> name >`. The signed key exchange runs automatically; wait for **`Verified secure connection with name`**.
7. Type a message and press Enter to send it to the selected contact. Messages from your other contacts appear as they arrive, labeled with the names you saved.

From then on, just use `/chat name`. Your contacts are remembered between runs.

If someone who has not added you tries to talk to you, you see a notice with their fingerprint (once per person) instead of a conversation. If you started a chat before the other person added you, run `/chat name` again once they have, and the client sends a fresh offer.

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

## Load Testing

`loadgen` connects many headless bot clients to a running server. The bots log in, run the signed offer/reply handshake and send real encrypted messages, just like `client`. Each message carries its send time and a sequence number, so every delivery is timed and checked.

```bash
make server loadgen
./server 9000 > /tmp/server.log 2>&1 &
./loadgen --pairs 10 --messages 10000
```

| Option | Meaning | Default |
| --- | --- | --- |
| `--host H`, `--port N` | Server to test | `127.0.0.1`, `9000` |
| `--pairs N` | Number of receivers | `10` |
| `--fanin K` | Senders per receiver (several server threads writing to one socket) | `1` |
| `--messages N` | Messages per sender | `10000` |
| `--size N` | Bytes per message (at least 16) | `64` |
| `--rate N` | Messages per second per sender; `0` sends as fast as possible | `0` |
| `--churn C` | Extra pairs whose receiver keeps disconnecting and logging back in | `0` |
| `--stalled S` | Extra receivers that never read, while their senders flood them | `0` |

The report gives, in order:

- **What was run:** date, machine, CPU count, load and rate.
- **Delivery:** delivered, missing, lost, out-of-order and misdelivered messages, churn and stalled-client results, and a single **`OK` / `FAILED` verdict**. If it says `FAILED`, ignore the performance numbers.
- **Performance**, after a 10% warm-up: throughput and latency percentiles (p50 to max). Without `--rate`, senders never wait, so latency mostly measures queueing; use `--rate` for meaningful latency. Paced runs also report whether the senders kept to the schedule.
- **Fairness:** the slowest, median and fastest sender.
- A one-line **`summary`** for collecting many runs with `grep '^summary'`.

The exit code is `0` only if the verdict is `OK`. Measured results, and the bugs the tool found, are recorded in [`docs/benchmarks.md`](docs/benchmarks.md).

> On WSL, keep the server's output out of `/mnt/c`, for example in `/tmp`; writes to the Windows drive are slow enough to distort the measurements.

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
   |--- OFFER [B][eA][sig A] --->|--- OFFER [A][eA][sig A] ---->|
   |                             |   verify, A is a contact,    |
   |                             |   derive rx/tx, wipe secret  |
   |<-- REPLY [A][eB][eA][sig B]-|<-- REPLY [A][eB][eA][sig B] -|
   |  verify, B is a contact,    |                              |
   |  reply answers eA: derive   |                              |
   |  rx/tx, wipe secret         |                              |
   |                             |                              |
   |--- MESSAGE [B][ciphertext]->|--- MESSAGE [A][ciphertext]-->|
```

### Login

1. When a client connects, the server sends a `CHALLENGE` of 32 random bytes.
2. The client signs `"tcpchat-login-v1" || challenge` with its Ed25519 identity key and replies with `AUTH`: its 32-byte public key followed by the 64-byte signature. The label keeps a login signature from being reusable in any other context.
3. The server verifies the signature. If it is valid and that identity is not already online, the server sends `AUTH_OK`, registers the client, sends it the list of online users, and sends `USER_ONLINE` to everyone else. Otherwise it sends `ERROR_MSG` and closes the connection. A long user list is split over several `USER_LIST` frames, each saying whether more follow.
4. The login must be completed within **10 seconds** of connecting, or the server closes the connection. The server accepts at most **1,000** connections at once; beyond that, a new connection gets `ERROR_MSG` "Server full." and is closed.
5. When a client disconnects, the server removes it and sends `USER_OFFLINE` to everyone else. The same identity can log in again once that has been sent, so other users never see "online" before the previous "offline".

### Contacts

Contacts are saved in `profiles/<name>/contacts`, a plain-text file with one contact per line:

```text
3f9a...c41e bob
a07d...92b0 carol
```

Each line is the contact's full 64-character hex ID, a space, and the name. Names follow the same rules as profile names, and no ID or name may appear twice. Blank lines and lines starting with `#` are ignored. When the file is loaded, a bad line is skipped with a warning naming its line number, and the rest of the file is still used.

The file is rewritten in full on every `/add` and `/remove`. The client writes `contacts.tmp` with owner-only permissions, then renames it over `contacts`, so an interrupted save leaves the previous file intact rather than a half-written one. If saving fails, the change is undone in memory too, so the running client and the file never disagree.

### Conversations

1. The client keeps a separate session for each peer, indexed by the peer's ID. Each session is in one of three states: **None** (no conversation), **Offered** (we sent an offer and are waiting for its reply) or **Ready** (keys derived).
2. `crypto_kx` requires the two sides to take different roles. Each client decides without asking the server: the side whose identity public key compares lower (byte by byte) is the **initiator**, and the other is the **responder**. Both sides always reach the same answer.
3. `/chat name` looks the contact up and checks they are online. It then generates a fresh ephemeral key pair and sends a signed **offer**. When the peer accepts, it answers with a signed **reply** containing its own ephemeral key **and the offer key it is answering**:

   ```text
   offer:  "tcpchat-offer-v1" || sender ID || recipient ID || offer key
   reply:  "tcpchat-reply-v1" || sender ID || recipient ID || reply key || answered offer key
   ```

   Only the keys and signature are sent; the receiver rebuilds the signed message. Including both IDs means a handshake meant for one user cannot be redirected to another. The separate labels mean an offer's signature can never be passed off as a reply's, or a login signature as either.
4. On receiving a `HANDSHAKE`, the client reads the kind byte, checks the payload has exactly the size for that kind, and verifies the signature against the sender's ID (stamped by the server). If any check fails, the frame is dropped **before any session is looked up or changed**.
5. If the signature is valid but the sender is **not a saved contact**, the client ignores the handshake, with a notice showing their fingerprint the first time that person tries: no session is created and no reply is sent.
6. For a contact, the client applies these rules:

   | Session state | Received | Action |
   | --- | --- | --- |
   | None | Offer | Reply to it → Ready |
   | Ready | Offer with the key already answered | Duplicate: ignore |
   | Ready | Offer with a new key | Peer started over: reply with a new key pair → Ready |
   | Offered | Offer (both started at once) | The lower offer key wins. If theirs wins, drop ours and reply → Ready. If ours wins, ignore theirs and send our offer again. |
   | Offered | Reply answering **our current** offer | Derive keys → Ready |
   | Anything else | Reply | Stale or not for us: ignore |

   Because both sides see the same two offer keys, crossed offers are always resolved the same way. Sending an offer again is harmless, since a copy the peer has already answered is ignored as a duplicate.
7. Each client derives a **receive (`rx`)** and **transmit (`tx`)** key and wipes its ephemeral secret key. One side's `tx` equals the other side's `rx`. Both print the peer's name and a session fingerprint (a BLAKE2b hash of both ephemeral keys, in initiator-then-responder order).
8. Running `/chat` again while an offer is unanswered sends a fresh offer immediately. A late reply to the old offer no longer matches and is ignored, so retrying is safe at any time.
9. Messages (`name : message`) are numbered from 0 in each direction of each session, encrypted with that peer's `tx` and a new random nonce, sent addressed to the peer, and decrypted by the recipient with its `rx` for the sender (see [Encryption](#encryption)). The recipient displays the name it saved for the sender's ID and ignores the name inside the message. Messages from peers without a Ready session, that fail authentication, or that repeat an earlier number are rejected; if numbers are skipped, the recipient is warned that earlier messages never arrived.
10. When a peer goes offline, or is removed from your contacts, the client wipes and removes that peer's session.

### Server Design

The server runs one thread per client. Several threads may need to send to the same client at once (its own handler, everyone messaging it, and presence updates), so each connection is wrapped in a `Connection`:

- **One send lock per connection:** every frame to a client is written while holding that client's lock, so frames never interleave. Threads sending to different clients don't wait for each other.
- **Shared ownership:** connections are held through `shared_ptr`. A thread that is sending to a client keeps its `Connection` alive even if the client disconnects meanwhile.
- **Closed only by the last owner:** the socket is closed in `~Connection()`, when the last `shared_ptr` is released. Closing it earlier would free the socket number for reuse by a new connection while another thread could still write to it. A connection is ended early with `shutdown()`, which cuts it but keeps the number reserved.
- **No sends under the registry lock:** `clientsMutex` protects the map of logged-in users. Under it, the server only reads or changes the map and copies what it needs (the user list, who to notify); all sends happen after it is released, so one slow client can't block logins, logouts or message routing for everyone else.
- **Ordered login frames:** a new client holds its own send lock from just before it is added to the map until `AUTH_OK` and the user list are sent, so those are always the first frames it receives.
- **Timeouts and limits:** a send that blocks for 2 seconds fails, and that client is dropped (a partly written frame would leave its stream unreadable anyway); logins time out after 10 seconds; at most 1,000 connections are accepted.
- **No small-write delays:** `TCP_NODELAY` is set on every socket, on the server and the clients. Without it, Nagle's algorithm and delayed ACKs held back one message per conversation by about 40 ms.

### TCP Frame Format

Each frame is encoded as:

```text
+----------------------+-------------------+-------------------------+
| Length (4 bytes)     | Type (1 byte)     | Body (variable length)  |
+----------------------+-------------------+-------------------------+
```

- **Length:** Unsigned 32-bit integer in network byte order, counting the type byte and body (not the length prefix itself). Frames shorter than 1 byte or longer than the maximum are rejected and the connection is closed.
- **Type:** One of the values below.
- **Limit:** The maximum frame length is **8,192 bytes**, including the type byte. The 32-byte peer ID and 48 bytes of message overhead (counter, nonce and tag) leave room for about 8,100 bytes of plaintext per message, including the sender's chat name.

Relayed frames carry an **addressed body**: `[32-byte peer ID][payload]`. From client to server, the ID is the **recipient**; the server replaces it with the authenticated **sender's** ID before forwarding. The server never inspects the payload.

| Type | Value | Sent by | Body |
| --- | --- | --- | --- |
| `MESSAGE` | 1 | client (relayed) | `[peer ID][8-byte counter][24-byte nonce][ciphertext][16-byte tag]` |
| `HANDSHAKE` | 2 | client (relayed) | `[peer ID][payload]`; see below |
| — | 3, 4 | — | Reserved (formerly `PEER_JOINED`/`PEER_LEFT`, no longer used) |
| `ERROR_MSG` | 5 | server only | Error text (e.g. "Server full.") |
| `CHALLENGE` | 6 | server only | 32 random bytes |
| `AUTH` | 7 | client only | `[32-byte Ed25519 public key][64-byte signature]` |
| `AUTH_OK` | 8 | server only | Empty |
| `USER_LIST` | 9 | server only | `[1 byte: 1 if another USER_LIST follows, 0 if last][up to 255 IDs of 32 bytes]` |
| `USER_ONLINE` | 10 | server only | 32-byte ID |
| `USER_OFFLINE` | 11 | server only | 32-byte ID |
| `USER_NOT_FOUND` | 12 | server only | 32-byte ID of a recipient who is not online, so a relayed frame could not be delivered |

A `HANDSHAKE` payload starts with a kind byte:

| Kind | Value | Payload | Size |
| --- | --- | --- | --- |
| Reply | 1 | `[kind][32-byte reply key][32-byte answered offer key][64-byte signature]` | 129 bytes |
| Offer | 2 | `[kind][32-byte offer key][64-byte signature]` | 97 bytes |

The kind byte itself is not signed, but it decides which label the signature is checked with, so changing it makes verification fail.

A frame can't exceed 8,192 bytes, so the list of online users is sent as one or more `USER_LIST` frames of up to 255 IDs, (8,192 − 1 type byte − 1 flag byte) / 32. The client adds each frame's IDs to its list; at least one frame is always sent, even for an empty list.

The `readNBytes()` and `sendAll()` helpers handle reads and writes that transfer fewer bytes than requested, since TCP does not preserve message boundaries. `sendFrame()`, `receiveFrame()`, `buildBody()` and `parseBody()` build and parse frames, and are shared by the client and server so both always use the same format.

### Encryption

`crypto.cpp` uses **XChaCha20-Poly1305** with a random **24-byte nonce** per message. A message payload is structured as:

```text
[8-byte counter][24-byte nonce][ciphertext][16-byte authentication tag]
```

The **counter** numbers the messages in each direction of a session, starting at 0, and is sent in the clear (big-endian). It is protected as **additional data**: bytes that AEAD authenticates without encrypting. The additional data for each message is:

```text
"tcpchat-msg-v1" || sender ID || recipient ID || counter
```

so the tag only verifies if the counter, both IDs and the purpose of the data are exactly what the sender used. The recipient authenticates the message first and only then looks at its number:

| Counter | Meaning | Result |
| --- | --- | --- |
| The next expected number | Normal | Accepted |
| Higher than expected | Genuine, but earlier messages never arrived | Accepted, with a warning saying how many are missing |
| Lower than expected | Already seen, or delivered out of order | Rejected |

Because checking comes after authentication, forged data can't move the counter or be reported as a replay. Counters restart at 0 with every new handshake; messages from an earlier session can't be replayed into a new one, because they were encrypted with different keys.

The tag lets the recipient reject any message that was altered, truncated or encrypted with a different key. Because each direction of each conversation has its own key, a message cannot be reflected back to its sender or replayed into a different conversation. The only key stored on disk is each profile's long-term identity key; all conversation keys exist only in memory for the length of a session.

## Project Structure

```text
tango-chat/
├── .github/
│   └── workflows/
│       └── ci.yml          # Build and test on Ubuntu and macOS on every push
├── src/
│   ├── client.cpp          # Profiles, login, commands, per-peer sessions, terminal UI, send/receive threads
│   ├── server.cpp          # Login verification, connections, user registry, presence, routing, limits
│   ├── crypto.cpp          # Identity keys, login, offer and reply signing, session keys, fingerprints, numbered AEAD messages
│   ├── crypto.hpp          # Identity, Session and session states, payload sizes, cryptography declarations
│   ├── contacts.cpp        # Contact rules, hex IDs, loading and safely saving the contacts file
│   ├── contacts.hpp
│   ├── botclient.cpp       # Headless client used by the integration tests and the load generator
│   ├── botclient.hpp
│   ├── net.cpp             # Framing, addressed bodies, split user lists, socket helpers, TCP_NODELAY
│   ├── net.hpp             # Message and handshake types, peer IDs, labels, limits, networking declarations
│   ├── util.cpp            # Name validation, command parsing, cleaning received text for the terminal
│   └── util.hpp
├── tests/
│   ├── doctest.h           # Test framework (single header)
│   ├── test_main.cpp       # Initializes libsodium and runs all tests
│   ├── test_net.cpp        # Framing, user-list splitting and parsing
│   ├── test_crypto.cpp     # Offer and reply signing, key derivation, encryption, message numbering
│   ├── test_contacts.cpp   # Hex IDs, contact rules, saving and loading the contacts file
│   ├── test_util.cpp       # Name validation and command parsing
│   └── test_integration.cpp  # Real server over TCP: login, offers and replies, routing, long user lists, malformed frames
├── tools/
│   └── loadgen.cpp         # Load generator: correctness, throughput, latency and fairness under load
├── docs/
│   └── benchmarks.md       # Load test results, bugs found and before/after numbers
├── experiments/
│   └── terminal_test.cpp   # Early terminal input experiments (not built)
├── Makefile                # Build, test, loadgen and clean targets
├── .gitignore
├── LICENSE                 # MIT license
└── README.md
```

## Security Considerations

This is an experimental application, **not an audited or production-ready secure messenger**.

- **Contacts are only as good as the first fingerprint check:** The client trusts whatever ID you save with `/add`. If you add someone without comparing fingerprints, a malicious server could have shown you an identity it controls. Comparing fingerprints out of band once, before adding, is what makes a contact trustworthy.
- **Old offers can be replayed:** A malicious server could resend an earlier, genuinely signed offer. The receiver treats it as the peer starting over and replies to it. The server cannot read any messages this way, because that offer's ephemeral secret was wiped long ago, but it would break the session until one side runs `/chat` again. Replayed *replies* are already rejected, since they no longer answer the current offer.
- **Local files are protected only by permissions:** Each `identity.key` and `contacts` file is protected only by file and folder permissions (`0600` and `0700`). Anyone who can write to your profile folder could swap a contact's ID or steal your identity.
- **Dropped messages are only noticed later:** If messages are withheld, the recipient is warned when the next message arrives, not before. The last messages of a conversation could be dropped without any warning.
- **Limited protection against denial of service:** The login timeout and the 1,000-connection cap stop the simplest resource exhaustion, but there are no per-address limits or rate limits, so a determined client can still fill the server or flood other users.
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
- [x] Show the current conversation in the prompt
- [x] Show each unknown-sender notice only once per person
- [x] Mark handshakes as offers or replies, with each reply bound to the offer it answers
- [x] Load generator with paced, fan-in, churn and stalled-client modes, and recorded benchmarks
- [x] Fix server concurrency bugs found under load: interleaved frames, reused sockets, sends under the registry lock, Nagle delays, per-message logging
- [x] Login timeout, connection cap, and user lists longer than one frame
- [ ] Freshness check for offers, so a replayed old offer is rejected
- [ ] Split the client into a core and a front end, with unit tests for the handshake rules
- [x] Dedicated `USER_NOT_FOUND` frame type instead of `ERROR_MSG`
- [x] Message counters and additional data: replayed, reordered and dropped messages are detected
- [x] Clean received text before printing it, so messages can't inject terminal control sequences
- [ ] Full-screen terminal UI
- [ ] `make install`, standard config and data paths, releases and a Homebrew tap
- [ ] Group chat
- [ ] Per-connection outgoing queues or a `poll()`-based server, so one slow client never delays a broadcast
- [ ] Run the load generator in CI

## License

Licensed under the [MIT License](LICENSE).
