# Benchmarks and Load Tests

This file records what the load generator (`tools/loadgen.cpp`) measured, which server bugs it found, and the before-and-after results of each fix. The numbers are a log of what happened on specific machines on specific days, not a guarantee of performance elsewhere.

## Setup

### Machines

| Name | Hardware | Notes |
| --- | --- | --- |
| **WSL** | `WIN4`, 12 CPUs, Ubuntu under WSL2 on Windows | Repository on `/mnt/c` (the Windows drive). Another virtual machine and several apps were running during all runs, so results are noisy. |
| **VM** | 2-CPU Linux virtual machine | Used to develop and check each fix before it was run on WSL. |

Unless a section says otherwise, numbers come from **WSL**. Server and load generator ran on the same machine and talked over `127.0.0.1`, so they competed for the same CPUs.

### Builds

- Server: `make server` (`-g`, no optimisation, no sanitizers).
- Load generator: `make loadgen` (`-O2`, no sanitizers), so the tool's own overhead stays small.

### How the load generator measures

- **Bots** are headless clients (`src/bot/botclient.cpp`) that log in, run the signed offer/reply handshake and exchange real encrypted messages, exactly like the terminal client.
- Each message is a **probe**: `[8-byte send time][8-byte sequence number][padding]`. The receiver records each message's latency and checks for lost, duplicated, reordered and misdelivered messages.
- **Warm-up:** the first 10% of each sender's messages are checked for correctness but left out of throughput and latency.
- **Unpaced runs** (no `--rate`): senders never wait, so queues fill up. Their **throughput** shows the maximum the system can push through; their **latency** mostly shows how long messages sat in queues, and grows with the length of the run. Don't read it as a speed number.
- **Paced runs** (`--rate N`): each sender sends N msg/s on a fixed schedule, and latency is measured from the scheduled time, so stalls are counted (avoiding *coordinated omission*). The report says whether the senders kept to the schedule.
- **Percentiles** use the nearest-rank method. Where a section has five runs, the table shows the **median** run value.

Every report ends with a one-line `summary`, so many runs can be collected with:

```bash
for i in 1 2 3 4 5; do ./loadgen --pairs 10 --messages 10000 | grep '^summary'; done
```

### Running a measurement

```bash
pkill -x server
./server 9000 > /tmp/server.log 2>&1 &   # keep the log off /mnt/c on WSL (see #7)
./loadgen --pairs 10 --messages 10000
```

Before trusting a result, check that the server actually started (no `Exit 1` from the shell; a leftover server may still hold the port), and compare only runs taken back to back under the same conditions.

## Summary of findings

| # | Problem | Found by | Before | After |
| --- | --- | --- | --- | --- |
| 5 | Nagle + delayed ACK stalled one message per conversation | Lockstep latency | max **~42 ms in every run** | Fixed 42 ms stall gone |
| 7 | Per-message log line, flushed under a global lock | Scaling to 50 pairs | 50 pairs: **103.7 s, 964 msg/s** | **0.25 s, 404,830 msg/s** |
| 6 | `USER_LIST` larger than one frame above 256 users | 129 pairs | login 257 of 258 failed | 400 bots OK |
| 1 | Two threads writing to one socket spliced frames | `--fanin` | 5/5 runs FAILED | 5/5 OK (VM) |
| 2 | Relay to a socket number reused by a new connection | `--churn` | Wrong-recipient frames | None in ~43,000 reconnects |
| 3 | Sends made while holding `clientsMutex` | `--stalled`, `--churn` | Server froze after 65 ms (VM) | 3/3 OK |
| 4 | No login timeout, no connection cap | Code review | Idle connection kept forever | Closed after 10.2 s; cap enforced |

## Baseline: one pair, lockstep

The first version of the tool sends one message, waits for it to arrive, then sends the next, so only one message is in flight. 20,000 messages of 64 bytes, 5 runs:

| Run | Throughput | Average trip |
| --- | --- | --- |
| 1 | 5,716 msg/s | 174.9 µs |
| 2 | 5,961 msg/s | 167.8 µs |
| 3 | 6,125 msg/s | 163.3 µs |
| 4 | 6,169 msg/s | 162.1 µs |
| 5 | 5,848 msg/s | 171.0 µs |

**Median: 5,961 msg/s, 167.8 µs per message, spread about ±4%.** That spread is the noise level for these conditions: a change has to move the result by clearly more than this to count. A 1,000-message run gave 285 µs, because short runs are dominated by warm-up.

## #5: TCP_NODELAY

With per-message latency (lockstep, 20,000 × 64 bytes, 5 runs), the maximum was **41.6–42.7 ms in every run**, about 1,000× the median. The slow message was always the second one in the conversation. That is the signature of Nagle's algorithm (holding back a small write until the previous one is acknowledged) meeting delayed ACK (the receiver waiting up to 40 ms before acknowledging).

**Fix:** `setNoDelay()` sets `TCP_NODELAY` on every socket: after `accept()` in the server, after `connect()` in the client and the bots.

**Which side needs it** (VM, max latency per run):

| `TCP_NODELAY` on | Max latency |
| --- | --- |
| Neither | ~43 ms |
| Bots only | ~43 ms |
| Server only | ~43 ms |
| **Both** | **0.6–11 ms** |

Each message crosses two connections (sender → server, server → receiver), and each can stall on its own.

**WSL, before and after** (medians of 5 runs):

| | p50 | p90 | p99 | p99.9 | max | throughput |
| --- | --- | --- | --- | --- | --- | --- |
| Before | 51.4 µs | 81.1 µs | 227.7 µs | 1,070 µs | 42.1 ms (every run) | 14,846 msg/s |
| After | 151.0 µs | 228.0 µs | 386.0 µs | 2,072 µs | 17.3 ms (varies: 8.7–61.2 ms) | 5,841 msg/s |

Only the **max pattern** is comparable here. The fixed 42 ms delay is gone; what remains varies from run to run and looks like scheduling noise. The p50 and throughput differences come from the conditions, not the fix: the "before" runs went to a leftover server process whose output was probably not going to a terminal, while the "after" runs went to a fresh server that printed a line for every message (see #7).

> TODO: clean before-and-after comparison of #5 on a quiet machine, running both server versions back to back.

## #7: logging every relayed message

Scaling up to many pairs showed throughput **falling** as pairs were added, the opposite of what a healthy server does. The server printed `[Relayed N bytes]` with `endl` (a flush) for every message, while holding the global `coutMutex`, and the log file was on `/mnt/c`, where every write crosses from Linux to Windows. Every client thread queued behind that lock.

Unpaced, 64-byte messages, with the per-message log going to `server.log` on `/mnt/c`:

| Pairs | Throughput |
| --- | --- |
| 1 | 49,561 msg/s |
| 10 | 26,902 msg/s |
| 50 | **964 msg/s** (103.7 s for 100,000 messages) |

Same server, 50 pairs × 2,000 messages:

| Server output | Elapsed | Throughput |
| --- | --- | --- |
| Per-message log to `server.log` on `/mnt/c` | 103.69 s | 964 msg/s |
| Per-message log to `/dev/null` | 0.50 s | 199,078 msg/s |
| **Per-message log removed** | **0.25 s** | **404,830 msg/s** |

About **420× faster**. Even with the output discarded, the lock, the formatting and one `write` call per message cost half the throughput.

The same pattern caused a second symptom later: when a run ended, hundreds of failed presence sends were each logged to `/mnt/c` **while holding `clientsMutex`**, so the next run's logins timed out (`login 2 of 20 failed: timed out waiting for a frame`). Moving the log to `/tmp` made that disappear; fix #3 removed the cause.

## Scaling and fairness

After #7, unpaced, 64-byte messages (single runs):

| Load | Throughput | Per-pair msg/s (min / median / max) | Pairs finished between |
| --- | --- | --- | --- |
| 10 pairs × 10,000 | 162,512 msg/s | 16,431 / 17,292 / 19,956 | 0.50–0.61 s |
| 50 pairs × 2,000 | 168,608 msg/s | 3,696 / 3,958 / **8,163** | 0.25–0.54 s |
| 50 pairs × 10,000 | 178,731 msg/s | 3,717 / 3,834 / 4,254 | 2.35–2.69 s |

- **No pair was starved:** the slowest pair always got at least 93% of the median.
- **Short runs favour early starters:** at 50 × 2,000, one pair ran at twice the median because its thread got a CPU before the queues filled. At 50 × 10,000 the gap shrank to 1.11×, so this is an effect of the test, not the server.
- **Throughput plateaus around 160–180k msg/s** whether 10 or 50 pairs are used.
- **Unpaced latency is not a speed number:** p50 was 206 ms at 50 × 2,000 and 1,207 ms at 50 × 10,000, with the same throughput. Longer runs just let the queues grow.

## Capacity curve (paced)

10 pairs, 64-byte messages, about 3 s per run, server log in `/tmp`:

| Offered | Delivered | p50 | p99 | Senders on schedule? |
| --- | --- | --- | --- | --- |
| 10,000 msg/s | 9,999 msg/s | 513 µs | 4.7 ms | Fell behind (3.5% late) |
| 50,000 msg/s | 49,987 msg/s | 499 µs | 2.5 ms | Kept up |
| 100,000 msg/s | 99,960 msg/s | 958 µs | **65 ms** | Fell behind (7.1% late) |
| 200,000 msg/s | **138,674 msg/s** | 755 ms | 1.3 s | Saturated |
| 400,000 msg/s | 171,138 msg/s | 2.2 s | 4.0 s | Saturated |

- **About 50,000 msg/s** with low latency; the **knee** (where p99 jumps) is around 100,000 msg/s; the **maximum** is about 140,000–170,000 msg/s. The maximum matches the unpaced plateau above.
- The "fell behind" at 10,000 msg/s is the machine, not the server: on WSL with a VM running, sleeping threads often wake a millisecond or more late, which also puts a floor of roughly 500 µs under p50. On the VM the same 10 pairs ran at 107–148 µs p50 up to 50,000 msg/s.
- All runs delivered every message in order.

> TODO: rerun this curve on the fixed server and on a quiet machine. Fix #3 in particular may move the knee.

## #6: user list above 256 users

Before the fix, `./loadgen --pairs 129 --messages 200` failed with:

```text
login 257 of 258 failed: connection closed or invalid frame
```

The 257th user receives a list of 256 others: 256 × 32 bytes + 1 type byte = 8,193 bytes, one over the 8,192-byte frame limit. The real client would have failed the same way.

**Fix:** the list is split over several `USER_LIST` frames of up to 255 IDs, each starting with a "more follows" flag byte.

**After:** `./loadgen --pairs 200 --messages 500` (400 bots): `verdict OK`. An integration test logs in 300 users.

## #1: interleaved frames (`--fanin`)

16 or 32 senders all write to one receiver, so several server threads write to the same socket. When the receiver's socket buffer is full, the kernel accepts a frame in pieces, and another thread's bytes can land in between.

```bash
./loadgen --pairs 1 --fanin 32 --messages 2000 --size 8000
```

| Server | Result |
| --- | --- |
| Before (WSL) | **5/5 FAILED**: `decrypt failed` after 506–680 messages; then all 32 senders timed out because the receiver stopped reading the broken stream |
| Before (VM) | 3/3 FAILED (`decrypt failed`); with 4,096-byte messages also `expected frame type 1, got 73` |
| After (VM) | **5/5 OK**, 64,000 / 64,000 delivered |

It is a race: with 16 senders and 4,096-byte messages, one WSL run passed. Small messages almost never trigger it, because they fit into the socket buffer in one piece.

**Fix:** each connection has its own send mutex (`Connection::send`), so frames to one client go out one at a time, while different clients still send in parallel.

> TODO: record the "after" for #1 on WSL.

## #2: relay to a reused socket (`--churn`)

Churn pairs: a receiver that keeps disconnecting and logging back in every 2–10 ms, while its sender keeps sending. A relay could look up the receiver's socket, the receiver could disconnect, and the OS could give the same socket number to a new connection before the relay wrote to it.

```bash
./loadgen --pairs 2 --messages 10000 --rate 1000 --churn 20
```

| Server | Reconnects (3 runs) | Wrong-recipient frames |
| --- | --- | --- |
| Before (WSL) | 41,702 | **1** (`login: expected frame type 6, got 1`: a chat message arrived before the CHALLENGE) |
| After (WSL) | 43,272 | **0** |
| Before (VM, `--churn 40`) | ~12,600 | 9 (`login: expected AUTH_OK, got frame type 1`), 3/3 runs FAILED |
| After (VM, `--churn 40`) | ~20,600 | 0, 5/5 runs OK, no leaked file descriptors |

**Fix:** a connection's socket is closed only in `~Connection()`, when the last `shared_ptr` to it is released, so its number can't be reused while another thread may still send on it. Ending a connection early uses `shutdown()`, which cuts it but keeps the number reserved.

Note: with `--churn 40` on WSL the server mostly **stopped responding** instead (237 msg/s delivered, 8,343 messages missing, 53 login timeouts). That was #3.

## #3: sending while holding `clientsMutex` (`--stalled`)

Logins and logouts sent presence frames to every client while holding `clientsMutex`. One client that stopped reading made one of those sends block, and every login, logout and message lookup on the server waited behind it.

`--stalled S` adds receivers that never read while their senders flood them with 1,000 × 8,000 bytes, more than the socket buffers hold.

```bash
./loadgen --pairs 2 --messages 10000 --rate 1000 --churn 5 --stalled 1
```

| Server | Result |
| --- | --- |
| Before (VM) | **FAILED**: froze after about 65 ms. 134 / 20,000 measured messages delivered, 25 churn logins timed out, all 5 churn senders stuck |
| After (VM) | 3/3 OK: 20,000 / 20,000, p50 about 120 µs, nothing stuck |
| After (WSL) | **3/3 OK**: 20,000 / 20,000, 0 senders stuck, about 3,300 reconnects per run |

Before the fix, the churn tests on WSL also showed churn senders blocked for more than 5 seconds (`send: could not send message`). These now count as failures (`senders stuck`).

**Fix:** under `clientsMutex` the server only reads or changes the map and copies what it needs; all sends happen after unlocking. A new client holds its own send lock until `AUTH_OK` and the user list are sent; a `leaving` set keeps presence in order; every client socket has a 2-second send timeout, and a client whose send fails is dropped.

After the fix (VM): fan-in still 3/3 OK, churn 40 3/3 OK, unpaced throughput 300,000–311,000 msg/s (unchanged), 5 stalled clients plus churn plus 10 pairs all OK, and the server's open file count back to 4 after every run.

## #4: login timeout and connection cap

Checked on the VM:

- A connection that never sends `AUTH` gets `Error receiving Auth.` and is closed after **10.2 s**. Before, it was kept forever.
- With the cap lowered to 50 for the test, the 51st connection got `server rejected login: Server full.`, and the next run worked normally.

## Open items

- Clean before-and-after of #5 on a quiet machine.
- WSL "after" numbers for #1.
- Capacity curve on the fixed server, on WSL and on macOS.
- A stalled client still delays the other recipients of the same broadcast by up to 2 s, once, before it is dropped. Removing that needs per-connection outgoing queues or a `poll()`-based server.
