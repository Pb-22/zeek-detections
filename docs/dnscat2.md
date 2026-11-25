# dnscat2 DNS session correlation

The detector correlates paired dnscat2 negotiation and session start messages with traffic in both directions. It requires distinct peer key fingerprints, matching DNS requests and actual answers, matching session IDs and a consistent generation before raising `DNScat2::CompatibleSession`.

| Entry | Source | Reader notes | Execution |
| --- | --- | --- | --- |
| Main | [main.zeek](../scripts/dnscat2/main.zeek) | [main.json](../website-notes/dnscat2/main.json) | Evaluates DNS observations incrementally. |
| Optional finite PCAP adapter | [cluster.zeek](../scripts/dnscat2/cluster.zeek) | [cluster.json](../website-notes/dnscat2/cluster.json) | Collects assigned finite inputs, validates closure and commits a source ordered batch through the shared main lifecycle. |

## Select an execution mode

From the repository root, select main explicitly for a capture:

```sh
zeek -C -r capture.pcap scripts/dnscat2/main.zeek
```

Use the desired capture filename. `-C` ignores packet checksums during replay. Main requires the negotiation, session start and subsequent paired traffic to reach the same lifecycle instance, with the DNS query names and actual answer data visible to Zeek.

The optional adapter uses the native Broker backend on Zeek 9.0.1 with a fixed manager, workers and proxy owners. A dedicated finite job supplies node membership, allowed observation scopes and immutable input assignments, including packet counts, hashes and source time bounds. Workers read their assigned trace, and the native close callback requires `/input/source.pcap`.

A policy file at the repository root selects the adapter with:

```zeek
@load ./scripts/dnscat2/cluster
```

`finite_mode` defaults to `F`. At startup that value prints `LIVE_CLUSTER_DISABLED` and exits the process. Explicit finite job configuration supplies `finite_mode=T`, assigned trace inputs and the fixed view needed by the completion checks.

Both assigned inputs close before the manager authorizes reduction. The resulting Notice is emitted during that later batch. Its explicit `$ts` retains the source time of the pair that completed the evidence. Main evaluates incrementally in standalone mode.

## Decode the actual DNS payload

The DNS gate requires a successful, complete message with one question and the expected query or reply direction. Pending transaction identity, question, answer owner, IN class, requested RR type and answer section must match. The actual reply data supplies server evidence.

| Carrier | Reconstruction |
| --- | --- |
| TXT | Bound and join the character strings, then parse raw hexadecimal text. |
| CNAME | Match the admitted suffix or explicit `dnscat.` wrapper, then decode the name labels. |
| MX | Decode the exchange name through the CNAME wrapper path. Preference retains its mail exchanger ranking meaning. |
| A | Convert the typed native address into four bytes: one sequence byte and three payload bytes. |
| AAAA | Convert the typed native address into sixteen bytes: one sequence byte and fifteen payload bytes. |

Address conversion uses native 32 bit words formatted at a fixed width. The AAAA path retains its full width for mapped addresses. Each response collects bounded sequence blocks until `dns_end`; identical duplicates are counted, conflicting duplicates and gaps reject. The first reconstructed byte declares message length. The decoder accepts arbitrary trailing padding values within the permitted final block and slices exactly the declared message.

All carriers enter the common envelope parser. INIT requires the 73 byte negotiation layout, supported zero subtype and flags, and the coordinate range checks used to retain a public key fingerprint. SYN and MSG require at least 17 decoded bytes; FIN requires at least 14. Paired stages and source request order complete the session predicate.

## Keep work and state bounded

**Parsing guards.** At most eight encoded boundaries are tried for a name. The 253 byte name limit and 512 byte decoded frame limit gate splitting, hexadecimal validation and conversion before lifecycle admission.

**Separate quotas.** Unanswered INITs enter a 512 entry candidate budget. A matching server INIT with a distinct fingerprint promotes the same epoch into a separate 256 entry session budget. Progressed sessions retain their quota while speculative candidates are evicted or expire.

**Embedded FIFOs.** Candidate and eligible pending records carry predecessor and successor links. Head and tail keys select admission and eviction positions directly. Append and unlink use a fixed number of link updates. Expiry scans the bounded tables, and promotion pressure scans retained sessions for the oldest completed or closed tombstone.

**Response lifetime.** A and AAAA blocks belong to one pending response. At `dns_end`, reconstruction completes and pending removal releases the retained block table and frame references. RR caps bound each collection at 64 A records or 16 AAAA records.

**Compact lifecycle inputs.** `Frame` and `Observation` retain kinds, lengths, SID, suffix, fingerprints, typed peers and transaction identity. Raw payload decoding stays in local normalization. The lifecycle and Broker facts operate on the metadata used by the decision.

**Stable ownership.** The typed HRW key groups scope, observed peers, typed server port, wrapper, suffix and SID under one effective owner. Query source ports remain transaction metadata, allowing the logical session context to follow related UDP exchanges across port changes and workers.

**Original epoch binding.** Each admitted query retains its generation and original key fingerprint. A new unanswered key creates a fresh epoch. Paired ENC, SYN, MSG and FIN facts must match the original binding before changing stage evidence or idle time. The finite owner saves that admitted Frame under its namespaced query token and restores it for the pair.

**Retained completion.** `done=T` is set before emission, producing one Notice for the retained session. Idle expiry or tombstone reclamation ends that retention window, and a later complete exchange can qualify again.

## Notice evidence

The classification is `DNScat2::CompatibleSession`. Its literal message is:

```text
dnscat2 DNS session pattern observed: paired negotiation and session-start messages followed by two-way session traffic
```

The subject template is:

```text
evidence=ENC_INIT,SYN,MSG; peer_keys=distinct; dns_request_reply=matched; suffix=%s; sid=%s
```

The first `%s` receives `q$suffix`; the second receives `q$sid`. Typed observed peers, UID and completing source reply time accompany the Notice. The main reader traces those arguments to their exact source expressions. The adapter reader explains its calls into the shared emitter.

## Configure lifetimes and inspect health

| Setting | Default | Effect |
| --- | --- | --- |
| `max_pending` / `pending_ttl` | 1024 / 30sec | Bound retained DNS transactions and their admission age. |
| `max_candidates` / `candidate_ttl` | 512 / 30sec | Bound unanswered negotiation state and its admission age. |
| `max_sessions` / `session_ttl` | 256 / 5min | Bound progressed and retained completion state, using accepted paired traffic for idle age. |
| `sweep_interval` | 1sec | Space expiry scans using `lifecycle_time`. |
| `max_boundaries` / `max_name_bytes` / `max_frame_bytes` | 8 / 253 / 512 | Bound parser work. |
| `max_worker_facts` | 2048 | Bound selected observations in each finite worker. |
| `max_owner_facts` / `max_tokens` | 4096 / 4096 | Bound finite owner facts, semantic entries and query bindings. |

The finite adapter waits for native EOF, contiguous per owner streams, consistent query and pair metadata, semantic checks and actual acknowledgements before commit. Owners then sort source events and advance `source_clock` before invoking the shared lifecycle. Scope and worker names configure placement; the detection predicate uses protocol structure and correlation.

The dedicated finite job keeps processes alive through EOF drain and explicit termination. It sets JSON logging, zero scheduled rotation, an empty rotation postprocessor and default remote logging disabled. Proxy configuration enables remote forwarding for the standard Notice filter. These settings apply to the whole job process.

At exit, main reports aggregate parsing, admission, expiry, eviction, capacity and FIFO health counters. `CLUSTER_STATS` reports finite buffers, token bindings, ACKs, source closes and configured limits. Read `coverage_degraded` alongside the separate drop, overflow and expiry counters when interpreting retained coverage.
