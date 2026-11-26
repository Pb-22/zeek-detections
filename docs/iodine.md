# iodine session recognition

The iodine module correlates version negotiation, an assigned userid, login configuration, and tunnel data in both directions. Matching fragment and ACK evidence qualifies DNS sessions. The Raw UDP path follows an accepted DNS session into its advertised peer and requires a paired Raw login and compressed traffic in both directions. The result is `Iodine::CompatibleSession` in Zeek's standard Notice stream.

## Source and selection

| File | Role | Reader notes |
| --- | --- | --- |
| [main.zeek](../scripts/iodine/main.zeek) | Entry point, selected UDP ports, observed direction and transport routing | [main.json](../website-notes/iodine/main.json) |
| [state.zeek](../scripts/iodine/state.zeek) | Pending transactions, negotiation, session generations, fragments, ACKs and Notice construction | [state.json](../website-notes/iodine/state.json) |
| [wire.zeek](../scripts/iodine/wire.zeek) | Byte operations, codecs, DNS message parsing and compressed framing checks | [wire.json](../website-notes/iodine/wire.json) |

Use the three files together from the `main` branch. Load `scripts/iodine/main.zeek` explicitly. The collection's current release remains 1.1.0, and its publisher loader continues to select PKINIT/U2U and the four Modbus modules. The iodine source is available for explicit standalone use from a checkout of `main`.

The verified iodine engine is stock Zeek 9.0.1. The reader notes explain the exact source statements and the state changes they produce.

## Replay a clear positive capture

The [iodine capture guide](https://github.com/Pb-22/Network_Detections/tree/main/iodine) supplies five selected test files. Start with `iodine-dns-positive-complete-session.pcap`, a native DNS session with NULL replies, Base128 upstream and Raw downstream.

Clone the source and capture repositories into the same parent directory:

```sh
git clone --branch main --single-branch https://github.com/Pb-22/zeek-detections.git
git clone --branch main --single-branch https://github.com/Pb-22/Network_Detections.git
cd zeek-detections
```

From that source checkout, resolve the paths before entering a new output directory:

```sh
SOURCE="$PWD/scripts/iodine/main.zeek"
PCAPS="$(dirname "$PWD")/Network_Detections/iodine/pcap"
OUTPUT="$(dirname "$PWD")/iodine-replay"
mkdir -p "$OUTPUT/dns-positive"
cd "$OUTPUT/dns-positive"
zeek -C -r "$PCAPS/iodine-dns-positive-complete-session.pcap" "$SOURCE"
```

`-C` matches the capture checksum handling used during validation. A successful replay produces one `Iodine::CompatibleSession` entry in `notice.log` with this message:

```text
iodine session pattern observed: matched negotiation followed by two way tunnel traffic
```

The `sub` field contains `transport=dns`, `suffix=iodine-lab.test`, `userid=0`, `upstream=Base128`, and `downstream=Raw`, along with version, login and complete body evidence.

## Compare the selected tests

Run each file in a separate output directory. Expected counts apply to `Iodine::CompatibleSession`.

| Capture | Origin | Expected Notices | Check |
| --- | --- | ---: | --- |
| `iodine-dns-positive-complete-session.pcap` | Native | 1 | Complete DNS session |
| `iodine-raw-udp-positive-complete-session.pcap` | Native | 1 | DNS negotiation followed by Raw UDP traffic |
| `iodine-dns-positive-fragmented-session.pcap` | Native | 1 | Seven upstream and five downstream fragments |
| `iodine-dns-negative-negotiation-only.pcap` | Derived control | 0 | Version and login negotiation without tunnel data |
| `iodine-dns-negative-upstream-data-only.pcap` | Derived control | 0 | Upstream data and downstream ACK headers, with downstream data bodies removed |

For example, reuse the resolved `SOURCE`, `PCAPS` and `OUTPUT` variables to test negotiation alone:

```sh
mkdir -p "$OUTPUT/negotiation-control"
cd "$OUTPUT/negotiation-control"
zeek -C -r "$PCAPS/iodine-dns-negative-negotiation-only.pcap" "$SOURCE"
```

The process should complete successfully with zero iodine Notices. Zeek can omit `notice.log` when a run emits no Notices. Check process completion and engine stderr when interpreting that result.

The capture guide includes Wireshark filters and explains the default DNS dissector's display of Raw UDP on port 53. [Capture validation](https://github.com/Pb-22/Network_Detections/blob/main/iodine/validation.json) records exact input hashes, expected and observed results, native versus derived provenance, and the tested source hashes. The captures preserve the reviewed input bytes under descriptive filenames.

## Follow the session evidence

The UDP entry point defaults to port `53/udp`. It adds selected ports to `udp_content_ports` and keeps global all UDP delivery flags unchanged. Packet direction supplies observed client and server addresses and ports.

DNS transaction identity includes both peers, both ports, transaction ID, and a fingerprint of the exact expanded question, type and class. Replies qualify through the answer section, matching question owner, IN class and the appropriate carrier wrapper. The parser handles NULL, private type 65399, TXT, CNAME, MX and SRV payloads. A questions can carry the CNAME wrapper used by iodine.

A version reply assigns a userid to the retained negotiation generation. Login then supplies the advertised tunnel configuration. Negotiated upstream and downstream codecs control later decoding. Four encoded upstream codecs and five downstream codecs are supported by the framing paths. The native upstream captures use Base128; the other upstream codec tests are derived cases.

Each DNS direction retains fragment hashes, lengths, final flags and at most two initial bytes per fragment. A complete packet requires contiguous slots and consistent final metadata. Matching opposite direction ACKs qualify both packets. New inconsistent fragment metadata clears earlier completion before a later ACK can use it.

The session identity keeps observed peers, suffix and assigned userid together. Query bindings also retain the admission epoch. The shared peer scan preserves the original command while examining each possible userid, allowing multiple userids behind the same observed address pair.

The Raw path selects one accepted DNS context for the advertised Raw peer. It retains a fingerprint of the client login body and requires a distinct server body before accepting Raw data. Raw data bodies with accepted size and compressed framing in both directions qualify that transport.

## Keep work and state bounded

| Setting | Default | Work or state bounded |
| --- | --- | --- |
| `pending_limit` / `pending_ttl_seconds` | 1024 / 30 seconds | Retained request bindings and their admission age |
| `candidate_limit` / `candidate_ttl_seconds` | 256 / 30 seconds | Negotiation candidates |
| `session_limit` / `session_idle_seconds` | 256 / 300 seconds | Progressed sessions and retained completion state |
| `max_datagram_bytes` | 8192 | Input size before transport parsing |
| `max_dns_name_bytes` | 255 | Expanded DNS names |
| `max_dns_records` | 16 | Answer, authority and additional records combined |
| `max_dns_pointer_jumps` | 10 | Compressed name traversal |
| `bounded_fragment_slots_per_session` | 32 | Fragment metadata across the two directions |
| `sweep_interval_seconds` | 1 second | Scheduled cleanup interval |

Candidate and pending records carry queue links. Admission and removal update those links directly. Expiry scans the bounded state tables. Separate candidate and progressed session budgets preserve their distinct admission roles.

Pending records keep command metadata and the one codec switch value needed at reply time. Encoded login and fragment bodies stay local to request parsing. Fragment records retain compact evidence rather than full tunnel payloads. Production recognition checks compressed framing and metadata while the offline validation process can reconstruct complete captured bodies.

The module sets the retained session's `done` flag after Notice construction. Later traffic in the same retained generation updates state without emitting that finding again. A later qualifying generation can produce a new Notice after the relevant retained context ends.

## Inspect the output

The literal `sub` template is:

```text
evidence=version,login,data_up,data_down;transport=%s;suffix=%s;userid=%d;upstream=%s;downstream=%s;version=0x00000502;login=%s;up_bytes=%d;down_bytes=%d;up_fragments=%d;down_fragments=%d
```

Arguments follow this order: transport, suffix, userid, upstream codec, downstream codec, advertised login configuration, upstream bytes, downstream bytes, upstream fragments, downstream fragments. The state reader traces each placeholder to its exact source expression. Notice source and destination are observed peers; for Raw traffic the destination uses the accepted advertised Raw peer.

At exit, `IODINE_HEALTH` reports pending, candidate and session peaks and final sizes, degradation, rejected oversized datagrams and queue integrity counters. Interpret these operational counters alongside the capture result.

Recognition requires negotiation and qualifying data to reach the same module instance. Observation completeness, selected ports, retained lifetimes, fragment coverage and ACK visibility determine the evidence available. The Notice describes compatible protocol behavior, including authorized iodine sessions. Throughput, cluster placement and production selectivity require their own environment specific qualification.
