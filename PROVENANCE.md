# Source provenance

The PKINIT/U2U detector and its evidence originated in [Pb-22/Network_Detections](https://github.com/Pb-22/Network_Detections/tree/5da4490f5f5210e8b75e46fe1a6ee1f7afb8c6f4/Certipy/PKINIT-U2U). The author is Pb-22. This repository is the maintained distribution location.

The original detector, retained unchanged through release 1.0.1, has SHA-256 `335d787262ae1681e3cfd3469062c80a1bc400551e682600fd9258586fb8144f`. Release 1.0.2 removes only its custom log ID, record/event declaration, stream initialization and log write. That release preserved detection conditions, correlation state, notice fields and the then PKINIT only publisher loader. The notice-only detector has SHA-256 `1e2a74def6eb7f630a2739b5eea1bab56aad17d8e0d916f4f7f5e085f7902126`.

The event fixture and eight captures retain their original bytes. Only the detector digest changes in the case manifest; every case and expectation is preserved. The replay runner now validates notice-only output. Path references, package tests and documentation reflect those changes. Earlier tags preserve the original detector and validation receipts.

The detector lives in `scripts/pkinit-u2u.zeek`; the event fixture lives in `tests/fixtures/event-regressions.zeek` and is never installed as an enabled module. Original Git history remains in Network_Detections. Release 1.1.0 preserves the PKINIT script, case manifest, runner, event fixture, eight captures and both 39 case receipts exactly as published in release 1.0.2.

## Modbus register write rejection scripts

Release 1.1.0 copies four approved scripts and four compact constructed captures from [Network_Detections at commit 894fc1ca71c0fed27cc7067799967a9cdbc6288d](https://github.com/Pb-22/Network_Detections/tree/894fc1ca71c0fed27cc7067799967a9cdbc6288d/modbus/write%20errors). Pb-22 authored these scripts. Each source script is under `zeek/write_rejections/Register_Write_<reason>/`; original reader captures are under `pcap/`. [modbus-cases.json](modbus-cases.json) records the complete original paths, exact SHA256 values and explicit integration expectations. The scripts and captures retain their approved bytes. The publisher loader adds all four modules beside PKINIT/U2U.

| Current script | SHA256 |
| --- | --- |
| `scripts/modbus-write-illegal-function.zeek` | `0de1f7dfc921292c1e90a75514cc6a58ade774d768ab7cf9b3143371253c2fbb` |
| `scripts/modbus-write-illegal-data-address.zeek` | `6fbbf3254a46c3af160189a8f96720f71f247a177089a5f48816f82d9ac3e54a` |
| `scripts/modbus-write-illegal-data-value.zeek` | `ff343f54fd21192e380d08a7161ea989ca2c5e30cc8bdbae0055135846c92e5b` |
| `scripts/modbus-write-server-device-failure.zeek` | `8d35a1479a789cb9a5c37155c0a1d03b6bc7c8e36b33ac4d68ab4fbfb7ce5bf3` |

The original source READMEs record standalone acceptance on Zeek 8.0.11 and 9.0.1, including the protocol boundary matrix. This release adds collection and installed loader acceptance on 9.0.0 and 9.0.1. All original captures and source manifests remain in Network_Detections. The four approved reader copies make this package's offline integration tests self contained. Earlier release tags preserve the PKINIT only collection.

## iodine session module

The iodine module preserves the reviewed three file Zeek implementation under `scripts/iodine/`. Its wire framing reference is the ISC licensed [iodine source at commit 7160bbe1c98c74bf34a8b97ed8c1540950ebb243](https://github.com/yarrick/iodine/tree/7160bbe1c98c74bf34a8b97ed8c1540950ebb243). Native captures came from controlled iodine sessions. The selected captures and derived control transformations are recorded in [Network_Detections/iodine](https://github.com/Pb-22/Network_Detections/tree/f06a5004bbb529d4444ef1105238f9aed8f10577/iodine).

`main.zeek`, `state.zeek` and `wire.zeek` retain their accepted SHA256 values in the capture validation record and this repository's checksum manifest. Repository publication keeps the source logic and current publisher loader unchanged. [The iodine guide](docs/iodine.md) distinguishes standalone source availability, the selected capture tests and observation requirements.

BSD-3-Clause applies to this repository's authored code and documentation. Packet identities and authentication material are controlled lab evidence, not reusable credentials. External standards and vendor documentation retain their own rights.
