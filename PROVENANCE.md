# Source provenance

The PKINIT/U2U detector and its evidence originated in [Pb-22/Network_Detections](https://github.com/Pb-22/Network_Detections/tree/5da4490f5f5210e8b75e46fe1a6ee1f7afb8c6f4/Certipy/PKINIT-U2U). The author is Pb-22. This repository is the maintained distribution location.

The original detector, retained unchanged through release 1.0.1, has SHA-256 `335d787262ae1681e3cfd3469062c80a1bc400551e682600fd9258586fb8144f`. Release 1.0.2 removes only its custom log ID, record/event declaration, stream initialization and log write. Detection conditions, correlation state, notice fields and publisher loader are unchanged. The notice-only detector has SHA-256 `1e2a74def6eb7f630a2739b5eea1bab56aad17d8e0d916f4f7f5e085f7902126`.

The event fixture and eight captures retain their original bytes. Only the detector digest changes in the case manifest; every case and expectation is preserved. The replay runner now validates notice-only output. Path references, package tests and documentation reflect those changes. Earlier tags preserve the original detector and validation receipts.

The detector lives in `scripts/pkinit-u2u.zeek`; the event fixture lives in `tests/fixtures/event-regressions.zeek` and is never installed as an enabled module. Original Git history remains in Network_Detections. Current validation is regenerated against the migrated paths.

BSD-3-Clause applies to this repository's authored code and documentation. Packet identities and authentication material are controlled lab evidence, not reusable credentials. External standards and vendor documentation retain their own rights.
