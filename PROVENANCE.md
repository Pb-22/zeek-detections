# Source provenance

The PKINIT/U2U detector and its evidence originated in [Pb-22/Network_Detections](https://github.com/Pb-22/Network_Detections/tree/5da4490f5f5210e8b75e46fe1a6ee1f7afb8c6f4/Certipy/PKINIT-U2U). The author is Pb-22. This repository is the maintained distribution location.

The detector is byte-identical to the accepted source: SHA-256 `335d787262ae1681e3cfd3469062c80a1bc400551e682600fd9258586fb8144f`. The event fixture, replay runner and eight captures also retain their original bytes. Path references, package tests and documentation reflect the new layout.

The detector lives in `scripts/pkinit-u2u.zeek`; the event fixture lives in `tests/fixtures/event-regressions.zeek` and is never installed as an enabled module. Original Git history remains in Network_Detections. Current validation is regenerated against the migrated paths.

BSD-3-Clause applies to this repository's authored code and documentation. Packet identities and authentication material are controlled lab evidence, not reusable credentials. External standards and vendor documentation retain their own rights.
