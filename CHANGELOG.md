# Changelog

## 1.0.1

- Replaced the exact Zeek 9.0.0 dependency with a Zeek 9.0 minimum.
- Verified Zeek 9.0.1 against all 39 replay cases and the package tests; added it to CI.
- Documented the Kerberos event API requirement that excludes Zeek 8.
- Preserved the detector, publisher loader, capture files and event fixture byte-for-byte.

## 1.0.0

- Established the zkg package and explicit publisher-controlled loader.
- Migrated the PKINIT and linked self-targeted U2U detector without changing its bytes.
- Retained eight capture cases and 31 constructed event regressions.
- Kept the event fixture outside the installed script directory.
