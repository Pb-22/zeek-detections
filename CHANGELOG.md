# Changelog

## 1.1.0

- Added the four accepted Modbus register write rejection scripts with their exact source bytes.
- Selected all four modules beside unchanged PKINIT/U2U in the publisher loader.
- Added four compact constructed reader captures, explicit per notice expectations and a portable 15 case integration runner.
- Verified standard Notice actions, zero suppression, native Modbus logs, disabled selections and PKINIT controls on Zeek 9.0.0 and 9.0.1.
- Preserved the Zeek 9.0 minimum, historical tags and every PKINIT replay input and receipt.

## 1.0.2

- Removed the custom `pkinit_u2u.log` stream and record; output uses the existing Notice framework only.
- Preserved all detection conditions, state handling, notice fields and publisher selection.
- Updated replay receipt schema to 2: `observed` counts matching notices and every case requires `custom_log_absent`.
- Regenerated both engine receipts and added a regression that rejects even an empty custom log.
- Preserved all eight captures, 31 constructed event cases and their expected notice counts.

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
