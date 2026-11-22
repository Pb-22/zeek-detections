# Zeek compatibility

## Minimum version

The package requires `zeek >=9.0`. This permits installation on newer releases without pinning one patch version. The tested engines are Zeek 9.0.0 and 9.0.1; the dependency range is not a claim that every future parser has been validated.

Release 1.0.2 removed custom logging while preserving the PKINIT detector's conditions, state handling, notice fields and then PKINIT only loader. Release 1.1.0 retains that detector, eight captures, constructed event fixture, case manifest, runner and historical receipts unchanged. It expands the loader to include four Modbus scripts.

## Tested engines

| Zeek version | Result |
| --- | --- |
| 9.0.0 | All 39 PKINIT replay cases and 15 Modbus integration cases pass; full package suite and real zkg installation pass |
| 9.0.1 | All 39 PKINIT replay cases and 15 Modbus integration cases pass; full package suite and real zkg installation pass |
| 8.0.0 | Detector does not load: required `krb_ap_request` prototype is unavailable |
| 8.0.11 | Detector does not load: required `krb_ap_request` prototype is unavailable |
| 8.2.2 | Detector does not load: required `krb_ap_request` prototype is unavailable |

Each successful replay contains seven authentic lab captures, one derived partial-view positive with an expected visibility-related miss, and 31 constructed event regressions. The positive capture produces one notice and no custom log; the negative and partial-view controls remain silent. Every case verifies that `pkinit_u2u.log` is absent. Package tests also verify the publisher loader's enabled and disabled behavior and the account-only notice subject.

Count-only execution receipts are [validation.json](validation.json) for 9.0.0 and [validation-9.0.1.json](validation-9.0.1.json) for 9.0.1. They bind the same detector, runner, case manifest and event fixture. The CI workflow pins the official images by digest and runs the complete package suite on both versions.

The Modbus scripts have existing standalone acceptance on 8.0.11 and 9.0.1. The collection keeps `zeek >=9.0` for the Kerberos dependency. Current Modbus integration receipts for [9.0.0](modbus-validation-9.0.0.json) and [9.0.1](modbus-validation-9.0.1.json) bind the expanded loader and exact scripts and captures. The four reader captures exercise standalone and collection counts, disabled Modbus selection, native protocol log parity and PKINIT enabled and disabled controls. Real zkg 3.2.0 installation checks dependencies and runs the declared package test command on both engines; the installed runtime contains the loader and five selected scripts.

## Why Zeek 8 is excluded

The detector uses the four-argument event:

```zeek
krb_ap_request(c: connection, ticket: KRB::Ticket,
               opts: KRB::AP_Options, in_kdc_padata: bool)
```

The `in_kdc_padata` flag distinguishes the authenticating AP-REQ inside KDC preauthentication. The detector uses that ticket to link the preceding PKINIT exchange to the later self-targeted U2U request. Removing the flag or substituting the additional ticket would change the detection contract.

Zeek 8's event has only three arguments. Direct loading and replay on 8.0.0, 8.0.11 and 8.2.2 fail with `use of undeclared alternate prototype` and `unknown identifier in_kdc_padata`. This is an API incompatibility, not merely an installation restriction.

Version-specific event declarations:

- [Zeek 8.0.11](https://github.com/zeek/zeek/blob/v8.0.11/src/analyzer/protocol/krb/events.bif)
- [Zeek 8.2.2](https://github.com/zeek/zeek/blob/v8.2.2/src/analyzer/protocol/krb/events.bif)
- [Zeek 9.0.0](https://github.com/zeek/zeek/blob/v9.0.0/src/analyzer/protocol/krb/events.bif)
- [Zeek 9.0.1](https://github.com/zeek/zeek/blob/v9.0.1/src/analyzer/protocol/krb/events.bif)

## Parser checks for newer releases

The inspected [9.0.0](https://github.com/zeek/zeek/blob/v9.0.0/src/analyzer/protocol/krb/krb-protocol.pac) and [9.0.1](https://github.com/zeek/zeek/blob/v9.0.1/src/analyzer/protocol/krb/krb-protocol.pac) sources both map wire `0x8` to `renewable_ok` and wire `0x4` to `enc_tkt_in_skey`. The existing `legacy_zeek9_kdc_bits = T` setting remains correct for those versions. Do not change it based on the field names alone.

Before deploying on another engine, verify that mapping, the required event API, certificate-file event ordering, and all packaged replay cases. A successful package installation establishes dependency acceptance, not running-sensor compatibility or deployment approval.
