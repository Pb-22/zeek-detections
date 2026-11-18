# Zeek compatibility

## Minimum version

The package requires `zeek >=9.0`. This permits installation on newer releases without pinning one patch version. The tested engines are Zeek 9.0.0 and 9.0.1; the dependency range is not a claim that every future parser has been validated.

The detector, publisher loader, eight capture files, case manifest, replay runner and constructed event fixture retain their original bytes in release 1.0.1.

## Tested engines

| Zeek version | Result |
| --- | --- |
| 9.0.0 | All 39 replay cases and 20 package tests pass |
| 9.0.1 | All 39 replay cases and 20 package tests pass |
| 8.0.0 | Detector does not load: required `krb_ap_request` prototype is unavailable |
| 8.0.11 | Detector does not load: required `krb_ap_request` prototype is unavailable |
| 8.2.2 | Detector does not load: required `krb_ap_request` prototype is unavailable |

Each successful replay contains seven authentic lab captures, one derived partial-view positive with an expected visibility-related miss, and 31 constructed event regressions. The positive capture produces one detection and one notice; the negative and partial-view controls remain silent. Package tests also verify the publisher loader's enabled and disabled behavior and the account-only notice subject.

Count-only execution receipts are [validation.json](validation.json) for 9.0.0 and [validation-9.0.1.json](validation-9.0.1.json) for 9.0.1. They bind the same detector, runner, case manifest and event fixture. The CI workflow pins the official images by digest and runs the complete package suite on both versions.

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
