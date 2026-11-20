# Pb-22 Zeek Detections

Zeek detection scripts with an explicit publisher-selected loader, versioned releases, packet evidence and offline regression tests.

## Enabled detection

| Module | Behavior | Tested engine |
| --- | --- | --- |
| [PKINIT/U2U](DETECTOR-GUIDE.md) | Successful PKINIT followed by linked, same-account, self-targeted Kerberos U2U ticket issuance | Zeek 9.0.0 and 9.0.1 |

The detector identifies UnPAC-compatible ticket activity, not proof of NT-hash extraction. Detection conditions are preserved from the accepted Network_Detections version; release 1.0.2 removes its custom log output. The notice subject contains only `principal@realm`; the message describes the observed behavior.

## Notice-only output

The detector emits `PKINIT_U2U::Self_Targeted_Ticket` through Zeek's existing Notice framework. Under the normal logging policy, it appears in `notice.log`. It creates no `pkinit_u2u.log` or other custom log stream. The notice includes the account in `sub`, the behavior in `msg`, and the qualifying TGS connection context. It does not export the former custom record's separate PKINIT connection UID, PKINIT source, service, ticket digest or elapsed-time fields.

When `notice.log` is already forwarded to a SIEM, use its existing notice ingestion and sourcetype; the new notice type is a field value, not a new log format. Confirm the sensor's export and notice policies. Creating a notice does not automatically create a SIEM alert.

[Detection logic and triage](DETECTOR-GUIDE.md) explain ticket linkage, response pairing, parser behavior, state retention and visibility boundaries. The [packet guide](PACKET-GUIDE.md) describes each capture. [Source provenance](PROVENANCE.md) records the migration.

## Install

With Zeek 9.0 or later and its configured package manager:

```sh
zkg install https://github.com/Pb-22/zeek-detections
```

Load installed packages from the normal site policy using `@load packages`, or load this package explicitly with `@load zeek-detections`. Use one route, not both. Apply changes through the sensor platform's supported deployment process. Downloading or installing the package does not establish that a running sensor is using it.

The package declares `zeek >=9.0`. Zeek 9.0.0 and 9.0.1 pass the retained replay and package tests. Zeek 8 is excluded because it lacks the Kerberos event parameter used to identify the authenticating ticket. The minimum version permits newer releases to install; it does not certify untested parser behavior. See [compatibility evidence](COMPATIBILITY.md) before deploying on a newer engine. Related AS and TGS flows must reach the same worker. Ordinary five-tuple balancing does not guarantee that placement.

## Publisher selection and updates

[scripts/__load__.zeek](scripts/__load__.zeek) is the publisher's enabled selection. Only modules loaded there are enabled by the collection. A script's presence in the repository does not enable it. The initial selection contains only PKINIT/U2U.

To enable or disable a module for collection subscribers, change that loader, run acceptance, and publish a newer release tag. Subscribers following releases receive the revised selection when they upgrade and deploy. A pinned version or commit remains pinned. Loading individual scripts separately can bypass the collection selection; subscribers who want publisher-controlled selection should load the package, not additional copies of its modules.

```sh
zkg refresh
zkg upgrade zeek-detections
```

Refresh checks for updates; upgrade installs them. Neither command schedules future updates. Work-lab subscriptions, platform integration, update cadence and running-sensor deployment are separate setup steps.

## Replay evidence

The retained matrix contains seven authentic lab captures, one derived partial-view positive with an expected visibility-related miss, and 31 constructed event regressions. The event fixture is test-only and lives outside `scripts/`; never load it on a sensor.

Tested engines for offline reproduction: Zeek 9.0.0 and 9.0.1, with Python 3.9 or later. From this repository, keep output in a new directory outside the checkout:

```sh
sha256sum --check SHA256SUMS
python3 -B -m unittest discover -s tests -v
python3 -B replay.py --events --output ../zeek-detections-replay
```

[validation.json](validation.json) and [validation-9.0.1.json](validation-9.0.1.json) contain count-only execution results for their named engines, bound to the exact script, runner, case manifest and event-fixture hashes. Receipt schema 2 counts matching notices as `observed` and verifies `custom_log_absent` for every case. CI runs the package tests and all 39 replay cases on both engines using immutable image digests. Tests also exercise the real package loader with PKINIT/U2U enabled and then disabled. Raw logs remain local. Captures retain controlled lab identities, public certificates and encrypted authentication material; they are evidence, not live credentials.

## Other detections

Other Zeek scripts from Network_Detections are being considered individually. They are not included or enabled merely because this collection exists. Test fixtures are not detection modules.

## License

Authored code and documentation use [BSD-3-Clause](LICENSE). See [PROVENANCE.md](PROVENANCE.md) for source and evidence attribution.

## Package manager references

- [Zeek package creation and versioning](https://docs.zeek.org/projects/package-manager/en/stable/package.html)
- [zkg installation, updates and loading](https://docs.zeek.org/projects/package-manager/en/stable/zkg.html)
