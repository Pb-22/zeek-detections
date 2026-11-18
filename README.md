# Pb-22 Zeek Detections

Zeek detection scripts with an explicit publisher-selected loader, versioned releases, packet evidence and offline regression tests.

## Enabled detection

| Module | Behavior | Tested engine |
| --- | --- | --- |
| [PKINIT/U2U](DETECTOR-GUIDE.md) | Successful PKINIT followed by linked, same-account, self-targeted Kerberos U2U ticket issuance | Zeek 9.0.0 |

The detector identifies UnPAC-compatible ticket activity, not proof of NT-hash extraction. Its source is unchanged from the accepted Network_Detections version. The notice subject contains only `principal@realm`; the message describes the observed behavior.

[Detection logic and triage](DETECTOR-GUIDE.md) explain ticket linkage, response pairing, parser behavior, state retention and visibility boundaries. The [packet guide](PACKET-GUIDE.md) describes each capture. [Source provenance](PROVENANCE.md) records the migration.

## Install

With Zeek 9.0.0 and its configured package manager:

```sh
zkg install https://github.com/Pb-22/zeek-detections
```

Load installed packages from the normal site policy using `@load packages`, or load this package explicitly with `@load zeek-detections`. Use one route, not both. Apply changes through the sensor platform's supported deployment process. Downloading or installing the package does not establish that a running sensor is using it.

The package currently declares the exact tested Zeek version, `9.0.0`. Its Kerberos parser bit mapping is significant; do not loosen that dependency without replay and parser checks. Related AS and TGS flows must reach the same worker. Ordinary five-tuple balancing does not guarantee that placement.

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

Requirements for offline reproduction: Zeek 9.0.0 and Python 3.9 or later. From this repository, keep output in a new directory outside the checkout:

```sh
sha256sum --check SHA256SUMS
python3 -B -m unittest discover -s tests -v
python3 -B replay.py --events --output ../zeek-detections-replay
```

[validation.json](validation.json) contains count-only execution results bound to the exact script, runner, case manifest and event-fixture hashes. Tests also exercise the real package loader with PKINIT/U2U enabled and then disabled. Raw logs remain local. Captures retain controlled lab identities, public certificates and encrypted authentication material; they are evidence, not live credentials.

## Other detections

Other Zeek scripts from Network_Detections are being considered individually. They are not included or enabled merely because this collection exists. Test fixtures are not detection modules.

## License

Authored code and documentation use [BSD-3-Clause](LICENSE). See [PROVENANCE.md](PROVENANCE.md) for source and evidence attribution.

## Package manager references

- [Zeek package creation and versioning](https://docs.zeek.org/projects/package-manager/en/stable/package.html)
- [zkg installation, updates and loading](https://docs.zeek.org/projects/package-manager/en/stable/zkg.html)
