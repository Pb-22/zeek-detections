# Modbus register write rejections

Four scripts report Modbus responder exceptions for FC06, Write Single Register, and FC16, Write Multiple Registers. FC16 is decimal 16 (`0x10`). The package loader enables all four beside PKINIT/U2U.

## Reasons and notice types

| Reason | Official name | Notice type |
| --- | --- | --- |
| `01` | Illegal Function | `ModbusWriteRejection::Register_Write_Illegal_Function` |
| `02` | Illegal Data Address | `ModbusWriteRejection::Register_Write_Illegal_Data_Address` |
| `03` | Illegal Data Value | `ModbusWriteRejection::Register_Write_Illegal_Data_Value` |
| `04` | Server Device Failure | `ModbusWriteRejection::Register_Write_Server_Device_Failure` |

Illegal Function reports that the function is unavailable for the device's current operation. Illegal Data Address reports an unavailable address or address and quantity combination. Illegal Data Value concerns a request field or structure, such as an FC16 quantity and byte count inconsistency. Application context supplies the meaning and intended range of register contents. Server Device Failure reports an unrecoverable device error while attempting the requested action.

These names and meanings follow section 7 of the [MODBUS Application Protocol Specification V1.1b3](https://modbus.org/file/secure/modbusprotocolspecification.pdf). Each notice records the responder's reported rejection. The corresponding request and device records establish its cause and operational effect.

## Inputs and matching

Each script handles the native `modbus_exception` event after TCP stream reassembly. The inspected analyzers dispatch exception responses on the responder branch and retain the raw exception function code. The stateless guard requires protocol ID `0`, MBAP length `3`, exception function `0x86` or `0x90`, and the script's selected reason. Length 3 counts the unit ID, function code and exception code. Explicit length checking preserves this boundary even when an analyzer accepts a longer exception body.

The event supplies the response header and reason. Matching works with response visibility alone; request correlation is a separate analysis step. Parsed application messages each produce a notice, including repeated messages and reused transaction IDs. TCP retransmission handling remains with Zeek's stream analyzer.

## Output and investigation

Output uses standard `notice.log`, `Notice::ACTION_LOG` and `0secs` suppression. Native Modbus logging stays enabled. The scripts use the existing Notice framework and protocol streams.

`msg` names the rejected function and official reason. `sub` contains `transaction_id`, `unit_id`, `function_code`, `exception_code`, `protocol_id` and `mbap_length`. The function in these fields is decimal 6 or 16. Standard connection fields identify the client and responding device.

Use the connection, transaction ID and unit ID to find the request and reply in the capture. Compare the requested function, address, quantity and byte count with the device's documented capabilities. Review device diagnostics for Server Device Failure. Correlate repeated rejections with the client's polling or write schedule and approved maintenance activity.

## Standalone examples

With a local Zeek executable, run these examples from the repository root. Each command creates a fresh sibling directory for logs. Each script on its own named capture produces two matching notices and zero other collection notices.

```sh
repo="$PWD"
mkdir ../modbus-function-replay
(cd ../modbus-function-replay && zeek -Cr "$repo/pcap/modbus/Register_Write_Illegal_Function__combined_positive_negative__expected_2_notices.pcap" "$repo/scripts/modbus-write-illegal-function.zeek")

mkdir ../modbus-address-replay
(cd ../modbus-address-replay && zeek -Cr "$repo/pcap/modbus/Register_Write_Illegal_Data_Address__combined_positive_negative__expected_2_notices.pcap" "$repo/scripts/modbus-write-illegal-data-address.zeek")

mkdir ../modbus-value-replay
(cd ../modbus-value-replay && zeek -Cr "$repo/pcap/modbus/Register_Write_Illegal_Data_Value__combined_positive_negative__expected_2_notices.pcap" "$repo/scripts/modbus-write-illegal-data-value.zeek")

mkdir ../modbus-failure-replay
(cd ../modbus-failure-replay && zeek -Cr "$repo/pcap/modbus/Register_Write_Server_Device_Failure__combined_positive_negative__expected_2_notices.pcap" "$repo/scripts/modbus-write-server-device-failure.zeek")
```

Standalone script acceptance already covers Zeek 8.0.11 and 9.0.1. The collection requires Zeek 9.0 or later because PKINIT/U2U needs its Kerberos event API. Collection integration and installed package acceptance cover 9.0.0 and 9.0.1. See [COMPATIBILITY.md](COMPATIBILITY.md).

## Collection replay

From the repository root:

```sh
python3 -B modbus_replay.py --output ../modbus-collection-replay
```

| Option | Meaning |
| --- | --- |
| `--zeek PATH` | Local executable, default `zeek` |
| `--output DIRECTORY` | Required new directory outside the checkout for logs and `receipt.json` |
| `--help` | Print command help |

The standard library runner validates script, publisher loader and capture hashes before starting Zeek. It runs 15 cases: four standalone captures, four captures through the actual package loader, four Modbus disabled selections, and PKINIT positive, negative and disabled controls. It validates complete notice type count maps, notice fields, actions, suppression and native Modbus log parity. Its receipt contains counts, hashes and pass results; raw logs stay in the requested output directory.

The compact captures are constructed protocol fixtures with matching and quiet exchanges. Their names describe standalone expectations. With all five modules loaded, the actual profiles are:

| Capture name prefix | Reason 01 | Reason 02 | Reason 03 | Reason 04 | PKINIT/U2U |
| --- | ---: | ---: | ---: | ---: | ---: |
| `Register_Write_Illegal_Function` | 2 | 2 | 1 | 0 | 0 |
| `Register_Write_Illegal_Data_Address` | 2 | 2 | 1 | 0 | 0 |
| `Register_Write_Illegal_Data_Value` | 2 | 2 | 2 | 2 | 0 |
| `Register_Write_Server_Device_Failure` | 2 | 2 | 2 | 2 | 0 |

The first two filenames contain identical original mixed capture bytes. [modbus-cases.json](modbus-cases.json) records each filename, hash and explicit expected notice map. [modbus-validation-9.0.0.json](modbus-validation-9.0.0.json) and [modbus-validation-9.0.1.json](modbus-validation-9.0.1.json) retain sanitized execution receipts. [PROVENANCE.md](PROVENANCE.md) binds the exact source commit and script bytes.
