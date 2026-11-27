# Try a PCAP first

Download a capture and inspect or replay it before using the optional fixture
generators. Each link below opens a ready file. Expected counts apply to the
named detector on stock Zeek 9.0.1; use a separate output directory for each run.

| Detector | First PCAP | Expected Notices | Source and instructions |
|---|---|---:|---|
| PKINIT/U2U | [Linked ticket exchange](https://raw.githubusercontent.com/Pb-22/Network_Detections/main/Certipy/PKINIT-U2U/pcap/positive-pkinit-u2u.pcap) | 1 | [Detector guide](DETECTOR-GUIDE.md) |
| Modbus Illegal Function | [Combined case](https://raw.githubusercontent.com/Pb-22/Network_Detections/main/modbus/write%20errors/pcap/Register_Write_Illegal_Function__combined_positive_negative__expected_2_notices.pcap) | 2 | [Modbus guide](MODBUS-WRITE-REJECTIONS.md) |
| Modbus Illegal Data Address | [Combined case](https://raw.githubusercontent.com/Pb-22/Network_Detections/main/modbus/write%20errors/pcap/Register_Write_Illegal_Data_Address__combined_positive_negative__expected_2_notices.pcap) | 2 | [Modbus guide](MODBUS-WRITE-REJECTIONS.md) |
| Modbus Illegal Data Value | [Combined case](https://raw.githubusercontent.com/Pb-22/Network_Detections/main/modbus/write%20errors/pcap/Register_Write_Illegal_Data_Value__combined_positive_negative__expected_2_notices.pcap) | 2 | [Modbus guide](MODBUS-WRITE-REJECTIONS.md) |
| Modbus Server Device Failure | [Combined case](https://raw.githubusercontent.com/Pb-22/Network_Detections/main/modbus/write%20errors/pcap/Register_Write_Server_Device_Failure__combined_positive_negative__expected_2_notices.pcap) | 2 | [Modbus guide](MODBUS-WRITE-REJECTIONS.md) |
| dnscat2 | [TXT session](https://raw.githubusercontent.com/Pb-22/Network_Detections/main/dnscat2/pcap/dnscat2-txt-positive-complete-session.pcap) | 1 | [dnscat2 guide](docs/dnscat2.md) |
| iodine | [Complete DNS session](https://raw.githubusercontent.com/Pb-22/Network_Detections/main/iodine/pcap/iodine-dns-positive-complete-session.pcap) | 1 | [iodine guide](docs/iodine.md) |

## Replay directly

With Zeek installed, select the relevant script explicitly. From a source
checkout, this example runs the PKINIT capture already included in pcap/:

```sh
repo="$PWD"
mkdir -p ../pkinit-replay
(cd ../pkinit-replay && zeek -C -r "$repo/pcap/positive-pkinit-u2u.pcap" "$repo/scripts/pkinit-u2u.zeek")
```

The finding appears in notice.log. The detector guides give its fields and
visibility limits. A capture can also be opened in Wireshark before any detector
runs. The reproducible generators and automated regression runners remain
available as secondary engineering tools.

The PKINIT and iodine examples use captured lab traffic. Modbus examples are
constructed test exchanges. The dnscat2 files are derivatives of native lab
captures with documented replacement of outer endpoint addresses. Keep these
origins distinct when describing the result.

The release loader still selects PKINIT/U2U and the four Modbus detections.
Iodine and dnscat2 require explicit selection from main. Downloading a PCAP does
not change a sensor's loaded scripts.
