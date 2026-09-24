# M5Unit-NFC

## Overview

Library for Unit-NFC series using [M5UnitUnified](https://github.com/m5stack/M5UnitUnified).  
M5UnitUnified has a unified API and can control multiple units via PaHub, etc.

### SKU:U216

**Unit NFC** is a near-field communication read/write unit operating at 13.56 MHz. The module features the ST25R3916 high-performance NFC front-end IC, supporting mainstream protocols including ISO 14443A, ISO 14443B, FeliCa™, and ISO 15693, enabling reliable read/write operations and data exchange with a wide variety of NFC/RFID tags and cards. The IC supports reader/writer mode, card emulation mode, and custom protocol mode, with automatic antenna tuning, high-sensitivity reception, and comprehensive protocol handling capabilities.

### SKU:U219

**Cap CC1101** is a wireless expansion module for Cardputer-Adv that combines a CC1101 Sub-1 GHz transceiver (315/433/868/915 MHz) and an ST25R3916 NFC front-end, both accessed over SPI. This library supports the NFC part (ST25R3916) only.

## PICC Support

Raw R/W includes FileSystem via ISO-DEP when applicable.  
Support may be expanded in future updates to cover PICCs not listed here.

### NFC-A

| PICC Type | NFC Forum Tag (NDEF) | Detect | Identify | Raw R/W | Notes |
|---|---|---|---|---|---|
| MIFARE Classic Mini | None | Yes | Yes | Yes | Auth required |
| MIFARE Classic 1K | None | Yes | Yes | Yes | Auth required |
| MIFARE Classic 2K | None | Yes | Yes | Yes | Auth required |
| MIFARE Classic 4K | None | Yes | Yes | Yes | Auth required |
| MIFARE Ultralight | Type2 | Yes | Yes | Yes |  |
| MIFARE Ultralight EV1 MF0UL11 | Type2 | Yes | Yes | Yes |  |
| MIFARE Ultralight EV1 MF0UL21 | Type2 | Yes | Yes | Yes |  |
| MIFARE Ultralight Nano | Type2 | Yes | Yes | Yes |  |
| MIFARE Ultralight C | Type2 | Yes | Yes | Yes |  |
| NTAG 203 | Type2 | Yes | Yes | Yes |  |
| NTAG 210u | Type2 | Yes | Yes | Yes |  |
| NTAG 210 | Type2 | Yes | Yes | Yes |  |
| NTAG 212 | Type2 | Yes | Yes | Yes |  |
| NTAG 213 | Type2 | Yes | Yes | Yes |  |
| NTAG 215 | Type2 | Yes | Yes | Yes |  |
| NTAG 216 | Type2 | Yes | Yes | Yes |  |
| ST25TA512B | Type4 | Yes | Yes | Yes | ISO-DEP |
| ST25TA02K | Type4 | Yes | Yes | Yes | ISO-DEP |
| ST25TA16K | Type4 | Yes | Yes | Yes | ISO-DEP |
| ST25TA64K | Type4 | Yes | Yes | Yes | ISO-DEP |
| MIFARE Plus 2K (S/X/EV1/EV2) | None | Yes | Yes | Yes | SL0/SL1/SL3(\*1)|
| MIFARE Plus 4K (S/X/EV1/EV2) | None | Yes | Yes | Yes | SL0/SL1/SL3(\*1)|
| MIFARE Plus SE 1K | None | Yes | Yes | Yes | SL0/SL1/SL3(\*1)|
| MIFARE DESFire 2K (EV1/EV2/EV3) | Type4 | Yes | Yes | Yes | ISO-DEP |
| MIFARE DESFire 4K (EV1/EV2/EV3) | Type4 | Yes | Yes | Yes | ISO-DEP |
| MIFARE DESFire 8K (EV1/EV2/EV3) | Type4 | Yes | Yes | Yes | ISO-DEP |
| MIFARE DESFire Light | Type4 | Yes | Yes | Yes | NDEF is not supported yet |

- \*1 I2C version: MIFARE Plus SL3 operation has issues, SL2 can not R/W.

### NFC-B

| PICC Type | NFC Forum Tag (NDEF) | Detect | Identify | Raw R/W | Notes |
|---|---|---|---|---|---|
| Unclassified | None | Yes | Partial | Yes | ISO-DEP transport only |

### NFC-F

| PICC Type | NFC Forum Tag (NDEF) | Detect | Identify | Raw R/W | Notes |
|---|---|---|---|---|---|
| FeliCa Standard | Type3 | Yes | Yes | Yes |  |
| FeliCa Lite | Type3 | Yes | Yes | Yes |  |
| FeliCa Lite-S | Type3 | Yes | Yes | Yes |  |


### NFC-V

| PICC Type | NFC Forum Tag (NDEF) | Detect | Identify | Raw R/W | Notes |
|---|---|---|---|---|---|
| ICODE SLI | Type5 | Yes | Yes | Yes |  |
| ICODE SLIX | Type5 | Yes | Yes | Yes |  |
| ICODE SLIX2 | Type5 | Yes | Yes | Yes |  |
| Tag-it 2048 | Type5 | Yes | Yes | Yes |  |
| Tag-it HF-I Standard | Type5 | Yes | Yes | Yes |  |
| Tag-it HF-I Plus | Type5 | Yes | Yes | Yes |  |
| Tag-it HF-I Pro | Type5 | Yes | Yes | Yes |  |
| ST25DV | Type5 |  Yes | Yes | Yes |  |

## Emulation

Emulation is supported for NFC-A and NFC-F only.  
See examples: [NFCA Emulation](examples/UnitUnified/NFCA/Emulation) and [NFCF Emulation](examples/UnitUnified/NFCF/Emulation)

## Known Issues

- I2C version: MIFARE Plus SL3 operation has issues.

### NessoN1 Connection
GROVE port (port_b) on NessoN1 uses SoftwareI2C (M5HAL Bus), which causes I2C register polling latency too high for ST25R3916 RF timing requirements.  
Use **QWIIC port (port_a)** with a QWIIC-GROVE conversion cable instead.

> **Note:** GROVE port support may be added in a future update if SoftwareI2C performance improves.

## Related Link

- [Unit NFC & Datasheet](https://docs.m5stack.com/en/products/sku/U216)
- [Cap CC1101 & Datasheet](https://docs.m5stack.com/en/cap/Cap_CC1101)

## Required Libraries

- [M5UnitUnified](https://github.com/m5stack/M5UnitUnified)
- [M5Utility](https://github.com/m5stack/M5Utility)
- [M5HAL](https://github.com/m5stack/M5HAL)

## License

- [M5Unit-NFC - MIT](LICENSE)


## Examples
See also [examples/UnitUnified](examples/UnitUnified)

### For ArduinoIDE settings
Each example contains the following block to select the unit:

```cpp
// For UnitNFC (U216)
// #define USING_UNIT_NFC
// For CapCC1101 (U219)
// #define USING_CAP_CC1101
// For UnitRFID2 (M5Unit-RFID, external)  *NFC-A/B Detect only
// #define USING_UNIT_RFID2
// For M5Dial builtin WS1850S  *NFC-A/B Detect only
// #define USING_M5DIAL_BUILTIN_WS1850S
```

Uncomment one of `USING_UNIT_NFC`, `USING_CAP_CC1101` (or `USING_UNIT_RFID2` / `USING_M5DIAL_BUILTIN_WS1850S` for NFC-A/B Detect):

```cpp
// For UnitNFC (U216)
#define USING_UNIT_NFC
// For CapCC1101 (U219)
// #define USING_CAP_CC1101
// For UnitRFID2 (M5Unit-RFID, external)  *NFC-A/B Detect only
// #define USING_UNIT_RFID2
// For M5Dial builtin WS1850S  *NFC-A/B Detect only
// #define USING_M5DIAL_BUILTIN_WS1850S
```

Some NFC-A examples are shared with [M5Unit-RFID](https://github.com/m5stack/M5Unit-RFID), which is why other unit definitions may exist.

### For ESP-IDF settings

> **NOTE:** The library and examples target ESP-IDF **5.x** (>=5.0).  
> `M5Unified` / `M5GFX` do not yet support ESP-IDF 6.x; stay on the latest 5.x release until upstream support lands.

On ESP-IDF native builds (`idf.py`), the unit/board is selected via Kconfig instead of editing the source `#define`. Each example exposes the same choice through `main/Kconfig.projbuild`, which sources one of the family-specific Kconfig files in `examples/UnitUnified/common/`:

| Kconfig file | Variants offered | Used by |
|---|---|---|
| `Kconfig.variant.full` | UnitNFC / CapCC1101NFC / UnitRFID2 / M5Dial built-in WS1850S | NFC-A Detect / Dump / NDEF / PolicyOverride / ReadWrite / ValueBlock |
| `Kconfig.variant.no_dial` | UnitNFC / CapCC1101NFC / UnitRFID2 | NFC-B Detect / JapanIDCard (M5Dial built-in cannot do NFC-B) |
| `Kconfig.variant.basic` | UnitNFC / CapCC1101NFC | NFC-A Emulation / all NFC-F / all NFC-V (only ST25R3916-based units supported) |

`examples/UnitUnified/common/variant.cmake` then maps the chosen `CONFIG_EXAMPLE_USING_*` to the source-level `USING_*` macro shared with the Arduino build.

Pick the variant with `menuconfig`:

```sh
cd examples/UnitUnified/NFCA/Detect    # or any example
idf.py set-target esp32s3              # or esp32 / esp32c6 / esp32p4 / ...
idf.py menuconfig
# -> M5Unit-NFC example -> Target unit / board -> choose ONE of the options offered
idf.py build flash monitor
```

The selected `CONFIG_EXAMPLE_USING_*` is translated into the Arduino-compatible `USING_*` macro at compile time, so the example source itself does not need to be edited.

## Doxygen document
[GitHub Pages](https://m5stack.github.io/M5Unit-NFC/)

If you want to generate documents on your local machine, execute the following command

```
bash docs/doxy.sh
```

It will output it under docs/html  
If you want to output Git commit hashes to html, do it for the git cloned folder.

### Required
- [Doxygen](https://www.doxygen.nl/)
- [Git](https://git-scm.com/) (Output commit hash to html)
