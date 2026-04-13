# M5Unit-NFC

## Overview

Library for Unit-NFC series using [M5UnitUnified](https://github.com/m5stack/M5UnitUnified).  
M5UnitUnified has a unified API and can control multiple units via PaHub, etc.

### SKU:U216

Unit NFC is a near-field communication (NFC) read/write unit based on a 13.56MHz frequency. It integrates the high-performance ST25R3916 NFC front-end chip, supporting NFC-A, NFC-B, NFC-F, and NFC-V standards, enabling read/write and communication functions for various NFC/RFID tags and cards. The chip supports reader mode, card emulation mode, and point-to-point communication mode, featuring automatic antenna tuning, high-sensitivity reception, and comprehensive protocol processing capabilities. This unit communicates with the host device via an I2C interface, providing stable data transmission performance. The product adopts a LEGO-compatible hole design, facilitating integration into creative structures or screw mounting, and is suitable for various applications requiring near-field communication and information verification, such as access control systems, identity recognition, intelligent transportation, and smart bookshelves.

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


## Related Link

- [Unit NFC & Datasheet](https://docs.m5stack.com/en/products/sku/U216)

## Required Libraries

- [M5UnitUnified](https://github.com/m5stack/M5UnitUnified)
- [M5Utility](https://github.com/m5stack/M5Utility)
- [M5HAL](https://github.com/m5stack/M5HAL)

## License

- [M5Unit-NFC - MIT](LICENSE)


## Examples
See also [examples/UnitUnified](examples/UnitUnified)

### For ArduinoIDE
Each example contains the following block to select the unit:

```cpp
// For UnitNFC
// #define USING_UNIT_NFC
// For CapCC1101
// #define USING_CAP_CC1101
```

Uncomment `USING_UNIT_NFC` or `USING_CAP_CC1101`:

```cpp
#define USING_UNIT_NFC
// #define USING_CAP_CC1101
```

**Note:** CapCC1101 / SKU:U219 (SPI connection via ST25R3916) is included in this library for future use.
The product is not yet publicly available.

Some NFC-A examples are shared with [M5Unit-RFID](https://github.com/m5stack/M5Unit-RFID), which is why other unit definitions may exist.

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
- [pcregrep](https://formulae.brew.sh/formula/pcre2)
- [Git](https://git-scm.com/) (Output commit hash to html)
