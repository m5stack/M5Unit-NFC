# M5Unit-NFC

## Overview

Library for Unit-NFC series using [M5UnitUnified](https://github.com/m5stack/M5UnitUnified).  
M5UnitUnfied has a unified API and can control multiple units via PaHub, etc.

### SKU:xxx

Description of the product


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


## Emulation

Emulation is supported for NFC-A and NFC-F only.  
See examples: [NFCA Emulation](examples/UnitUnified/NFCA/Emulation) and [NFCF Emulation](examples/UnitUnified/NFCF/Emulation)

## Known Issues

- I2C version: MIFARE Plus SL3 operation has issues.


## Related Link

- [Unit NFC & Datasheet](https://docs.m5stack.com/en/----------)
- [CapHacker & Datasheet](https://docs.m5stack.com/en/---------)

## Required Libraries:

- [M5UnitUnified](https://github.com/m5stack/M5UnitUnified)
- [M5Utility](https://github.com/m5stack/M5Utility)
- [M5HAL](https://github.com/m5stack/M5HAL)

## License

- [M5Unit-NFC -MIT](LICENSE)


## Examples
See also [examples/UnitUnified](examples/UnitUnified)

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
