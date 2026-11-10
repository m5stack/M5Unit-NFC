# Shared infrastructure for UnitUnified NFC examples

This directory holds the Kconfig and sdkconfig pieces that every example under `examples/UnitUnified/` pulls in. The files are used by both the **Arduino (PlatformIO) build** and the **ESP-IDF native (`idf.py`) build**.

## Files

| File | Used by | Purpose |
|---|---|---|
| `Kconfig.variant.full` | NFC-A non-Emulation examples (Detect / Dump / NDEF / PolicyOverride / ReadWrite / ValueBlock) | menuconfig choice with **4 options**: UnitNFC / CapCC1101NFC / UnitRFID2 / M5Dial built-in WS1850S |
| `Kconfig.variant.no_dial` | NFC-B examples (Detect / JapanIDCard) | menuconfig choice with **3 options** — M5Dial built-in is excluded because it does not support NFC-B |
| `Kconfig.variant.basic` | NFC-A Emulation, all NFC-F examples, all NFC-V examples | menuconfig choice with **2 options** — only ST25R3916-based units (UnitNFC / CapCC1101NFC) support NFC-A Emulation / NFC-F / NFC-V |
| `Kconfig.variant.i2c_hub` | ViaPaHub | menuconfig choice with **2 options** — UnitNFC / UnitRFID2. CapCC1101NFC is SPI and the M5Dial built-in sits on the internal I2C bus, so a PaHub can reach neither |
| `variant.cmake` | All examples | Maps the chosen `CONFIG_EXAMPLE_USING_*` to the source-level `USING_*` macro shared with the Arduino build |
| `sdkconfig.defaults` | All examples | Shared ESP-IDF defaults (CPU 240 MHz, FreeRTOS tick 1 ms, main stack 8 KiB, loop core 1, IDLE1 unwatched, PSRAM `SPIRAM_IGNORE_NOTFOUND`, flash 4 MiB, `TOUCH_SUPPRESS_DEPRECATE_WARN=y` for ESP32 classic) |
| `sdkconfig.defaults.esp32p4` | All examples on esp32p4 target | M5Tab5 (esp32p4 silicon revision v1.0) flash compatibility: `CONFIG_ESP32P4_SELECTS_REV_LESS_V3=y` + `CONFIG_ESP32P4_REV_MIN_0=y` |

## How a per-example `main/CMakeLists.txt` wires this up

Each example's `main/CMakeLists.txt` ends with:

```cmake
include("${CMAKE_CURRENT_LIST_DIR}/../../../common/variant.cmake")
```

and each `main/Kconfig.projbuild` does:

```
rsource "../../../common/Kconfig.variant.<full|no_dial|basic>"
```

Both paths count up from `<family>/<Example>/main/`. An example with no family level is one directory
closer, so `ViaPaHub/main/` uses `../../common/variant.cmake` and
`rsource "../../common/Kconfig.variant.i2c_hub"`.

The top-level `CMakeLists.txt` pins `SDKCONFIG_DEFAULTS` to `common/sdkconfig.defaults`, so the example's own `sdkconfig.defaults` is **not** read. To set additional `CONFIG_*` defaults, modify `common/sdkconfig.defaults` (shared) or use `idf.py menuconfig` (per build).

## Repository sharing

NFC-A and NFC-B examples (which include `Kconfig.variant.full` / `Kconfig.variant.no_dial`) are shared with [M5Unit-RFID](https://github.com/m5stack/M5Unit-RFID). When propagating changes via [follow_nfc_examples.sh](https://github.com/m5stack/M5Unit-RFID/blob/develop/follow_nfc_examples.sh), the relevant files in this directory go with them.

NFC-F / NFC-V / NFC-A Emulation are M5Unit-NFC-only (WS1850S-based units cannot drive these protocols), so `Kconfig.variant.basic` is not used by M5Unit-RFID.

**M5Unit-NFC is the primary repository for these shared files. Modify them here first, then propagate.**
