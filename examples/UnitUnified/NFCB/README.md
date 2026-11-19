# NFCB Examples shared between M5Unit-NFC and M5Unit-RFID

These examples are shared between [M5Unit-NFC](https://github.com/m5stack/M5Unit-NFC) and [M5Unit-RFID](https://github.com/m5stack/M5Unit-RFID).

**M5Unit-NFC is the primary repository for these examples.**
Modifications should be made in M5Unit-NFC first, then propagated to M5Unit-RFID via [follow_nfc_examples.sh](https://github.com/m5stack/M5Unit-RFID/blob/develop/follow_nfc_examples.sh).

**Do not edit these files directly in the M5Unit-RFID repository.**

## JapanIDCard: the PIN is injected, never written in the source

`JapanIDCard` reads a file the card hands over only after a successful `VERIFY`, so it needs the card's
PIN. `EXAMPLE_JAPANID_PIN` is empty by default and the example then stops before `VERIFY`, which still
leaves the NFC-B activation and the APDU exchange to watch, so the example is worth running without a
PIN as well.

**A wrong PIN spends one of the card's few retries, and running out of them locks the card.**

| Build | How the PIN is handed over | Where the value ends up |
|---|---|---|
| ESP-IDF native (`idf.py`) | `idf.py menuconfig` -> `JapanIDCard` -> `Card PIN` | `sdkconfig`, which git ignores |
| PlatformIO | `build_flags`, see below | `platformio.ini`, which **is** tracked |
| Arduino IDE | `build_opt.h` in the sketch folder, see below | a file of its own, which git does not know about |

PlatformIO:

```ini
build_flags = ${option_release.build_flags}
  -DUSING_UNIT_NFC
  -DEXAMPLE_JAPANID_PIN="\"1234\""
```

Arduino IDE: the ESP32 core hands the compiler whatever a `build_opt.h` next to the sketch holds, one
flag per line, so neither the sketch nor the core settings need an edit. Note that the quotes are
escaped once here, not twice as in `platformio.ini`.

```
-DEXAMPLE_JAPANID_PIN=\"1234\"
```

Of the three, only `platformio.ini` is tracked by git. Prefer `menuconfig` or `build_opt.h` when the PIN
should not reach the working tree at all, and reach for the environment
(`PLATFORMIO_BUILD_FLAGS='-DEXAMPLE_JAPANID_PIN="\"1234\""'`) when PlatformIO is the only option.

> Note: The M5Dial built-in WS1850S is **not supported for NFC-B** (vendor limitation) and is therefore excluded from the unit selection guard in these examples. UnitNFC / CapCC1101NFC (ST25R3916, both I2C and SPI) and the external UnitRFID2 (WS1850S over I2C) are supported.
