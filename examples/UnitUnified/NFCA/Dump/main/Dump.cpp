/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for M5Unit-NFC/RFID
  Dump NFC-A PICC
  This example is shared with M5Unit-RFID
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedNFC.h>
#include <M5Utility.h>
#include <wiring/m5_unit_unified_wiring.hpp>
#include <vector>

// *************************************************************
// Choose ONE define symbol to match the unit/board you are using
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_CAP_CC1101) && !defined(USING_UNIT_RFID2) && \
    !defined(USING_M5DIAL_BUILTIN_WS1850S)
// For UnitNFC (U216)
// #define USING_UNIT_NFC
// For CapCC1101 (U219)
// #define USING_CAP_CC1101
// For UnitRFID2 (U031-B)
// #define USING_UNIT_RFID2
// For M5Dial Builtin WS1850S (K130)
// #define USING_M5DIAL_BUILTIN_WS1850S
#endif

#if defined(USING_UNIT_RFID2) || defined(USING_M5DIAL_BUILTIN_WS1850S)
#include <M5UnitUnifiedRFID.h>
#endif

using namespace m5::nfc::a;
using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;

namespace {
auto& lcd = M5.Display;
m5::unit::UnitUnified Units;

#if defined(USING_UNIT_NFC)
#pragma message("Choose UnitNFC")
m5::unit::UnitNFC unit{};  // I2C
#elif defined(USING_CAP_CC1101)
#pragma message("Choose CapCC1101NFC")
m5::unit::CapCC1101NFC unit{};  // CapCC1101 (SPI)
#elif defined(USING_UNIT_RFID2)
#pragma message("Choose UnitRFID2")
m5::unit::UnitRFID2 unit{};  // UnitRFID2 external (M5Unit-RFID, GROVE)
#elif defined(USING_M5DIAL_BUILTIN_WS1850S)
#pragma message("Choose UnitRFID2 (M5Dial Builtin)")
m5::unit::UnitRFID2 unit{};  // M5Dial builtin WS1850S (internal I2C)
#else
#error Choose ONE: USING_UNIT_NFC / USING_CAP_CC1101 / USING_UNIT_RFID2 / USING_M5DIAL_BUILTIN_WS1850S
#endif
m5::nfc::NFCLayerA nfc_a{unit};

// KeyA that can authenticate all blocks
// If it's a different key value, change it
constexpr Key keyA = DEFAULT_KEY;  // Default as 0xFFFFFFFFFFFF

// The screen is the only feedback when no serial monitor is attached, so every stage paints it and
// names itself with the same word the log uses. Black means the round finished, red means it failed.
constexpr uint16_t COLOR_DETECTED = TFT_DARKGREEN;
constexpr uint16_t COLOR_READ     = TFT_BLUE;
constexpr uint16_t COLOR_DONE     = TFT_BLACK;
constexpr uint16_t COLOR_FAILED   = TFT_RED;
constexpr uint32_t TONE_DETECTED  = 2000;
constexpr uint32_t TONE_DONE      = 4000;
constexpr uint32_t TONE_FAILED    = 300;

void show_stage(const uint16_t color, const char* stage)
{
    lcd.fillScreen(color);
    lcd.setCursor(0, lcd.height() / 2);
    lcd.printf("%s", stage);
}

void show_failure(const char* reason)
{
    show_stage(COLOR_FAILED, reason);
    M5.Speaker.tone(TONE_FAILED, 200);
}

// The log has scrolled away by the time a whole card is read out, so the screen keeps which PICC it
// was and how big it is. Two beeps instead of one, because the wait is long.
// The sizes are what the PICC reports it holds, NOT how much this dump read off it: dump() answers
// with a bool, and on a file based PICC (DESFire, ST25TA) it walks a set of files whose count and
// total length only reach the log. Reporting the bytes actually read needs a summary from the
// library side and is left for a later version
void show_dumped(const PICC& picc)
{
    show_stage(COLOR_DONE, "OK\n");
    lcd.printf("%s\n%s\ncapacity total %u / user %u bytes\n(not the amount read)", picc.uidAsString().c_str(),
               picc.typeAsString().c_str(), picc.totalSize(), picc.userAreaSize());
    M5.Speaker.tone(TONE_DONE, 60);
    m5::utility::delay(90);
    M5.Speaker.tone(TONE_DONE, 60);
}

void show_prompt()
{
    show_stage(COLOR_DONE, "Please put the PICC and click BtnA");
    M5.Log.printf("Please put the PICC and click BtnA\n");
}
}  // namespace

void setup()
{
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);

    // The screen shall be in landscape mode
    if (lcd.height() > lcd.width()) {
        lcd.setRotation(1);
    }

    bool unit_ready{};

#if defined(USING_M5DIAL_BUILTIN_WS1850S)
    // M5Dial builtin WS1850S: small loop antenna; reduce RxGain to 33dB to mitigate
    // reflection interference (default 48dB causes unstable WUPA on Builtin).
    {
        auto cfg          = unit.config();
        cfg.receiver_gain = m5::unit::mfrc522::ReceiverGain::dB33;
        unit.config(cfg);
    }
    unit_ready = m5::unit::wiring::i2cClass(Units, unit, M5.In_I2C) && Units.begin();

#elif defined(USING_UNIT_NFC) || defined(USING_UNIT_RFID2)
    unit_ready = m5::unit::wiring::addI2C(Units, unit, 0, m5::unit::wiring::NessoPort::PortA) && Units.begin();

#elif defined(USING_CAP_CC1101)
    // SPI mode 1 (CPOL=0, CPHA=1). Use literal so this builds in ESP-IDF native too
    // (Arduino's SPI_MODE1 is not defined there).
    unit_ready = m5::unit::wiring::addSPI(Units, unit, 10000000, 1) && Units.begin();
#endif

    if (!unit_ready) {
        M5_LOGE("Failed to begin");
        m5::unit::wiring::failStop();
    }
    M5_LOGI("M5UnitUnified initialized");
    M5_LOGI("%s", Units.debugInfo().c_str());

    lcd.setFont(&fonts::Font0);
    show_prompt();
}

void loop()
{
    M5.update();
    Units.update();

    if (M5.BtnA.wasClicked()) {
        PICC picc{};
        if (nfc_a.detect(picc)) {
            if (nfc_a.identify(picc) && nfc_a.reactivate(picc)) {
                // Green only once a PICC has been found and named, so a click into empty air does not
                // paint the color that means a card is there
                show_stage(COLOR_DETECTED, "");
                M5.Speaker.tone(TONE_DETECTED, 30);
                lcd.printf("%s\n%s", picc.uidAsString().c_str(), picc.typeAsString().c_str());
                M5.Log.printf("==== Dump %s %s %u/%u ====\n", picc.uidAsString().c_str(), picc.typeAsString().c_str(),
                              picc.userAreaSize(), picc.totalSize());
                // A whole card takes seconds to read out, so the reading stage gets its own color and
                // the screen only turns black once every block has been read
                show_stage(COLOR_READ, "READ");
                const bool ok = nfc_a.dump(keyA);  // Need key if MIFARE classic, Ignore key if not MIFARE classic
                if (!ok) {
                    // A dump that reported a failure names itself. Looking for the PICC here would
                    // only mislead: a failed MIFARE Plus SL3 authentication leaves the session in a
                    // state where the PICC cannot be activated again either
                    show_failure("FAILED: dump");
                } else if (!nfc_a.reactivate(picc)) {
                    // On a file based PICC (DESFire, ST25TA) dump() carries on past a file it could
                    // not read and still answers true, so a card taken away in the middle of the walk
                    // would look like a finished run. The PICC being gone is what gives it away
                    show_failure("FAILED: PICC was removed");
                } else {
                    show_dumped(picc);
                }
                nfc_a.deactivate();
            } else {
                show_failure("FAILED: identify");
                M5_LOGE("Failed to identify/activate %s", picc.uidAsString().c_str());
            }
        } else {
            show_failure("PICC NOT exists");
            M5.Log.printf("PICC NOT exists\n");
        }
    }
}

#if !defined(ARDUINO)
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_timer.h>

#if CONFIG_FREERTOS_UNICORE
// Single-core SoCs: run loop() back-to-back, but every ~2 s yield a 5 ms slice so the IDLE task
// runs and feeds the task watchdog (default 5 s).
static inline void feedIdleTaskPeriodically(void)
{
    constexpr uint32_t FEED_INTERVAL_MS   = 2000;
    constexpr TickType_t FEED_SLEEP_TICKS = pdMS_TO_TICKS(5);
    static uint32_t s_last_feed_ms        = 0;
    const uint32_t now_ms                 = static_cast<uint32_t>(esp_timer_get_time() / 1000);
    if (m5::utility::hasElapsed(s_last_feed_ms, FEED_INTERVAL_MS, now_ms)) {
        s_last_feed_ms = now_ms;
        vTaskDelay(FEED_SLEEP_TICKS);
    }
}
#endif

extern "C" void app_main(void)
{
    setup();
    for (;;) {
#if CONFIG_FREERTOS_UNICORE
        feedIdleTaskPeriodically();
#endif
        loop();
    }
}
#endif
