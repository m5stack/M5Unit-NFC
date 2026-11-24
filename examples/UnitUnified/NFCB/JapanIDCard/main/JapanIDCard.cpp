/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for M5Unit-NFC/RFID
  JapanIDCard example (read Mynumber Ticket Information Input Assistant AP)
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
// NOT SUPPORTED for NFC-B; use UnitRFID2
#endif

#if defined(USING_M5DIAL_BUILTIN_WS1850S)
#error NFC-B is not supported on M5Dial Builtin (small antenna physical limit). \
Use USING_UNIT_RFID2 with external Unit-RFID2 instead.
#endif

#if defined(USING_UNIT_RFID2) || defined(USING_M5DIAL_BUILTIN_WS1850S)
#include <M5UnitUnifiedRFID.h>
#endif

// *************************************************************
// The PIN is never written in this file. Inject it instead:
//   ESP-IDF : idf.py menuconfig -> JapanIDCard -> Card PIN
//   Arduino : build_flags = -DEXAMPLE_JAPANID_PIN="\"1234\""
// A wrong PIN spends one of the card's few retries, and running out of them locks it.
// *************************************************************
#if !defined(ARDUINO)
#if !defined(EXAMPLE_JAPANID_PIN)
#define EXAMPLE_JAPANID_PIN CONFIG_EXAMPLE_JAPANID_PIN
#endif
#endif

#if !defined(EXAMPLE_JAPANID_PIN)
#define EXAMPLE_JAPANID_PIN ""  // Empty: stop before VERIFY instead of spending a retry
#endif

using namespace m5::nfc;
using namespace m5::nfc::b;

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
m5::unit::UnitRFID2 unit{};  // M5Dial builtin WS1850S (internal I2C; NOT supported for NFC-B)
#else
#error Choose ONE: USING_UNIT_NFC / USING_CAP_CC1101 / USING_UNIT_RFID2 / USING_M5DIAL_BUILTIN_WS1850S
#endif
m5::nfc::NFCLayerB nfc_b{unit};

// The screen is the only feedback when no serial monitor is attached, so every stage paints it and
// names itself with the same word the log uses. Black means the round finished, red means it failed.
// TFT_* are RGB565, so the constants are uint16_t: a uint32_t picks the RGB888 overload of
// fillScreen() and paints a different color
constexpr uint16_t COLOR_DETECTED = TFT_DARKGREEN;
constexpr uint16_t COLOR_READ     = TFT_BLUE;
constexpr uint16_t COLOR_DONE     = TFT_BLACK;
constexpr uint16_t COLOR_FAILED   = TFT_RED;
constexpr uint32_t TONE_DETECTED  = 2000;
constexpr uint32_t TONE_DONE      = 4000;
constexpr uint32_t TONE_FAILED    = 300;
constexpr uint32_t TONE_NOTICE    = 1000;

void show_stage(const uint16_t color, const char* stage)
{
    lcd.fillScreen(color);
    lcd.setCursor(0, 0);
    lcd.printf("%s", stage);
}

void show_failure(const char* reason)
{
    show_stage(COLOR_FAILED, reason);
    M5.Speaker.tone(TONE_FAILED, 200);
}

// A card this example cannot work with is not a failure of anything: it gets the idle color and says
// so, with a single mid tone that is neither the success nor the failure one
void show_notice(const char* text)
{
    show_stage(COLOR_DONE, text);
    M5.Speaker.tone(TONE_NOTICE, 50);
}

bool dump()
{
    NFCBFileSystem fs(nfc_b);

    // Mynumber Ticket Information Input Assistant AP
    constexpr uint8_t DF1[] = {0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x08};
    if (!fs.selectByDfName(DF1, sizeof(DF1), m5::nfc::apdu::SelectResponse::FCI)) {
        show_notice("Not a JapanIDCard");
        M5_LOGE("Not JapanIDCard");
        return false;
    }

    constexpr uint8_t EF[] = {0x00, 0x11};
    if (!fs.selectFile(m5::nfc::apdu::SelectBy::EfUnderCurrentDf, m5::nfc::apdu::SelectOccurrence::FirstOrOnly,
                       m5::nfc::apdu::SelectResponse::None, EF, sizeof(EF))) {
        show_failure("FAILED: select EF");
        M5_LOGE("Failed to select EF");
        return false;
    }

    // The PIN comes from menuconfig or build_flags; see the top of this file.
    constexpr char pass[]       = EXAMPLE_JAPANID_PIN;
    constexpr uint16_t pass_len = static_cast<uint16_t>(sizeof(pass) - 1);

    if (pass_len == 0) {
        M5_LOGE(
            "PIN is not set, so VERIFY is skipped. Inject it with menuconfig (ESP-IDF) or "
            "-DEXAMPLE_JAPANID_PIN (Arduino). (Repeated wrong verifies will LOCK the card!)");
        show_notice("PIN is not set, so VERIFY is skipped");
        return false;
    }
    if (!fs.verifyGlobal(reinterpret_cast<const uint8_t*>(pass), pass_len)) {
        show_failure("FAILED: verify");
        M5_LOGE("Failed to verify");
        return false;
    }

    constexpr uint8_t EF2[] = {0x00, 0x02};  // Name etc...
    if (!fs.selectFile(m5::nfc::apdu::SelectBy::EfUnderCurrentDf, m5::nfc::apdu::SelectOccurrence::FirstOrOnly,
                       m5::nfc::apdu::SelectResponse::None, EF2, sizeof(EF2))) {
        show_failure("FAILED: select EF2");
        M5_LOGE("Failed to select EF2");
        return false;
    }

    std::vector<uint8_t> buf;
    show_stage(COLOR_READ, "READ");
    if (!fs.readBinary(buf, 2, 1)) {
        show_failure("FAILED: read the length");
        M5_LOGE("Failed to readBinary");
        return false;
    }
    if (buf.empty()) {
        show_failure("FAILED: empty length");
        M5_LOGE("Empty length response");
        return false;
    }
    const uint8_t file_size = buf[0];
    M5_LOGI("readBinary size = %u", file_size);
    if (!fs.readBinary(buf, 0, file_size)) {
        show_failure("FAILED: read the file");
        M5_LOGE("Failed to readBinary");
        return false;
    }
    m5::utility::log::dump(buf.data(), buf.size(), false);
    show_stage(COLOR_DONE, "OK\n");
    lcd.printf("%u bytes read", file_size);
    M5.Speaker.tone(TONE_DONE, 30);
    return true;
}

}  // namespace

void setup()
{
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);

    // Select NFC-B mode via config() (applied at begin())
    auto cfg = unit.config();
    cfg.mode = NFC::B;
    unit.config(cfg);

    bool unit_ready{};

#if defined(USING_M5DIAL_BUILTIN_WS1850S)
    // Unreachable: gated by #error above.
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

    if (lcd.height() > lcd.width()) {
        lcd.setRotation(1);
    }
    lcd.setFont(&fonts::Font0);
    show_stage(COLOR_DONE, "Please put the PICC and click BtnA");
    M5.Log.printf("Please put the PICC and click BtnA\n");
}

void loop()
{
    M5.update();
    Units.update();

    if (M5.BtnA.wasClicked()) {
        PICC picc{};
        if (nfc_b.select(picc)) {
            show_stage(COLOR_DETECTED, "PICC");
            M5.Speaker.tone(TONE_DETECTED, 30);
            M5.Log.printf("==== PICC %s %s ====\n", picc.pupiAsString().c_str(), picc.typeAsString().c_str());
            dump();  // Paints the outcome itself: every way out of it says what happened
            nfc_b.deactivate();
        } else {
            show_failure("PICC NOT exists");
            M5.Log.printf("PICC NOT exists\n");
        }
        // Printed over the color the round ended on, so the result stays readable while waiting
        lcd.printf("\nPlease put the PICC and click BtnA");
        M5.Log.printf("Please put the PICC and click BtnA\n");
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
