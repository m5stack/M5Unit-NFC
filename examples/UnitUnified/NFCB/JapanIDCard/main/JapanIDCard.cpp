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

void dump()
{
    NFCBFileSystem fs(nfc_b);

    // Mynumber Ticket Information Input Assistant AP
    constexpr uint8_t DF1[] = {0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x08};
    if (!fs.selectByDfName(DF1, sizeof(DF1), m5::nfc::apdu::SelectResponse::FCI)) {
        M5_LOGE("Not JapanIDCard");
        return;
    }

    constexpr uint8_t EF[] = {0x00, 0x11};
    if (!fs.selectFile(m5::nfc::apdu::SelectBy::EfUnderCurrentDf, m5::nfc::apdu::SelectOccurrence::FirstOrOnly,
                       m5::nfc::apdu::SelectResponse::None, EF, sizeof(EF))) {
        M5_LOGE("Failed to select EF");
        return;
    }

    // ********************************************
    // Password (YOU MUST CHANGE IT!) as string
    constexpr char pass[] = "XXXX";
    // ********************************************

    if (strcmp(pass, "XXXX") == 0) {
        M5_LOGE(
            "PIN is placeholder \"XXXX\". Edit the source before running. (Repeated wrong verifies will LOCK the "
            "card!)");
        return;
    }
    if (!fs.verifyGlobal(reinterpret_cast<const uint8_t*>(pass), 4)) {
        M5_LOGE("Failed to verify");
        return;
    }

    constexpr uint8_t EF2[] = {0x00, 0x02};  // Name etc...
    if (!fs.selectFile(m5::nfc::apdu::SelectBy::EfUnderCurrentDf, m5::nfc::apdu::SelectOccurrence::FirstOrOnly,
                       m5::nfc::apdu::SelectResponse::None, EF2, sizeof(EF2))) {
        M5_LOGE("Failed to select EF2");
        return;
    }

    std::vector<uint8_t> buf;
    if (!fs.readBinary(buf, 2, 1)) {
        M5_LOGE("Failed to readBinary");
        return;
    }
    if (buf.empty()) {
        M5_LOGE("Empty length response");
        return;
    }
    const uint8_t file_size = buf[0];
    M5_LOGI("readBinary size = %u", file_size);
    if (!fs.readBinary(buf, 0, file_size)) {
        M5_LOGE("Failed to readBinary");
        return;
    }
    m5::utility::log::dump(buf.data(), buf.size(), false);
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
    lcd.fillScreen(0);
    lcd.setCursor(0, 0);
    lcd.printf("Please put the PICC and click BtnA");
    M5.Log.printf("Please put the PICC and click BtnA\n");
}

void loop()
{
    M5.update();
    Units.update();

    if (M5.BtnA.wasClicked()) {
        lcd.fillRect(0, lcd.fontHeight(), lcd.width(), lcd.height() - lcd.fontHeight());
        PICC picc{};
        if (nfc_b.select(picc)) {
            M5.Speaker.tone(3000, 20);
            M5.Log.printf("==== PICC %s %s ====\n", picc.pupiAsString().c_str(), picc.typeAsString().c_str());
            dump();
            nfc_b.deactivate();
        } else {
            M5.Log.printf("PICC NOT exists\n");
        }
    }
}

#if !defined(ARDUINO)
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_timer.h>

#if CONFIG_FREERTOS_UNICORE
static inline void feedIdleTaskPeriodically(void)
{
    constexpr uint32_t FEED_INTERVAL_MS   = 2000;
    constexpr TickType_t FEED_SLEEP_TICKS = pdMS_TO_TICKS(5);
    static uint32_t s_next_feed_ms        = 0;
    const uint32_t now_ms                 = static_cast<uint32_t>(esp_timer_get_time() / 1000);
    if (now_ms >= s_next_feed_ms) {
        s_next_feed_ms = now_ms + FEED_INTERVAL_MS;
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
