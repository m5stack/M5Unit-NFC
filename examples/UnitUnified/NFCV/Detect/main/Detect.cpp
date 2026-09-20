/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916
  Detect NFC-V PICC
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedNFC.h>
#include <M5Utility.h>
#include <wiring/m5_unit_unified_wiring.hpp>
#include <vector>

// *************************************************************
// Choose one define symbol to match the unit you are using
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_CAP_CC1101)
// For UnitNFC (U216)
// #define USING_UNIT_NFC
// For CapCC1101 (U219)
// #define USING_CAP_CC1101
#endif

using namespace m5::nfc;
using namespace m5::nfc::v;

namespace {
auto& lcd = M5.Display;
m5::unit::UnitUnified Units;

#if defined(USING_UNIT_NFC)
#pragma message("Choose UnitNFC")
m5::unit::UnitNFC unit{};  // I2C
#elif defined(USING_CAP_CC1101)
#pragma message("Choose CapCC1101NFC")
m5::unit::CapCC1101NFC unit{};  // CapCC1101 (SPI)
#else
#error Choose unit please!
#endif
m5::nfc::NFCLayerV nfc_v{unit};
}  // namespace

void setup()
{
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);

    auto cfg = unit.config();
    cfg.mode = NFC::V;
    unit.config(cfg);

    bool unit_ready{};
#if defined(USING_UNIT_NFC)
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
    lcd.fillScreen(TFT_DARKGREEN);
    lcd.setCursor(0, 0);
}

void loop()
{
    M5.update();
    Units.update();

    std::vector<PICC> piccs;
    if (nfc_v.detect(piccs)) {
        M5.Speaker.tone(3000, 10);
        lcd.fillScreen(0);
        lcd.setCursor(0, 0);
        lcd.printf("%zu PICC\n", piccs.size());
        M5.Log.printf("%zu PICC\n", piccs.size());
        uint32_t idx{};
        for (auto&& u : piccs) {
            M5.Log.printf("PICC:%s %s %u\n", u.uidAsString().c_str(), u.typeAsString().c_str(), u.totalSize());
            lcd.printf("[%2u]:PICC:<%s> %s\n", static_cast<unsigned>(idx), u.uidAsString().c_str(),
                       u.typeAsString().c_str());
            ++idx;
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
