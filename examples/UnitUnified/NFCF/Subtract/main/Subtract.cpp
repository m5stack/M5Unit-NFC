/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916
  Subtract register example for Lite,Lite-S
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
using namespace m5::nfc::f;

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
m5::nfc::NFCLayerF nfc_f{unit};

void subtract_register()
{
    REG reg{};
    if (!nfc_f.read16(reg.reg, lite::REG /* Same as lite_s::REG */)) {
        M5_LOGE("Failed to read");
        return;
    }
    M5.Log.printf("Before:A:%u B:%u C:%llu\n", reg.regA(), reg.regB(), reg.regC());
    nfc_f.dump(lite::REG);

    // Subtract
    reg.regA(reg.regA() - 1);
    reg.regB(reg.regB() - 2);
    reg.regC(reg.regC() - 3);
    if (!nfc_f.write16(lite::REG, reg.reg, sizeof(reg.reg))) {
        M5_LOGE("Failed to write");
        return;
    }
    if (!nfc_f.read16(reg.reg, lite::REG /* Same as lite_s::REG */)) {
        M5_LOGE("Failed to read");
        return;
    }
    M5.Log.printf("After:A:%u B:%u C:%llu\n", reg.regA(), reg.regB(), reg.regC());
    nfc_f.dump(lite::REG);

    // Increases are prohibited (A,B)
    if (!nfc_f.read16(reg.reg, lite::REG /* Same as lite_s::REG */)) {
        M5_LOGE("Failed to read");
        return;
    }

    auto tmp = reg;
    reg.regA(reg.regA() + 1);
    if (!nfc_f.write16(lite::REG, reg.reg, sizeof(reg.reg))) {
        M5.Log.printf("OK) Increases are prohibited %u\n", can_write_reg(tmp, reg));
    } else {
        M5_LOGE("Oops!?");
    }

    reg = tmp;
    reg.regB(reg.regB() + 1);
    if (!nfc_f.write16(lite::REG, reg.reg, sizeof(reg.reg))) {
        M5.Log.printf("OK) Increases are prohibited %u\n", can_write_reg(tmp, reg));
    } else {
        M5_LOGE("Oops!?");
    }

    // RegC can write some value if A>=A' and B>=B'
    reg = tmp;
    reg.regC(0xFFFFFFFFFFFFFFFFull);
    M5.Log.printf("regC can %s write\n", can_write_reg(tmp, reg) ? "" : "NOT");

    if (!nfc_f.write16(lite::REG, reg.reg, sizeof(reg.reg))) {
        M5_LOGE("Failed to write");
    }
    if (!nfc_f.read16(reg.reg, lite::REG /* Same as lite_s::REG */)) {
        M5_LOGE("Failed to read");
        return;
    }
    M5.Log.printf("After:A:%u B:%u C:%llu\n", reg.regA(), reg.regB(), reg.regC());
    nfc_f.dump(lite::REG);
}

}  // namespace

void setup()
{
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);

    auto cfg = unit.config();
    cfg.mode = NFC::F;
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
        if (nfc_f.detect(picc)) {
            M5.Log.printf("%s:%s %s F:%02X DF:%04X\n", picc.idmAsString().c_str(), picc.pmmAsString().c_str(),
                          picc.typeAsString().c_str(), picc.format, picc.dfc_format);
            if (picc.type == Type::FeliCaLite || picc.type == Type::FeliCaLiteS) {
                if (nfc_f.activate(picc)) {
                    M5.Speaker.tone(2500, 20);
                    subtract_register();
                    nfc_f.deactivate();
                }
            } else {
                M5.Log.printf("Not support\n");
            }
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
