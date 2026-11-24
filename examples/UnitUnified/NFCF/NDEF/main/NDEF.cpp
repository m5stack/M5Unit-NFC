/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916
  Read/write NDEF NFC-F PICC
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
using namespace m5::nfc::ndef;

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
#error Choose ONE: USING_UNIT_NFC / USING_CAP_CC1101
#endif
m5::nfc::NFCLayerF nfc_f{unit};

// The screen is the only feedback when no serial monitor is attached, so every stage paints it and
// names itself with the same word the log uses. Black means the round finished, red means it failed.
// TFT_* are RGB565, so the constants are uint16_t: a uint32_t picks the RGB888 overload of
// fillScreen() and paints a different color
constexpr uint16_t COLOR_DETECTED = TFT_DARKGREEN;
constexpr uint16_t COLOR_READ     = TFT_BLUE;
constexpr uint16_t COLOR_WRITTEN  = TFT_ORANGE;
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

void show_result(const bool ok, const char* reason)
{
    show_stage(ok ? COLOR_DONE : COLOR_FAILED, ok ? "OK" : reason);
    M5.Speaker.tone(ok ? TONE_DONE : TONE_FAILED, ok ? 30 : 200);
}

// A card this example cannot work with is not a failure of anything: it gets the idle color and says
// so, with a single mid tone that is neither the success nor the failure one
void show_notice(const char* text)
{
    show_stage(COLOR_DONE, text);
    M5.Speaker.tone(TONE_NOTICE, 50);
}

// The records the read printed are the point of the round, so the verdict goes under them and the
// screen keeps its contents. A failed read has nothing worth keeping, so that one paints over
void report_read(const bool ok)
{
    if (!ok) {
        show_failure("FAILED: read");
        return;
    }
    lcd.printf("\n-- OK --");
    M5.Speaker.tone(TONE_DONE, 30);
}

bool read_ndef()
{
    TLV msg{};

    // Read NDEF message TLV
    if (!nfc_f.ndefRead(msg)) {
        M5_LOGE("Failed to read");
        return false;
    }

    // If it does not exist, a Null TLV is returned
    if (msg.isMessageTLV()) {
        lcd.setCursor(0, lcd.fontHeight());
        M5.Log.printf("==== NDEF Message %zu records ====\n", msg.records().size());
        for (auto&& r : msg.records()) {
            switch (r.tnf()) {
                case TNF::Wellknown: {
                    const auto payload = r.payloadAsString();
                    M5.Log.printf("SZ:%3u TNF:%u T:%s [%s]\n", r.payloadSize(), r.tnf(), r.type(), payload.c_str());
                    lcd.printf("T:%s [%s]\n", r.type(), payload.c_str());
                } break;
                default:
                    M5.Log.printf("SZ:%3u TNF:%u T:%s\n", r.payloadSize(), r.tnf(), r.type());
                    break;
            }
        }
    } else {
        M5.Log.printf("NDEF Message TLV is NOT exists\n");
    }
    return true;
}

bool write_ndef()
{
    TLV msg{Tag::Message};  // NDEF Message TLV
    Record r[4] = {};       // Wellknown as default

    // *********************************************************
    // Change format to support NDEF
    // *********************************************************
    if (!nfc_f.writeSupportNDEF(true)) {
        show_failure("FAILED: change format");
        M5_LOGE("Failed to writeSupportNDEF");
        return false;
    }

    // URI record
    r[0].setURIPayload("m5stack.com/", URIProtocol::HTTPS);

    // Text record with language type
    const char* en_data = "Hello M5Stack";
    r[1].setTextPayload(en_data, "en");
    const char* ja_data = "こんにちは M5Stack";
    r[2].setTextPayload(ja_data, "ja");
    const char* zh_data = "你好 M5Stack";
    r[3].setTextPayload(zh_data, "zh");

    uint32_t max_user_size = nfc_f.activatedPICC().userAreaSize() - 1 /* terminator TLV */;
    for (auto&& rr : r) {
        msg.push_back(rr);
        if (msg.required() > max_user_size) {
            msg.pop_back();
            break;
        }
    }

    if (!nfc_f.ndefWrite(msg)) {
        show_failure("FAILED: write");
        M5_LOGE("Failed to write");
        return false;
    }
    return nfc_f.dump();
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
    show_stage(COLOR_DONE, "Please put the PICC and click/hold BtnA");
    M5.Log.printf("Please put the PICC and click BtnA\n");
}

void loop()
{
    M5.update();
    Units.update();
    bool clicked = M5.BtnA.wasClicked();  // For read
    bool held    = M5.BtnA.wasHold();     // For write

    if (clicked || held) {
        PICC picc{};
        if (nfc_f.detect(picc)) {
            if (nfc_f.activate(picc)) {
                M5.Log.printf("%s:%s %s F:%02X DF:%04X\n", picc.idmAsString().c_str(), picc.pmmAsString().c_str(),
                              picc.typeAsString().c_str(), picc.format, picc.dfc_format);

                M5.Speaker.tone(TONE_DETECTED, 30);
                if (clicked) {
                    show_stage(COLOR_READ, "READ\n");
                    // nfc_f.dump();
                    report_read(read_ndef());
                } else if (held) {
                    show_stage(COLOR_WRITTEN, "WRITE");
                    show_result(write_ndef(), "FAILED: write");
                }
                M5.Log.printf("Please remove the PICC from the reader\n");
                nfc_f.deactivate();
            } else {
                show_failure("FAILED: activate");
            }
            // Printed over the color the round ended on, so the result stays readable while waiting
            lcd.printf("\nPlease put the PICC and click/hold BtnA");
            M5.Log.printf("Please put the PICC and click/hold BtnA\n");
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
