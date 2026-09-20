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
#error Choose unit please!
#endif
m5::nfc::NFCLayerF nfc_f{unit};

void read_ndef()
{
    TLV msg{};

    // Read NDEF message TLV
    if (!nfc_f.ndefRead(msg)) {
        M5_LOGE("Failed to read");
        lcd.fillScreen(TFT_RED);
        return;
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
}

void write_ndef()
{
    TLV msg{Tag::Message};  // NDEF Message TLV
    Record r[4] = {};       // Wellknown as default

    // *********************************************************
    // Change format to support NDEF
    // *********************************************************
    if (!nfc_f.writeSupportNDEF(true)) {
        M5_LOGE("Failed to writeSupportNDEF");
        return;
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
        M5_LOGE("Failed to write");
        return;
    }
    nfc_f.dump();
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
    bool clicked = M5.BtnA.wasClicked();  // For read
    bool held    = M5.BtnA.wasHold();     // For write

    if (clicked || held) {
        PICC picc{};
        if (nfc_f.detect(picc)) {
            if (nfc_f.activate(picc)) {
                M5.Log.printf("%s:%s %s F:%02X DF:%04X\n", picc.idmAsString().c_str(), picc.pmmAsString().c_str(),
                              picc.typeAsString().c_str(), picc.format, picc.dfc_format);

                if (clicked) {
                    M5.Speaker.tone(2000, 30);
                    lcd.fillScreen(TFT_BLUE);
                    // nfc_f.dump();
                    read_ndef();
                } else if (held) {
                    M5.Speaker.tone(4000, 30);
                    lcd.fillScreen(TFT_YELLOW);
                    write_ndef();
                    lcd.fillScreen(0);
                }
                M5.Log.printf("Please remove the PICC from the reader\n");
                nfc_f.deactivate();
            }
            lcd.setCursor(0, 0);
            lcd.printf("Please put the PICC and click/hold BtnA");
            M5.Log.printf("Please put the PICC and click/hold BtnA\n");
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
