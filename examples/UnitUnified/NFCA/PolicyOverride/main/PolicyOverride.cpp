/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for M5Unit-NFC/RFID
  Demonstrate per-call ISO-DEP timeout/retry override (policy_t) on an ISO/IEC 14443-4 PICC.

  After activating an ISO/IEC 14443-4 PICC, the same APDU is sent three ways:
    (a) default policy (timeout/retries from the activation-derived ISO-DEP config)
    (b) override with a long fwt_ms and max_retries=0 (e.g. for a slow, non-idempotent command)
    (c) override with a deliberately tiny fwt_ms to show that the override actually controls
        the per-exchange timeout (this one is expected to time out)
  The override is per-call only: it does not change the session config and does not reset the
  ISO-DEP block number.
  This example is shared with M5Unit-RFID
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedNFC.h>
#include <M5Utility.h>
#include <wiring/m5_unit_unified_wiring.hpp>

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

// ISO/IEC 7816-4 SELECT by name (NDEF Tag Application AID). A benign Type-4 command:
// the PICC answers with a status word (e.g. 9000 or 6A82) whose value does not matter here;
// we only observe whether the per-call timeout lets the exchange complete.
constexpr uint8_t SELECT_NDEF_AID[]{0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00};

// Send SELECT_NDEF_AID once with the given per-call override (nullptr = use config) and log the result.
void send_select(m5::nfc::isodep::IsoDEP* dep, const char* label, const m5::nfc::isodep::policy_t* override_policy)
{
    uint8_t rx[64]{};
    uint16_t rx_len = sizeof(rx);
    const bool ok   = dep->transceiveAPDU(rx, rx_len, SELECT_NDEF_AID, sizeof(SELECT_NDEF_AID), override_policy);
    if (ok && rx_len >= 2) {
        M5.Log.printf("  [%s] OK  SW=%02X%02X (rx_len=%u)\n", label, rx[rx_len - 2], rx[rx_len - 1], rx_len);
    } else {
        M5.Log.printf("  [%s] FAILED (timeout/no response) ok=%d rx_len=%u\n", label, ok, rx_len);
    }
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
    lcd.fillScreen(0);
    lcd.setCursor(0, lcd.height() / 2);
    lcd.printf("Put an ISO14443-4 PICC and click BtnA");
    M5.Log.printf("Put an ISO14443-4 PICC and click BtnA\n");
}

void loop()
{
    M5.update();
    Units.update();

    if (!M5.BtnA.wasClicked()) {
        return;
    }

    PICC picc{};
    if (!nfc_a.detect(picc) || !nfc_a.identify(picc)) {
        M5.Log.printf("No PICC\n");
        return;
    }
    // MIFARE Plus SL1 reports as ISO14443-4 but communicates as MIFARE Classic (no ISO-DEP APDU),
    // so skip Classic-compatible PICCs (mirrors the RATS condition in NFCLayerA::activate).
    if (!picc.isISO14443_4() || picc.isMifareClassicCompatible()) {
        M5.Log.printf("Not an ISO-DEP (14443-4) PICC: %s\n", picc.typeAsString().c_str());
        return;
    }
    // reactivate() runs WUPA + anti-collision + SELECT + RATS, establishing the ISO-DEP session
    if (!nfc_a.reactivate(picc)) {
        M5_LOGE("Failed to reactivate %s", picc.uidAsString().c_str());
        return;
    }
    auto* dep = nfc_a.isoDEP();
    if (!dep) {
        M5_LOGE("ISO-DEP not available");
        nfc_a.deactivate();
        return;
    }

    M5.Speaker.tone(2000, 30);
    M5.Log.printf("=== ISO-DEP per-call policy override: %s %s ===\n", picc.uidAsString().c_str(),
                  picc.typeAsString().c_str());

    // (a) Default policy (timeout/retries derived from the activation-time ISO-DEP config)
    send_select(dep, "default", nullptr);

    // (b) Override: long fwt and no retry (e.g. a slow, non-idempotent command)
    const m5::nfc::isodep::policy_t long_policy{2000, 8000, 0};
    send_select(dep, "override fwt=2000ms retries=0", &long_policy);

    // (c) Override: deliberately tiny fwt to show the override controls the per-exchange timeout.
    //     Usually times out, proving the override value reaches the transceive. A very fast PICC
    //     (e.g. ST25TA) may still answer within 1 ms and succeed.
    const m5::nfc::isodep::policy_t tiny_policy{1, 8000, 0};
    send_select(dep, "override fwt=1ms (usually times out)", &tiny_policy);

    nfc_a.deactivate();
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
