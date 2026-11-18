/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916 / WS1850S
  Detect PICCs of every NFC family the unit supports, reached through a PaHub

  BtnA: click to detect in the current family, hold to step to the next one. Unlike the other
  examples, which fix the family in config() before begin(), this one calls configureNFCMode()
  while running. A WS1850S offers NFC-A and NFC-B only, so the other two are compiled out.

  Device ---> PaHub (0x70)
                `- ch:0 UnitNFC / UnitRFID2

  The PaHub answers on 0x70 by default. Nothing behind it collides (ST25R3916 is 0x50, WS1850S is
  0x28), but a v2.1 PaHub can be moved to 0x71-0x77 with its DIP switch, and the hub then has to be
  constructed with that address: m5::unit::UnitPaHub hub{0x71};
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedNFC.h>
#include <M5UnitUnifiedHUB.h>
#include <M5Utility.h>
#include <wiring/m5_unit_unified_wiring.hpp>
#include <vector>
#include <algorithm>

// *************************************************************
// Choose ONE define symbol to match the unit you are using
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_UNIT_RFID2)
// For UnitNFC (U216)
// #define USING_UNIT_NFC
// For UnitRFID2 (U031-B)
// #define USING_UNIT_RFID2
#endif

#if defined(USING_UNIT_RFID2)
#include <M5UnitUnifiedRFID.h>
#endif

using namespace m5::nfc;

namespace {
auto& lcd = M5.Display;
m5::unit::UnitUnified Units;
m5::unit::UnitPaHub hub{};

#if defined(USING_UNIT_NFC)
#pragma message("Choose UnitNFC")
m5::unit::UnitNFC unit{};  // I2C
#elif defined(USING_UNIT_RFID2)
#pragma message("Choose UnitRFID2")
m5::unit::UnitRFID2 unit{};  // UnitRFID2 external (M5Unit-RFID, GROVE)
#else
#error Choose ONE: USING_UNIT_NFC / USING_UNIT_RFID2
#endif

// One layer per family, all on the same unit. Only the one matching the configured mode is used.
// NFCLayerF / NFCLayerV take an ST25R3916 only, so a WS1850S cannot even declare them
NFCLayerA nfc_a{unit};
NFCLayerB nfc_b{unit};
#if defined(USING_UNIT_NFC)
NFCLayerF nfc_f{unit};
NFCLayerV nfc_v{unit};
#endif

constexpr uint8_t HUB_CHANNEL{0};

// detect_family() returns how many PICCs answered, or this
constexpr int DETECT_FAILED{-1};

struct Family {
    NFC mode;
    const char* name;
};

// Only the families this build has a layer for. A WS1850S has no NFC-F / NFC-V layer, so those are
// left out of the cycle rather than offered and then refused
constexpr Family families[] = {
    {NFC::A, "NFC-A"},
    {NFC::B, "NFC-B"},
#if defined(USING_UNIT_NFC)
    {NFC::F, "NFC-F"},
    {NFC::V, "NFC-V"},
#endif
};
uint8_t family_index{};

// Font0 is 6x8, so one text size step per 160 px keeps the four lines readable from AtomS3 (128 px)
// up to Tab5 (1280 px) without assuming any particular resolution
uint8_t text_size{1};

void draw(const char* unit_name, const char* family, const char* state, const char* detail)
{
    const int32_t h = lcd.fontHeight();
    lcd.startWrite();
    lcd.fillScreen(TFT_BLACK);
    lcd.setCursor(0, 0);
    lcd.printf("%s via PaHub ch%u\n", unit_name, HUB_CHANNEL);
    lcd.setCursor(0, h);
    lcd.printf("%s\n", family);
    lcd.setCursor(0, h * 2);
    lcd.printf("%s\n", state);
    if (detail && *detail) {
        lcd.setCursor(0, h * 3);
        // Wrap by hand: a UID can be longer than a narrow screen
        const int32_t columns = lcd.width() / (6 * text_size);
        for (int32_t i = 0, row = 3; detail[i] && row < lcd.height() / h; row++) {
            char line[64]{};
            int32_t n = 0;
            while (detail[i] && n < columns && n < (int32_t)sizeof(line) - 1) {
                line[n++] = detail[i++];
            }
            lcd.setCursor(0, h * row);
            lcd.print(line);
        }
    }
    lcd.endWrite();
}

// The chip keeps its RF field on after begin(), and configureNFCMode() only clears the wakeup bit,
// so nfc_initial_field_on() would refuse with "Already tx_en". Drop the transmitter and receiver
// before switching, but leave `en` alone: it enables the oscillator and regulator, begin() is what
// raises it, and nothing in configureNFCMode() puts it back. WS1850S handles all of this inside
// configureNFCMode() (turnOffAntenna), so it needs nothing here
bool stop_field()
{
#if defined(USING_UNIT_NFC)
    using namespace m5::unit::st25r3916::command;
    using namespace m5::unit::st25r3916::regval;
    uint8_t oc{};
    if (!unit.readOperationControl(oc)) {
        return false;
    }
    oc &= static_cast<uint8_t>(~(tx_en | rx_en | wu));
    return unit.writeDirectCommand(CMD_STOP_ALL_ACTIVITIES) && unit.writeOperationControl(oc) && unit.clearInterrupts();
#else
    return true;
#endif
}

// Ask the unit for the family, then poll with the matching layer. Returns how many PICCs answered,
// or DETECT_FAILED. Found PICCs are printed to serial and summarized into detail for the screen.
//
// This goes no further than detect(). detect() classifies a PICC only from what the first exchange
// reveals (the SAK for NFC-A, the PMm for NFC-F), so the type printed below is provisional and can be
// a generic answer such as ISO14443-4 or, for NFC-B, Unclassified. Settling the type takes more
// exchanges, which only NFC-A offers (NFCLayerA::identify(); see the NFCA/Detect example) -
// NFCLayerB / NFCLayerF / NFCLayerV have no identify() at all
int detect_family(const NFC mode, char* detail, const size_t detail_len)
{
    // Reconfiguring the family the unit is already in would drop and raise the RF field for nothing
    if (unit.NFCMode() != mode) {
        if (!stop_field()) {
            M5.Log.printf("  failed to stop the RF field\n");
            return DETECT_FAILED;
        }
        if (!unit.configureNFCMode(mode)) {
            M5.Log.printf("  failed to configure %s\n", families[family_index].name);
            return DETECT_FAILED;
        }
        M5.Log.printf("  reconfigured to %s\n", families[family_index].name);
    }
    switch (mode) {
        case NFC::A: {
            std::vector<m5::nfc::a::PICC> piccs;
            if (!nfc_a.detect(piccs)) {
                return 0;
            }
            for (auto&& p : piccs) {
                M5.Log.printf("  UID:%s SAK:%02X ATQA:%04X %s\n", p.uidAsString().c_str(), p.sak, p.atqa,
                              p.typeAsString().c_str());
            }
            snprintf(detail, detail_len, "%s %s", piccs.front().uidAsString().c_str(),
                     piccs.front().typeAsString().c_str());
            return (int)piccs.size();
        }
        case NFC::B: {
            std::vector<m5::nfc::b::PICC> piccs;
            if (!nfc_b.detect(piccs)) {
                return 0;
            }
            for (auto&& p : piccs) {
                M5.Log.printf("  PUPI:%s %s\n", p.pupiAsString().c_str(), p.typeAsString().c_str());
            }
            snprintf(detail, detail_len, "%s %s", piccs.front().pupiAsString().c_str(),
                     piccs.front().typeAsString().c_str());
            return (int)piccs.size();
        }
#if defined(USING_UNIT_NFC)
        case NFC::F: {
            std::vector<m5::nfc::f::PICC> piccs;
            if (!nfc_f.detect(piccs)) {
                return 0;
            }
            for (auto&& p : piccs) {
                M5.Log.printf("  IDm:%s PMm:%s %s\n", p.idmAsString().c_str(), p.pmmAsString().c_str(),
                              p.typeAsString().c_str());
            }
            snprintf(detail, detail_len, "%s %s", piccs.front().idmAsString().c_str(),
                     piccs.front().typeAsString().c_str());
            return (int)piccs.size();
        }
        case NFC::V: {
            std::vector<m5::nfc::v::PICC> piccs;
            if (!nfc_v.detect(piccs)) {
                return 0;
            }
            for (auto&& p : piccs) {
                M5.Log.printf("  UID:%s %s\n", p.uidAsString().c_str(), p.typeAsString().c_str());
            }
            snprintf(detail, detail_len, "%s %s", piccs.front().uidAsString().c_str(),
                     piccs.front().typeAsString().c_str());
            return (int)piccs.size();
        }
#endif
        default:  // every family in families[] has a case above
            return DETECT_FAILED;
    }
}

#if defined(USING_UNIT_NFC)
constexpr const char* UNIT_NAME = "UnitNFC";
#else
constexpr const char* UNIT_NAME = "UnitRFID2";
#endif

// Put the unit into a family and say so on the screen and the serial. The RF field is already up
// after begin(), and configureNFCMode() refuses to raise it again, so the transmitter and receiver
// have to come down first (see stop_field above).
bool switch_family(const NFC mode, const char* name)
{
    if (!stop_field()) {
        M5.Log.printf("  failed to stop the RF field\n");
        draw(UNIT_NAME, name, "field failed", "hold: retry");
        return false;
    }
    if (!unit.configureNFCMode(mode)) {
        M5.Log.printf("  failed to configure %s\n", name);
        draw(UNIT_NAME, name, "config failed", "hold: retry");
        return false;
    }
    M5.Log.printf("Family: %s\n", name);
    draw(UNIT_NAME, name, "click: detect", "hold: next family");
    return true;
}

}  // namespace

void setup()
{
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);
    if (lcd.height() > lcd.width()) {
        lcd.setRotation(1);
    }
    lcd.setFont(&fonts::Font0);
    text_size = (uint8_t)std::max<int32_t>(1, lcd.width() / 160);
    lcd.setTextSize(text_size);
    lcd.setTextColor(TFT_WHITE, TFT_BLACK);

    if (!hub.add(unit, HUB_CHANNEL)) {
        M5_LOGE("Failed to connect the unit to the hub");
        m5::unit::wiring::failStop();
    }

    // Run the hub at the lowest clock of the units behind it
    auto hcfg  = hub.component_config();
    hcfg.clock = std::min(hcfg.clock, unit.component_config().clock);
    hub.component_config(hcfg);

    // Board-aware I2C for the PaHub: NessoN1 -> QWIIC (port_a), NanoC6/NanoH2 -> Ex_I2C, others -> Wire.
    // NessoN1 has to go through port_a: its GROVE port is SoftwareI2C, whose register polling is too
    // slow for the RF timing the reader needs (see the NessoN1 section of the README)
    if (!m5::unit::wiring::addI2C(Units, hub, 0, m5::unit::wiring::NessoPort::PortA) || !Units.begin()) {
        M5_LOGE("Failed to begin");
        M5_LOGW("%s", Units.debugInfo().c_str());
        m5::unit::wiring::failStop();
    }

    M5_LOGI("M5UnitUnified initialized");
    M5_LOGI("%s", Units.debugInfo().c_str());

    M5.Log.printf("%s via PaHub ch%u\n", UNIT_NAME, HUB_CHANNEL);
    M5.Log.printf("BtnA click: detect in the current family, hold: step to the next family\n");

    // Settle the first family here rather than on the first click, so that what the screen says is
    // what the unit is in. A family that cannot be configured is as fatal as a unit that cannot begin
    if (!switch_family(families[family_index].mode, families[family_index].name)) {
        M5_LOGE("Failed to configure %s", families[family_index].name);
        m5::unit::wiring::failStop();
    }
}

void loop()
{
    M5.update();
    Units.update();

    if (M5.BtnA.wasHold()) {
        const auto previous = family_index;
        family_index        = (family_index + 1) % m5::stl::size(families);
        // Step back when the switch does not take, so the screen never names a family the unit is not
        // in. Holding again comes back to this one and tries it afresh
        if (!switch_family(families[family_index].mode, families[family_index].name)) {
            family_index = previous;
        }
        return;
    }

    if (!M5.BtnA.wasClicked()) {
        return;
    }

    const auto mode = families[family_index].mode;
    const auto name = families[family_index].name;
    char detail[64]{};

    const int found = detect_family(mode, detail, sizeof(detail));
    if (found < 0) {
        M5.Log.printf("%s: failed\n", name);
        draw(UNIT_NAME, name, "failed", "click: retry");
        return;
    }
    if (found == 0) {
        M5.Log.printf("%s: no PICC\n", name);
        draw(UNIT_NAME, name, "no PICC", "");
        return;
    }
    M5.Speaker.tone(3000, 20);
    M5.Log.printf("%s: %d PICC\n", name, found);
    char state[24]{};
    snprintf(state, sizeof(state), "%d PICC", found);
    draw(UNIT_NAME, name, state, detail);
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
