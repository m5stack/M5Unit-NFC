/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916
  NFC-A Emulation mode
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedNFC.h>
#include <M5Utility.h>
#include <wiring/m5_unit_unified_wiring.hpp>
#include <vector>
#include <algorithm>
#include <cstring>

// *************************************************************
// Choose ONE define symbol to match the unit you are using
// NOTE: Emulation is supported ONLY on UnitNFC (ST25R3916) and CapCC1101NFC (ST25R3916).
//       UnitRFID2 (WS1850S) and M5Dial Builtin (WS1850S) do NOT support emulation.
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_CAP_CC1101)
// For UnitNFC (U216)
// #define USING_UNIT_NFC
// For CapCC1101 (U219)
// #define USING_CAP_CC1101
#endif
#if defined(USING_UNIT_RFID2) || defined(USING_M5DIAL_BUILTIN_WS1850S)
#error Emulation is NOT supported on UnitRFID2 / M5Dial Builtin (WS1850S). Use UnitNFC or CapCC1101NFC.
#endif

using namespace m5::nfc;
using namespace m5::nfc::a;
using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;

namespace {
auto& lcd = M5.Display;
m5::unit::UnitUnified Units;

#if defined(USING_UNIT_NFC)
#pragma message "Choose UnitNFC"
m5::unit::UnitNFC unit{};  // I2C
#elif defined(USING_CAP_CC1101)
#pragma message "Choose CapCC1101NFC"
m5::unit::CapCC1101NFC unit{};  // CapCC1101 (SPI)
#else
#error Choose unit please!
#endif
m5::nfc::EmulationLayerA emu_a{unit};

// constexpr Key keyA = DEFAULT_KEY;  // Default as 0xFFFFFFFFFFFF
// constexpr Key keyB = DEFAULT_KEY;  // Default as 0xFFFFFFFFFFFF

PICC picc{};

#define EMU_MIFARE_ULTRALIGHT
// #define EMU_NTAG213

#if defined(EMU_MIFARE_ULTRALIGHT)
constexpr Type type{Type::MIFARE_Ultralight};
constexpr uint8_t uid[] = {0x04, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE};
uint8_t picc_memory[]   = {
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0xA3, 0x00, 0x00,  //
    0xE1, 0x10, 0x06, 0x00,  //
    0x03, 0x25, 0x91, 0x01,  //
    0x0D, 0x55, 0x04, 0x6D,  //
    0x35, 0x73, 0x74, 0x61,  //
    0x63, 0x6B, 0x2E, 0x63,  //
    0x6F, 0x6D, 0x2F, 0x51,  //
    0x01, 0x10, 0x54, 0x02,  //
    0x65, 0x6E, 0x48, 0x65,  //
    0x6C, 0x6C, 0x6F, 0x20,  //
    0x4D, 0x35, 0x53, 0x74,  //
    0x61, 0x63, 0x6B, 0xFE,  //
    0x44, 0x45, 0x46, 0x00,  //
    0x44, 0x45, 0x46, 0x00,  //
};
#elif defined(EMU_NTAG213)
constexpr Type type{Type::NTAG_213};
constexpr uint8_t uid[] = {0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33};
uint8_t picc_memory[]   = {
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x48, 0x00, 0x00,  //
    0xE1, 0x10, 0x12, 0x00,  //
    0x01, 0x03, 0xA0, 0x0C,  //
    0x34, 0x03, 0x58, 0x91,  //
    0x01, 0x0D, 0x55, 0x04,  //
    0x6D, 0x35, 0x73, 0x74,  //
    0x61, 0x63, 0x6B, 0x2E,  //
    0x63, 0x6F, 0x6D, 0x2F,  //
    0x11, 0x01, 0x11, 0x54,  //
    0x02, 0x7A, 0x68, 0xE4,  //
    0xBD, 0xA0, 0xE5, 0xA5,  //
    0xBD, 0x20, 0x4D, 0x35,  //
    0x53, 0x74, 0x61, 0x63,  //
    0x6B, 0x11, 0x01, 0x10,  //
    0x54, 0x02, 0x65, 0x6E,  //
    0x48, 0x65, 0x6C, 0x6C,  //
    0x6F, 0x20, 0x4D, 0x35,  //
    0x53, 0x74, 0x61, 0x63,  //
    0x6B, 0x51, 0x01, 0x1A,  //
    0x54, 0x02, 0x6A, 0x61,  //
    0xE3, 0x81, 0x93, 0xE3,  //
    0x82, 0x93, 0xE3, 0x81,  //
    0xAB, 0xE3, 0x81, 0xA1,  //
    0xE3, 0x81, 0xAF, 0x20,  //
    0x4D, 0x35, 0x53, 0x74,  //
    0x61, 0x63, 0x6B, 0xFE,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0xBD,  //
    0x02, 0x00, 0x00, 0xFF,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
};

#else
#error "Choose the target to emulate"
#endif

uint8_t bcc8(const uint8_t* p, const uint8_t len, const uint8_t init = 0)
{
    uint8_t v = init;
    for (uint_fast8_t i = 0; i < len; ++i) {
        v ^= p[i];
    }
    return v;
}

// Correctly embed the Ultralight and NTAG UIDs into memory
// The emulated memory as it stood at the last hold, so a hold shows only what the reader has
// written since. A click prints everything and leaves this alone, so the two never interfere
uint8_t picc_memory_seen[sizeof(picc_memory)]{};

void dump_emulated_memory(const bool only_changed)
{
    constexpr uint16_t BLOCK_SIZE{4};
    const uint16_t blocks = (sizeof(picc_memory) + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint16_t shown{};

    M5.Log.printf("==== Emulated memory (%s) ====\n", only_changed ? "changed since the last hold" : "all");
    for (uint16_t blk = 0; blk < blocks; ++blk) {
        const uint16_t offset = blk * BLOCK_SIZE;
        const uint16_t len    = std::min<uint16_t>(BLOCK_SIZE, sizeof(picc_memory) - offset);
        if (only_changed && memcmp(picc_memory + offset, picc_memory_seen + offset, len) == 0) {
            continue;
        }
        M5.Log.printf("[%03X]:", offset);
        for (uint16_t i = 0; i < len; ++i) {
            M5.Log.printf("%02X ", picc_memory[offset + i]);
        }
        M5.Log.printf("\n");
        ++shown;
    }
    if (only_changed) {
        if (!shown) {
            M5.Log.printf("No block has changed\n");
        }
        memcpy(picc_memory_seen, picc_memory, sizeof(picc_memory));
    }
}

void embed_uid(uint8_t mem[9], const uint8_t uid[7])
{
    memcpy(mem, uid, 3);
    mem[3] = bcc8(uid, 3, 0x88 /* CT */);
    memcpy(mem + 4, uid + 3, 4);
    mem[8] = bcc8(uid + 3, 4);
}

constexpr uint16_t color_table[] = {
    //  None,      Off,     Idle,     Ready,   Active,      Halt };
    TFT_BLACK, TFT_RED, TFT_BLUE, TFT_YELLOW, TFT_GREEN, TFT_MAGENTA};
constexpr const char* state_table[] = {"-", "O", "I", "R", "A", "H"};

}  // namespace

void setup()
{
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);

    // The screen shall be in landscape mode
    if (lcd.height() > lcd.width()) {
        lcd.setRotation(1);
    }

    // Emulation settings
    auto cfg      = unit.config();
    cfg.emulation = true;
    cfg.mode      = NFC::A;
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

    lcd.setFont(&fonts::Font2);

    //
    lcd.startWrite();
    lcd.fillScreen(TFT_RED);
    if (picc.emulate(type, uid, sizeof(uid))) {
        embed_uid(picc_memory, uid);
        memcpy(picc_memory_seen, picc_memory, sizeof(picc_memory));
        if (emu_a.begin(picc, picc_memory, sizeof(picc_memory))) {
            lcd.fillScreen(TFT_DARKGREEN);
            lcd.setCursor(0, 16);
            const auto& e_picc = emu_a.emulatePICC();
            M5.Log.printf("Emulation:%s %s ATQA:%04X SAK:%u\n", e_picc.typeAsString().c_str(),
                          e_picc.uidAsString().c_str(), e_picc.atqa, e_picc.sak);
            lcd.printf("%s\n%s\nATQA:%04X SAK:%u", e_picc.typeAsString().c_str(), e_picc.uidAsString().c_str(),
                       e_picc.atqa, e_picc.sak);
        }
    }
    lcd.fillRect(0, 0, 32, 16, color_table[0]);
    lcd.drawString(state_table[0], 0, 0);
    lcd.endWrite();
}

void loop()
{
    M5.update();
    Units.update();
    emu_a.update();  // Need call in loop

    // Take the phone away before asking, since printing stops the emulation answering for as long
    // as it runs
    if (M5.BtnA.wasClicked()) {
        dump_emulated_memory(false);
    } else if (M5.BtnA.wasHold()) {
        dump_emulated_memory(true);
    }

    static EmulationLayerA::State latest{};
    auto state = emu_a.state();
    if (latest != state) {
        latest = state;
        lcd.startWrite();
        lcd.fillRect(0, 0, 32, 16, color_table[m5::stl::to_underlying(state)]);
        lcd.drawString(state_table[m5::stl::to_underlying(state)], 0, 0);
        lcd.endWrite();
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
