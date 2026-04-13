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
#include <Wire.h>
#include <M5HAL.hpp>  // For NessoN1
#include <vector>

// *************************************************************
// Choose one define symbol to match the unit you are using
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_CAP_CC1101)
// For UnitNFC
// #define USING_UNIT_NFC
// For CapNFC
// #define USING_CAP_CC1101
#endif
#if defined(USING_UNIT_RFID2)
#error UnitRFID2 does NOT support emulation
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

#if defined(USING_UNIT_NFC)
    auto board = M5.getBoard();
    bool unit_ready{};
    // NessoN1: port_b (GROVE) uses SoftwareI2C (M5HAL Bus) which causes I2C register
    //          polling latency too high for MFRC522/WS1850S RF timing requirements.
    //          Use QWIIC (port_a) with Wire instead. (Requires QWIIC-GROVE conversion cable)
    if (board == m5::board_t::board_M5NanoC6) {
        M5_LOGI("Using M5.Ex_I2C");
        unit_ready = Units.add(unit, M5.Ex_I2C) && Units.begin();
    } else {
        auto pin_num_sda = M5.getPin(m5::pin_name_t::port_a_sda);
        auto pin_num_scl = M5.getPin(m5::pin_name_t::port_a_scl);
        M5_LOGI("getPin: SDA:%u SCL:%u", pin_num_sda, pin_num_scl);
        Wire.end();
        Wire.begin(pin_num_sda, pin_num_scl, 400 * 1000U);
        unit_ready = Units.add(unit, Wire) && Units.begin();
    }
    if (!unit_ready) {
        M5_LOGE("Failed to begin");
        lcd.fillScreen(TFT_RED);
        while (true) {
            m5::utility::delay(10000);
        }
    }
#elif defined(USING_CAP_CC1101)
    if (!SPI.bus()) {
        auto spi_sclk = M5.getPin(m5::pin_name_t::sd_spi_sclk);
        auto spi_mosi = M5.getPin(m5::pin_name_t::sd_spi_mosi);
        auto spi_miso = M5.getPin(m5::pin_name_t::sd_spi_miso);
        M5_LOGI("getPin: %d,%d,%d", spi_sclk, spi_mosi, spi_miso);
        SPI.begin(spi_sclk, spi_miso, spi_mosi /* SS is shared SD, CC1101, ST25R3916 */);
    }

    SPISettings settings = {10000000, MSBFIRST, SPI_MODE1};
    if (!Units.add(unit, SPI, settings) || !Units.begin()) {
        M5_LOGE("Failed to begin");
        lcd.fillScreen(TFT_RED);
        while (true) {
            m5::utility::delay(10000);
        }
    }
#endif
    M5_LOGI("M5UnitUnified initialized");
    M5_LOGI("%s", Units.debugInfo().c_str());

    lcd.setFont(&fonts::Font2);

    //
    lcd.startWrite();
    lcd.fillScreen(TFT_RED);
    if (picc.emulate(type, uid, sizeof(uid))) {
        embed_uid(picc_memory, uid);
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
