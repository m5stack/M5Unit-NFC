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
#include <vector>

// *************************************************************
// Choose one define symbol to match the unit you are using
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_HACKER_CAP)
// For UnitNFC
// #define USING_UNIT_NFC
// For CapNFC
// #define USING_HACKER_CAP
#endif

using namespace m5::nfc;
using namespace m5::nfc::f;

namespace {
auto& lcd = M5.Display;
m5::unit::UnitUnified Units;

#if defined(USING_UNIT_NFC)
#pragma message "Choose UnitNFC"
m5::unit::UnitNFC unit{};  // I2C
#elif defined(USING_HACKER_CAP)
#pragma message "Choose HackerCapNFC"
m5::unit::HackerCapNFC unit{};  // HackerCap (SPI)
#else
#error Choose unit please!
#endif
m5::unit::nfc::NFCLayerF nfc_f{unit};

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
        M5_LOGE("Failed to read");
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
        M5.Log.printf("Increases are prohibited %u\n", can_write_reg(tmp, reg));
    } else {
        M5_LOGE("Oops!?");
    }

    reg = tmp;
    reg.regB(reg.regB() + 1);
    if (!nfc_f.write16(lite::REG, reg.reg, sizeof(reg.reg))) {
        M5.Log.printf("Increases are prohibited %u\n", can_write_reg(tmp, reg));
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

#if 0
    //// M5GFX 0.2.15 NG! with HackerCap
    auto board = M5.getBoard();
    if (board != lgfx::board_t::board_M5CardputerADV) {
        M5_LOGE("This is NOT M5Cardputer-ADV %U/%XH", board, board);
        lcd.fillScreen(TFT_RED);
        while (true) {
            m5::utility::delay(10000);
        }
    }
#endif

#if defined(USING_UNIT_NFC)
    auto pin_num_sda = M5.getPin(m5::pin_name_t::port_a_sda);
    auto pin_num_scl = M5.getPin(m5::pin_name_t::port_a_scl);
    M5_LOGI("getPin: SDA:%u SCL:%u", pin_num_sda, pin_num_scl);
    Wire.end();
    Wire.begin(pin_num_sda, pin_num_scl, 400 * 1000U);

    if (!Units.add(unit, Wire) || !Units.begin()) {
        M5_LOGE("Failed to begin");
        lcd.clear(TFT_RED);
        while (true) {
            m5::utility::delay(10000);
        }
    }
#elif defined(USING_HACKER_CAP)
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
    M5_LOGI("M5UnitUnified has been begun");
    M5_LOGI("%s", Units.debugInfo().c_str());

    if (lcd.width() < lcd.height()) {
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
