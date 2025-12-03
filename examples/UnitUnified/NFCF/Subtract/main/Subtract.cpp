/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for M5Cardputer-ADV with HackerCap
  Subtract register  example (Lite,Lite-S only)
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedNFC.h>
#include <M5Utility.h>
#include <vector>

using namespace m5::nfc;
using namespace m5::nfc::f;

namespace {
auto& lcd = M5.Display;
m5::unit::UnitUnified Units;
m5::unit::CapST25R3916 cap;  // ST25R3916 in the HackerCap
m5::unit::nfc::NFCLayerF nfc_f{cap};

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

    auto cfg = cap.config();
    cfg.mode = NFC::F;
    cap.config(cfg);

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

    if (!SPI.bus()) {
        auto spi_sclk = M5.getPin(m5::pin_name_t::sd_spi_sclk);
        auto spi_mosi = M5.getPin(m5::pin_name_t::sd_spi_mosi);
        auto spi_miso = M5.getPin(m5::pin_name_t::sd_spi_miso);
        M5_LOGI("getPin: %d,%d,%d", spi_sclk, spi_mosi, spi_miso);
        SPI.begin(spi_sclk, spi_miso, spi_mosi /* SS is shared SD, CC1101, ST25R3916 */);
    }

    SPISettings settings = {10000000, MSBFIRST, SPI_MODE1};
    if (!Units.add(cap, SPI, settings) || !Units.begin()) {
        M5_LOGE("Failed to begin");
        lcd.fillScreen(TFT_RED);
        while (true) {
            m5::utility::delay(10000);
        }
    }
    M5_LOGI("M5UnitUnified has been begun");
    M5_LOGI("%s", Units.debugInfo().c_str());

    if (lcd.width() < lcd.height()) {
        lcd.setRotation(1);
    }
    lcd.setFont(&fonts::Font0);
    lcd.fillScreen(0);
    lcd.setCursor(0, 0);
    lcd.printf("Please put the PICC and click G0");
    M5.Log.printf("Please put the PICC and click G0\n");
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
