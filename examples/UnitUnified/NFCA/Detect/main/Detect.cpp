/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for M5Cardputer-ADV with HackerCap
  Detect NFC-A PICC
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedNFC.h>
#include <M5Utility.h>
#include <vector>

//#define USING_I2C

using namespace m5::nfc::a;

namespace {
auto& lcd = M5.Display;
m5::unit::UnitUnified Units;

#if defined(USING_I2C)
m5::unit::UnitST25R3916 unit{};  // I2C connected
#else
m5::unit::CapST25R3916 unit{};  // ST25R3916 in the HackerCap
#endif
m5::unit::nfc::NFCLayerA nfc_a{unit};

}  // namespace

void setup()
{
    M5.begin();

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

#if defined(USING_I2C)
    auto pin_num_sda = M5.getPin(m5::pin_name_t::port_a_sda);
    auto pin_num_scl = M5.getPin(m5::pin_name_t::port_a_scl);
    M5_LOGI("getPin: SDA:%u SCL:%u", pin_num_sda, pin_num_scl);
    Wire.end();
    Wire.begin(pin_num_sda, pin_num_scl, 100 * 1000U);

    if (!Units.add(unit, Wire) || !Units.begin()) {
        M5_LOGE("Failed to begin");
        lcd.clear(TFT_RED);
        while (true) {
            m5::utility::delay(10000);
        }
    }
#else
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
}

void loop()
{
    M5.update();
    Units.update();

    std::vector<PICC> piccs;
    if (nfc_a.detect(piccs)) {
        M5.Speaker.tone(3000, 10);
        lcd.fillScreen(0);
        lcd.setCursor(0, 0);
        lcd.printf("%zu PICC\n", piccs.size());
        M5.Log.printf("%zu PICC\n", piccs.size());
        uint32_t idx{};
        for (auto&& u : piccs) {
            M5.Log.printf("PICC:%s %s %u/%u\n", u.uidAsString().c_str(), u.typeAsString().c_str(), u.userAreaSize(),
                          u.totalSize());
            lcd.printf("[%2u]:PICC:<%s> %s\n", idx, u.uidAsString().c_str(), u.typeAsString().c_str());
            ++idx;
        }
        nfc_a.deactivate();
    }
}
