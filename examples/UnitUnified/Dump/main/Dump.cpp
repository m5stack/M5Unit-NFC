/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for M5Cardputer-ADV with HackerCap
  Dump NFC device
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedNFC.h>
#include <M5Utility.h>
#include <vector>

using namespace m5::nfc::a;

namespace {
auto& lcd = M5.Display;
m5::unit::UnitUnified Units;
m5::unit::CapST25R3916 cap;  // ST25R3916 in the HackerCap
m5::unit::nfc::NFCLayerA nfc_a{cap};
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
    heap_caps_check_integrity_all(true);

    M5_LOGI("M5UnitUnified has been begun");
    M5_LOGI("%s", Units.debugInfo().c_str());

    if (lcd.width() < lcd.height()) {
        lcd.setRotation(1);
    }
    lcd.setFont(&fonts::Font0);
    lcd.fillScreen(0);
    lcd.setCursor(0, 0);
    lcd.printf("Please put the device and click G0");
    M5.Log.printf("Please put the device and click G0\n");
}

void loop()
{
    M5.update();
    auto touch = M5.Touch.getDetail();
    Units.update();

    if (M5.BtnA.wasClicked() || touch.wasClicked()) {
        lcd.fillRect(0, lcd.fontHeight(), lcd.width(), lcd.height() - lcd.fontHeight());
        std::vector<UID> devices;
        if (nfc_a.detect(devices)) {
            // If multiple occurrences are detected, only the first one detected
            auto& uid = devices.front();
            if (nfc_a.activate(uid)) {
                M5.Log.printf("==== Dump %s %s ====\n", uid.uidAsString().c_str(), uid.typeAsString().c_str());
                nfc_a.dump(uid);
                nfc_a.deactivate();
            } else {
                M5_LOGE("Failed to activate %s", uid.uidAsString().c_str());
            }
        } else {
            M5.Log.printf("No devices\n");
        }
    }
}
