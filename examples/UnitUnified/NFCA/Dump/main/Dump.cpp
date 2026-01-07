/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916
  Dump NFC-A PICC
  This example is shared with M5Unit-RFID
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedNFC.h>
#include <M5Utility.h>
#include <vector>

// *************************************************************
// Choose one define symbol to match the unit you are using
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_HACKER_CAP) && !defined(USING_UNIT_RFID2)
// For UnitNFC
// #define USING_UNIT_NFC
// For CapNFC
// #define USING_HACKER_CAP
// For UnitRFID2
// #define USING_UNIT_RFID2
#endif

#if defined(USING_UNIT_RFID2)
#include <M5UnitUnifiedRFID.h>
#endif

using namespace m5::nfc::a;
using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;

namespace {
auto& lcd = M5.Display;
m5::unit::UnitUnified Units;

#if defined(USING_UNIT_NFC)
#pragma message "Choose UnitNFC"
m5::unit::UnitNFC unit{};  // I2C
#elif defined(USING_HACKER_CAP)
#pragma message "Choose HackerCapNFC"
m5::unit::HackerCapNFC unit{};  // HackerCap (SPI)
#elif defined(USING_UNIT_RFID2)
#pragma message "Choose UnitRFID2"
m5::unit::UnitRFID2 unit{};  // UnitRFID2 (M5Unit-RFID)
#else
#error Choose unit please!
#endif
m5::nfc::NFCLayerA nfc_a{unit};

// KeyA that can authenticate all blocks
// If it's a different key value, change it
constexpr Key keyA = DEFAULT_KEY;  // Default as 0xFFFFFFFFFFFF
}  // namespace

void setup()
{
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);

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

#if defined(USING_UNIT_NFC) || defined(USING_UNIT_RFID2)
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
        if (nfc_a.detect(picc)) {
            if (nfc_a.identify(picc) && nfc_a.reactivate(picc)) {
                M5.Speaker.tone(3000, 20);
                M5.Log.printf("==== Dump %s %s %u/%u ====\n", picc.uidAsString().c_str(), picc.typeAsString().c_str(),
                              picc.userAreaSize(), picc.totalSize());
                nfc_a.dump(keyA);  // Need key if MIFARE classic, Ignore key if not MIFARE classic
                nfc_a.deactivate();
            } else {
                M5_LOGE("Failed to identify/activate %s", picc.uidAsString().c_str());
            }
        } else {
            M5.Log.printf("PICC NOT exists\n");
        }
    }
}
