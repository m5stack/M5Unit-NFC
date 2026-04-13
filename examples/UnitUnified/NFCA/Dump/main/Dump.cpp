/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for M5Unit-NFC/RFID
  Dump NFC-A PICC
  This example is shared with M5Unit-RFID
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
#if !defined(USING_UNIT_NFC) && !defined(USING_CAP_CC1101) && !defined(USING_UNIT_RFID2)
// For UnitNFC
// #define USING_UNIT_NFC
// For CapNFC
// #define USING_CAP_CC1101
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
#elif defined(USING_CAP_CC1101)
#pragma message "Choose CapCC1101NFC"
m5::unit::CapCC1101NFC unit{};  // CapCC1101 (SPI)
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

    // The screen shall be in landscape mode
    if (lcd.height() > lcd.width()) {
        lcd.setRotation(1);
    }

#if defined(USING_UNIT_NFC) || defined(USING_UNIT_RFID2)
    auto board = M5.getBoard();
    bool unit_ready{};
#if defined(USING_M5DIAL_BUILTIN_WS1850S)
    // M5Dial builtin WS1850S on In_I2C (G12/G11, shared with RTC8563)
    M5_LOGI("Using M5.In_I2C for builtin WS1850S");
    unit_ready = Units.add(unit, M5.In_I2C) && Units.begin();
#else
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
#endif  // USING_M5DIAL_BUILTIN_WS1850S
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

    lcd.setFont(&fonts::Font0);
    lcd.fillScreen(TFT_DARKGREEN);
    lcd.setCursor(0, lcd.height() / 2);
    lcd.printf("Please put the PICC and click BtnA");
    M5.Log.printf("Please put the PICC and click BtnA\n");
}

void loop()
{
    M5.update();
    Units.update();

    if (M5.BtnA.wasClicked()) {
        lcd.fillScreen(TFT_DARKGREEN);
        lcd.setCursor(0, lcd.height() / 2);
        PICC picc{};
        if (nfc_a.detect(picc)) {
            if (nfc_a.identify(picc) && nfc_a.reactivate(picc)) {
                M5.Speaker.tone(3000, 20);
                lcd.printf("%s\n%s", picc.uidAsString().c_str(), picc.typeAsString().c_str());
                M5.Log.printf("==== Dump %s %s %u/%u ====\n", picc.uidAsString().c_str(), picc.typeAsString().c_str(),
                              picc.userAreaSize(), picc.totalSize());
                nfc_a.dump(keyA);  // Need key if MIFARE classic, Ignore key if not MIFARE classic
                nfc_a.deactivate();
            } else {
                lcd.printf("Failed to identify");
                M5_LOGE("Failed to identify/activate %s", picc.uidAsString().c_str());
            }
        } else {
            lcd.printf("PICC NOT exists");
            M5.Log.printf("PICC NOT exists\n");
        }
    }
}
