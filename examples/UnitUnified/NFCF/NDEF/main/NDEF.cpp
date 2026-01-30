/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916
  Read/write NDEF NFC-F PICC
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
using namespace m5::nfc::ndef;

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
m5::nfc::NFCLayerF nfc_f{unit};

void read_ndef()
{
    TLV msg{};

    // Read NDEF message TLV
    if (!nfc_f.ndefRead(msg)) {
        M5_LOGE("Failed to read");
        return;
    }

    // If it does not exist, a Null TLV is returned
    if (msg.isMessageTLV()) {
        lcd.setCursor(0, lcd.fontHeight());
        M5.Log.printf("==== MDEF Message %zu records ====\n", msg.records().size());
        for (auto&& r : msg.records()) {
            switch (r.tnf()) {
                case TNF::Wellknown: {
                    auto s = r.payloadAsString().c_str();
                    M5.Log.printf("SZ:%3u TNF:%u T:%s [%s]\n", r.payloadSize(), r.tnf(), r.type(), s);
                    lcd.printf("T:%s [%s]\n", r.type(), s);
                } break;
                default:
                    M5.Log.printf("SZ:%3u TNF:%u T:%s\n", r.payloadSize(), r.tnf(), r.type());
                    break;
            }
        }
    } else {
        M5.Log.printf("NDEF Message TLV is NOT exists\n");
    }
}

void write_ndef()
{
    TLV msg{Tag::Message};  // NDEF Message TLV
    Record r[4] = {};       // Wellknown as default

    // Change format to support NDEF
    if (!nfc_f.writeSupportNDEF(true)) {
        M5_LOGE("Failed to writeSupportNDEF");
        return;
    }

    // URI record
    r[0].setURIPayload("m5stack.com/", URIProtocol::HTTPS);

    // Text record with langage type
    const char* en_data = "Hello M5Stack";
    r[1].setTextPayload(en_data, "en");
    const char* ja_data = "こんにちは M5Stack";
    r[2].setTextPayload(ja_data, "ja");
    const char* zh_data = "你好 M5Stack";
    r[3].setTextPayload(zh_data, "zh");

    uint32_t max_user_size = nfc_f.activatedPICC().userAreaSize() - 1 /* terminator TLV */;
    for (auto&& rr : r) {
        msg.push_back(rr);
        if (msg.required() > max_user_size) {
            msg.pop_back();
            break;
        }
    }

    if (!nfc_f.ndefWrite(msg)) {
        M5_LOGE("Failed to write");
        return;
    }
    nfc_f.dump();
}

}  // namespace

void setup()
{
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);

    auto cfg = unit.config();
    cfg.mode = NFC::F;
    unit.config(cfg);

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
    bool clicked = M5.BtnA.wasClicked();  // For read
    bool held    = M5.BtnA.wasHold();     // For write

    if (clicked || held) {
        PICC picc{};
        if (nfc_f.detect(picc)) {
            if (nfc_f.activate(picc)) {
                M5.Log.printf("%s:%s %s F:%02X DF:%04X\n", picc.idmAsString().c_str(), picc.pmmAsString().c_str(),
                              picc.typeAsString().c_str(), picc.format, picc.dfc_format);

                if (clicked) {
                    M5.Speaker.tone(2000, 30);
                    lcd.fillScreen(TFT_BLUE);
                    nfc_f.dump();
                    read_ndef();
                } else if (held) {
                    M5.Speaker.tone(4000, 30);
                    lcd.fillScreen(TFT_YELLOW);
                    write_ndef();
                }
                M5.Log.printf("Please remove the PICC from the reader\n");
                nfc_f.deactivate();
            }
            lcd.setCursor(0, 0);
            lcd.printf("Please put the PICC and click/hold BtnA");
            M5.Log.printf("Please put the PICC and click/hold BtnA\n");
        } else {
            M5.Log.printf("PICC NOT exists\n");
        }
    }
}
