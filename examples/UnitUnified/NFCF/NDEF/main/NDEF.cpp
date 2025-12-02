/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for M5Cardputer-ADV with HackerCap
  NDEF example
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedNFC.h>
#include <M5Utility.h>
#include <vector>

using namespace m5::nfc;
using namespace m5::nfc::f;
using namespace m5::nfc::ndef;

namespace {
auto& lcd = M5.Display;
m5::unit::UnitUnified Units;
m5::unit::CapST25R3916 cap;  // ST25R3916 in the HackerCap
m5::unit::nfc::NFCLayerF nfc_f{cap};

void read_ndef(const PICC& picc)
{
    TLV msg;
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
                    lcd.printf("T:%s\n", r.type());
                    if (strcmp(r.type(), "image/png") == 0) {
                        lcd.drawPng(r.payload(), r.payloadSize(), lcd.width() >> 1, lcd.height() >> 1);
                    }
                    break;
            }
        }
    } else {
        M5.Log.printf("NDEF Message TLV is NOT exists\n");
    }
}

void write_ndef(const PICC& picc)
{
    TLV msg{};         // Message as default
    Record r[4] = {};  // Wellknown as default

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

    uint32_t max_user_size = picc.userAreaSize() - 1 /* terminator TLV */;
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
    bool clicked = M5.BtnA.wasClicked();  // For read
    bool held    = M5.BtnA.wasHold();     // For write

    if (clicked || held) {
        PICC picc{};
        if (nfc_f.detect(picc)) {
            if (nfc_f.activate(picc)) {
                M5.Log.printf("  %s:%s %s F:%02X DF:%04X\n", picc.idmAsString().c_str(), picc.pmmAsString().c_str(),
                              picc.typeAsString().c_str(), picc.format, picc.dfc_format);

                if (clicked) {
                    M5.Speaker.tone(2000, 30);
                    lcd.fillScreen(TFT_BLUE);
                    read_ndef(picc);
                } else if (held) {
                    M5.Speaker.tone(4000, 30);
                    lcd.fillScreen(TFT_YELLOW);
                    write_ndef(picc);
                }
                M5.Log.printf("Please remove the PICC from the reader\n");
                nfc_f.deactivate();
            }
            lcd.setCursor(0, 0);
            lcd.printf("Please put the PICC and click/hold G0");
            M5.Log.printf("Please put the PICC and click/hold G0\n");
        } else {
            M5.Log.printf("PICC NOT exists\n");
        }
    }
}
