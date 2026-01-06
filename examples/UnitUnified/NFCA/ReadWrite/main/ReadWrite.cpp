/*
 * SPDX-FileCopyrightText: 2024 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916
  Read/write NFC-A PICC
  This example is shared with M5Unit-RFID

  NFCLayerA
  read/write are performed only on the user area.
  raed4/write4, raed16/write16 allows access to any position by setting safety == false, or use the  unit-side API.
  See also each header and Doxygen docuemnt.
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

constexpr char long_msg[] =
    "This is a sample message buffer used for testing NFC page writes and data integrity verification purposes.";
constexpr char short_msg[] = "0123456789ABCDEFGHIJ";

void read_all_user_area(const Key& key)
{
    static uint8_t buf[4096]{};
    uint16_t rx_len{4096};
    memset(buf, 0x52, sizeof(buf));

    if (nfc_a.read(buf, rx_len, 0, key)) {
        M5.Log.printf("User area %u\n", rx_len);
        M5.Log.printf("--------------------------------\n");
        m5::utility::log::dump(buf, rx_len, false);
        M5.Log.printf("--------------------------------\n");
    } else {
        M5_LOGE("Failed to read");
    }
}

// Using read/write for all
bool read_write(const uint8_t sblock, const char* msg, const Key& key)
{
    auto len = strlen(msg);
    uint8_t buf[(strlen(msg) + 15) / 16 * 16]{};
    uint16_t rx_len = sizeof(buf);

    // Write
    M5.Log.printf("================================ WRITE\n");
    if (nfc_a.write(sblock, (const uint8_t*)msg, len, key)) {
        lcd.fillScreen(TFT_ORANGE);
        nfc_a.dump();

        // Verify
        if (nfc_a.read(buf, rx_len, sblock, key)) {
            lcd.fillScreen(TFT_BLUE);
            M5.Log.printf("================================ VERIFY:%s\n", memcmp(buf, msg, len) == 0 ? "OK" : "NG");
            m5::utility::log::dump(buf, rx_len, false);

            // Clear
            memset(buf, 0, sizeof(buf));
            lcd.fillScreen(TFT_MAGENTA);
            if (nfc_a.write(sblock, buf, sizeof(buf), key)) {
                M5.Log.printf("================================ CLEAR\n");
                nfc_a.dump();
                return true;
            } else {
                M5_LOGE("Failed to write");
            }
        } else {
            M5_LOGE("Failed to read");
        }
    } else {
        M5_LOGE("Failed to write %u", sblock);
    }
    return false;
}

// Using read16/write16 for MIFARE classic
void read_write_sector_structure(const uint8_t block, const Key& key)
{
    constexpr char msg[] = "M5Unit-RFID";

    // Read and write access with A authentication
    if (!nfc_a.mifareClassicAuthenticateA(block, key)) {
        M5_LOGE("Failed to AuthA");
        return;
    }

    M5.Log.printf("Before[%u] ----\n", block);
    nfc_a.dump(block);

    M5.Log.printf("Write\n");
    if (!nfc_a.write16(block, (const uint8_t*)msg, sizeof(msg))) {
        M5_LOGE("Failed to write");
        return;
    }
    M5.Log.printf("After[%u] ----\n", block);
    nfc_a.dump(block);

    // Read
    uint8_t rbuf[16]{};
    if (!nfc_a.read16(rbuf, block)) {
        M5_LOGE("Failed to read");
        return;
    }

    // Verify
    bool verify = std::memcmp(rbuf, (const uint8_t*)msg, sizeof(msg)) == 0;
    M5.Log.printf("Verify %s\n", verify ? "OK" : "NG");

    // Clear
    M5.Log.printf("Clear\n");
    uint8_t c[1]{};
    if (!nfc_a.write16(block, c, sizeof(c))) {
        M5_LOGE("Failed to write");
        return;
    }
    nfc_a.dump(block);
}

// Using read4,16/write4 for Ultralight,NTAG
void read_write_page_structure(const PICC& picc, const uint8_t page)
{
    constexpr char msg[] = "M5";

    // Ultralight can only be read in 4 page (16bytes) units
    uint8_t aligned_page = page & ~0x03;

    M5.Log.printf("Before[%u] ----\n", page);
    nfc_a.dump(aligned_page);

    if (!nfc_a.write4(page, (const uint8_t*)msg, sizeof(msg))) {
        M5_LOGE("Failed to write");
        return;
    }
    M5.Log.printf("After[%u] ----\n", page);
    nfc_a.dump(aligned_page);

    // Read
    uint8_t rbuf[16]{};
    if (picc.isNTAG()) {
        if (!nfc_a.read4(rbuf, page)) {
            M5_LOGE("Failed to read");
            return;
        }
    } else {
        if (!nfc_a.read16(rbuf, aligned_page)) {
            M5_LOGE("Failed to read");
            return;
        }
    }

    bool verify = std::memcmp(rbuf, (const uint8_t*)msg, sizeof(msg)) == 0;
    M5.Log.printf("Verify %s\n", verify ? "OK" : "NG");

    // Clear
    M5.Log.printf("Clear\n");
    uint8_t c[1]{};
    if (!nfc_a.write4(page, c, sizeof(c))) {
        M5_LOGE("Failed to write");
        return;
    }
    nfc_a.dump(aligned_page);
}

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

    lcd.setCursor(0, 0);
    lcd.printf("Please put the PICC and click/hold BtnA");
    M5.Log.printf("Please put the PICC and click/hold BtnA\n");
}

void loop()
{
    M5.update();
    Units.update();
    bool clicked = M5.BtnA.wasClicked();
    bool held    = M5.BtnA.wasHold();

    if (clicked || held) {
        PICC picc;
        if (nfc_a.detect(picc)) {
            lcd.fillScreen(TFT_DARKGREEN);
            if (nfc_a.identify(picc) && nfc_a.reactivate(picc)) {
                M5.Log.printf("PICC:%s %s %u/%u\n", picc.uidAsString().c_str(), picc.typeAsString().c_str(),
                              picc.userAreaSize(), picc.totalSize());

                if (clicked) {
                    M5.Speaker.tone(2000, 30);
                    // Need key if MIFARE classic, Ignore key if not MIFARE classic
                    read_all_user_area(keyA);
                    auto ret = read_write(0, picc.userAreaSize() >= 120 ? long_msg : short_msg, keyA);
                    lcd.fillScreen(ret ? 0 : TFT_RED);
                } else if (held) {
                    M5.Speaker.tone(4000, 30);
                    if (picc.isMifareClassic()) {
                        read_write_sector_structure(picc.blocks - 2, keyA);
                    } else if (picc.supportsNFC()) {
                        read_write_page_structure(picc, 10);
                    } else {
                        M5_LOGE("Not support");
                    }
                }
                nfc_a.deactivate();
            } else {
                M5_LOGE("Failed to identify/activate %s", picc.uidAsString().c_str());
            }

        } else {
            M5.Log.printf("PICC NOT exists\n");
        }
        lcd.setCursor(0, 0);
        lcd.printf("Please put the PICC and click/hold BtnA");
        M5.Log.printf("Please put the PICC and click/hold BtnA\n");
    }
}
