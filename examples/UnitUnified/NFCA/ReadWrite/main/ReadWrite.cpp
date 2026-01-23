/*
 * SPDX-FileCopyrightText: 2024 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for M5Unit-NFC/RFID
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

// KeyA that can authenticate all blocks (Classic)
// If it's a different key value, change it
constexpr classic::Key keyA = classic::DEFAULT_KEY;  // Default as 0xFFFFFFFFFFFF
// AES KeyA that can authenticate all blocks (Plus SL3)
// If it's a different key value, change it
constexpr plus::AESKey aesKeyA = plus::DEFAULT_FF_KEY;  // all 0xFF

constexpr char long_msg[] =
    "This is a sample message buffer used for testing NFC page writes and data integrity verification purposes.";
constexpr char short_msg[] = "0123456789ABCDEFGHIJ";

struct ReadWriteOps {
    const char* label;
    bool (*read)(uint8_t*, uint16_t&, const uint8_t);
    bool (*write)(const uint8_t, const uint8_t*, const uint16_t);
    bool (*dump_block)(const uint8_t);
};

bool read_default(uint8_t* buf, uint16_t& len, const uint8_t block)
{
    return nfc_a.read(buf, len, block, keyA);
}

bool write_default(const uint8_t block, const uint8_t* buf, const uint16_t len)
{
    return nfc_a.write(block, buf, len, keyA);
}

bool read_plus_sl3(uint8_t* buf, uint16_t& len, const uint8_t block)
{
    return nfc_a.read(buf, len, block, aesKeyA);
}

bool write_plus_sl3(const uint8_t block, const uint8_t* buf, const uint16_t len)
{
    return nfc_a.write(block, buf, len, aesKeyA);
}

bool dump_default(const uint8_t block)
{
    return (nfc_a.activatedPICC().isMifareClassic()
                ? nfc_a.mifareClassicAuthenticateA(classic::get_sector_trailer_block(block), keyA)
                : true) &&
           nfc_a.dump(block);
}

bool dump_plus_sl3(const uint8_t block)
{
    return nfc_a.dump(block);
}

static ReadWriteOps select_rw_ops()
{
    auto& picc = nfc_a.activatedPICC();
    if (picc.isMifarePlus() && picc.security_level == 3) {
        return {"PlusSL3", read_plus_sl3, write_plus_sl3, dump_plus_sl3};
    }
    return {"Default", read_default, write_default, dump_default};
}

void read_all_user_area()
{
    auto& picc = nfc_a.activatedPICC();

    static uint8_t buf[4096]{};
    uint16_t rx_len{4096};
    memset(buf, 0x52, sizeof(buf));

    if ((picc.isMifarePlus() && picc.security_level == 3) ? nfc_a.read(buf, rx_len, picc.firstUserBlock(), aesKeyA)
                                                          : nfc_a.read(buf, rx_len, picc.firstUserBlock(), keyA)) {
        M5.Log.printf("User area %u\n", rx_len);
        M5.Log.printf("--------------------------------\n");
        m5::utility::log::dump(buf, rx_len, false);
        M5.Log.printf("--------------------------------\n");
    } else {
        M5_LOGE("Failed to read");
    }
}

// Using read/write for all
bool read_write(const uint8_t sblock, const char* msg)
{
    auto ops = select_rw_ops();
    auto len = strlen(msg);
    uint8_t buf[(strlen(msg) + 15) / 16 * 16]{};
    uint16_t rx_len = sizeof(buf);

    // Write
    M5.Log.printf("================================ WRITE %s %u len:%zu\n", ops.label, sblock, sizeof(buf));
    if (ops.write(sblock, (const uint8_t*)msg, len)) {
        lcd.fillScreen(TFT_ORANGE);
        ops.dump_block(sblock);

        // Verify
        if (ops.read(buf, rx_len, sblock)) {
            lcd.fillScreen(TFT_BLUE);
            M5.Log.printf("================================ VERIFY:%s\n", memcmp(buf, msg, len) == 0 ? "OK" : "NG");
            if (memcmp(buf, msg, len)) {
                m5::utility::log::dump(buf, rx_len, false);
                M5_LOGE("VERIFY NG!!");
            }

            // Clear
            memset(buf, 0, sizeof(buf));
            lcd.fillScreen(TFT_MAGENTA);
            if (ops.write(sblock, buf, sizeof(buf))) {
                M5.Log.printf("================================ CLEAR\n");
                ops.dump_block(sblock);
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
void read_write_sector_structure(const uint8_t block)
{
    constexpr char msg[] = "M5Unit-RFID";

    // Read and write access with A authentication
    if (!nfc_a.mifareClassicAuthenticateA(block, keyA)) {
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

// Using read4,write4 for Ultralight,NTAG
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
    uint8_t rbuf[4]{};
    if (!nfc_a.read4(rbuf, page)) {
        M5_LOGE("Failed to read");
        return;
    }

    bool verify = std::memcmp(rbuf, (const uint8_t*)msg, sizeof(msg)) == 0;
    M5.Log.printf("Verify %u %s\n", picc.isNTAG2(), verify ? "OK" : "NG");
    if (!verify) {
        M5_LOGE("VERIFY NG!!");
        m5::utility::log::dump(msg, sizeof(msg), false);
        m5::utility::log::dump(rbuf, sizeof(rbuf), false);
    }

    // Clear
    M5.Log.printf("Clear\n");
    uint8_t c[1]{};
    if (!nfc_a.write4(page, c, sizeof(c))) {
        M5_LOGE("Failed to write");
        return;
    }
    nfc_a.dump(aligned_page);
}

// For file base system (DESFire, ST25TA etc...)
bool read_write_file_base()
{
    return true;
}

}  // namespace

void setup()
{
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);

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
                bool file_system_flat_memory = picc.isFileSystemFlatMemory();
                if (clicked) {
                    M5.Speaker.tone(2000, 30);
                    if (file_system_flat_memory) {
                        // read_all_user_area();
                        auto ret = read_write(picc.firstUserBlock(), picc.userAreaSize() >= 120 ? long_msg : short_msg);
                        lcd.fillScreen(ret ? 0 : TFT_RED);
                    } else {
                        auto ret = read_write_file_base();
                        lcd.fillScreen(ret ? 0 : TFT_RED);
                    }
                } else if (held) {
                    nfc_a.dump();
#if 0
                    M5.Speaker.tone(4000, 30);
                    if (picc.isMifareClassic()) {
                        read_write_sector_structure(picc.blocks - 2);
                    } else if (picc.supportsNFC()) {
                        read_write_page_structure(picc, 10);
                    } else {
                        M5_LOGE("No example");
                    }
#endif
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
