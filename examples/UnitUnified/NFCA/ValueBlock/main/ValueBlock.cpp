/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916
  Value block for MIFARE classic
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
#else
#error Choose unit please!
#endif
m5::nfc::NFCLayerA nfc_a{unit};

// KeyA,B that can authenticate all blocks
// If it's a different key value, change it
constexpr Key keyA = DEFAULT_KEY;  // Default as 0xFFFFFFFFFFFF
constexpr Key keyB = DEFAULT_KEY;  // Default as 0xFFFFFFFFFFFF

#if 0
void print_value_block(const Key& key)
{
    uint32_t count{};
    uint8_t st_block{};
    for (uint_fast16_t block = 0; block < nfc_a.activatedPICC().blocks; ++block) {
        uint8_t stb = get_sector_trailer_block(block);
        if (stb != st_block) {
            st_block = stb;
            // M5_LOGI("AUTH: %u", st_block);
            if (!nfc_a.mifareClassicAuthenticateA(st_block, key)) {
                M5_LOGE("Failed to AUTH %u/%u", block, st_block);
                return;
            }
        }
        bool vb{};
        if (!nfc_a.mifareClassicIsValueBlock(vb, block)) {
            M5_LOGE("Failed %u", block);
            return;
        }
        if (vb) {
            int32_t value{};
            if (nfc_a.mifareClassicReadValueBlock(value, block)) {
                ++count;
                M5.Log.printf("[%3u]:%" PRId32 "\n", block, value);
            } else {
                M5_LOGE("Failed %u", block);
                return;
            }
        }
    }
    M5.Log.printf("%u value blocks\n", count);
}

void print_access_conditions(const Key& akey, const Key& key)
{
    uint8_t st_block{};
    for (uint_fast16_t block = 0; block < nfc_a.activatedPICC().blocks; ++block) {
        uint8_t stb = get_sector_trailer_block(block);
        if (stb != st_block) {
            st_block = stb;
            // M5_LOGI("AUTH: %u", st_block);
            if (!nfc_a.mifareClassicAuthenticateA(st_block, key)) {
                M5_LOGE("Failed to AUTH %u/%u", block, st_block);
                return;
            }
        }
        uint8_t ab{};
        if (!nfc_a.mifareClassicReadAccessCondition(ab, block)) {
            M5_LOGE("Failed %u", block);
            return;
        }
        M5.Log.printf("[%3u]:%02X\n", block, ab);
    }
}
#endif

void non_rechargeable_value_block(const uint8_t block, const Key& akey, const Key& bkey)
{
    auto& picc = nfc_a.activatedPICC();
    if (!picc.isUserBlock(block) || !picc.isUserBlock(block - 1)) {
        M5_LOGE("block and block - 1 must be user block %u %u", block, block - 1);
        return;
    }

    if (!nfc_a.mifareClassicAuthenticateA(block, akey)) {
        M5_LOGE("Failed to AUTH A %u/%u", block, block);
        return;
    }

    // Change read/write block
    if (!nfc_a.mifareClassicWriteAccessCondition(block, READ_WRITE_BLOCK, akey, bkey)) {
        M5_LOGE("Failed to WriteAccessCondition %u", block);
        return;
    }

    // Write value
    if (!nfc_a.mifareClassicWriteValueBlock(block, 1234567)) {
        M5_LOGE("Failed to WriteValue %u", block);
        return;
    }

    // After writing the value, change it to the value block (Non rechargeable)
    if (!nfc_a.mifareClassicWriteAccessCondition(block, VALUE_BLOCK_NON_RECHARGEABLE, akey, bkey)) {
        M5_LOGE("Failed to WriteAccessCondition %u", block);
        return;
    }
    M5.Log.printf("==== Initial value\n");
    nfc_a.dump(block);

    // Decrement and transfer value
    if (!nfc_a.mifareClassicDecrementValueBlock(block, 4567u)) {
        M5_LOGE("Failed to decrement %u", block);
        return;
    }
    M5.Log.printf("==== Decrement done\n");
    nfc_a.dump(block);

    // Incremental operations cannot be performed because charging is not possible
    if (nfc_a.mifareClassicIncrementValueBlock(block, 9876543)) {
        M5_LOGE("Oops!?!?");
        return;
    } else {
        // Passing through this block is normal
        M5.Log.printf("Incremental operations cannot be performed because charging is not possible\n");
        // The Increment command failed, causing a HALT, so need reactivate and auth
        if (!nfc_a.reactivate()) {
            M5_LOGE("Failed to reactivate");
            return;
        }
        if (!nfc_a.mifareClassicAuthenticateA(block, akey)) {
            M5_LOGE("Failed to AUTH %u/%u", block, block);
            return;
        }
        M5.Log.printf("==== Can NOT increment\n");
        nfc_a.dump(block);
    }

    // Copy value block
    if (!nfc_a.mifareClassicRestoreValueBlock(block)) {
        M5_LOGE("Failed to restore %u", block);
        return;
    }
    if (!nfc_a.mifareClassicTransferValueBlock(block - 1)) {
        M5_LOGE("Failed to transfer %u", block);
        return;
    }
    M5.Log.printf("==== Copy from %u to %u\n", block, block - 1);
    nfc_a.dump(block);

    // Change read/write block and clear
    if (!nfc_a.mifareClassicWriteAccessCondition(block, READ_WRITE_BLOCK, akey, bkey)) {
        M5_LOGE("Failed to WriteAccessCondition%u", block);
        return;
    }
    uint8_t c[1]{};
    if (!nfc_a.write16(block, c, sizeof(c)) || !nfc_a.write16(block - 1, c, sizeof(c))) {
        M5_LOGE("Failed to Write %u/%u", block, block - 1);
        return;
    }

    M5.Log.printf("==== To be normal block\n");
    nfc_a.dump(block);
}

void rechargeable_value_block(const uint8_t block, const Key& akey, const Key& bkey)
{
    auto& picc = nfc_a.activatedPICC();
    if (!picc.isUserBlock(block) || !picc.isUserBlock(block - 1)) {
        M5_LOGE("block and block - 1 must be user block %u %u", block, block - 1);
        return;
    }

    // Auth A
    uint8_t stb = get_sector_trailer_block(block);
    if (!nfc_a.mifareClassicAuthenticateA(stb, akey)) {
        M5_LOGE("Failed to AUTH A %u/%u", block, stb);
        return;
    }

    // KeyB authentication is required for Increment operations
    // Additionally, KeyB must be read-only
    // Some cards may function even if the sector trailer access bit is 001, but strictly speaking, 110 or similar is
    // preferable
    // Change Sector trailer access bits
    //       RkeyA  WkeyA    RAb       WAb     ***RkeyB***   WkeyB
    // 011 | never | key B | key A|B | key B | ***never*** | key B |
    if (!nfc_a.mifareClassicWriteAccessCondition(stb, 0x03 /*011*/, akey, bkey)) {
        M5_LOGE("Failed to WriteAccessCondition %u", stb);
        return;
    }

    // Auth B
    if (!nfc_a.mifareClassicAuthenticateB(block, bkey)) {
        M5_LOGE("Failed to AUTH A %u/%u", block, stb);
        return;
    }

    // Change read/write block
    if (!nfc_a.mifareClassicWriteAccessCondition(block, READ_WRITE_BLOCK, akey, bkey)) {
        M5_LOGE("Failed to WriteAccessCondition %u", block);
        return;
    }
    // Write value
    if (!nfc_a.mifareClassicWriteValueBlock(block, 1234567)) {
        M5_LOGE("Failed to WriteValue %u", block);
        return;
    }

    // After writing the value, change it to the value block (rechargeable)
    if (!nfc_a.mifareClassicWriteAccessCondition(block, VALUE_BLOCK_RECHARGEABLE, akey, bkey)) {
        M5_LOGE("Failed to WriteAccessCondition %u", block);
        return;
    }
    M5.Log.printf("==== Initial value\n");
    nfc_a.dump(block);

    // Decrement and transfer value
    if (!nfc_a.mifareClassicDecrementValueBlock(block, 4567u)) {
        M5_LOGE("Failed to decrement %u", block);
        return;
    }
    M5.Log.printf("==== Decrement done\n");
    nfc_a.dump(block);

    // Increment and transfer value
    if (!nfc_a.mifareClassicIncrementValueBlock(block, 99u)) {
        M5_LOGE("Failed to increment %u", block);
        return;
    }
    M5.Log.printf("==== Increment done\n");
    nfc_a.dump(block);

    // Copy value block
    if (!nfc_a.mifareClassicRestoreValueBlock(block)) {
        M5_LOGE("Failed to restore %u", block);
        return;
    }
    if (!nfc_a.mifareClassicTransferValueBlock(block - 1)) {
        M5_LOGE("Failed to transfer %u", block);
        return;
    }
    M5.Log.printf("==== Copy from %u to %u\n", block, block - 1);
    nfc_a.dump(block);

    // Change read/write block and clear
    if (!nfc_a.mifareClassicWriteAccessCondition(block, READ_WRITE_BLOCK, akey, bkey)) {
        M5_LOGE("Failed to WriteAccessCondition%u", block);
        return;
    }
    uint8_t c[1]{};
    if (!nfc_a.write16(block, c, sizeof(c)) || !nfc_a.write16(block - 1, c, sizeof(c))) {
        M5_LOGE("Failed to Write %u/%u", block, block - 1);
        return;
    }

    // Restore access bits
    if (!nfc_a.mifareClassicWriteAccessCondition(stb, 0x01 /*001*/, akey, bkey)) {
        M5_LOGE("Failed to WriteAccessCondition %u", stb);
        return;
    }
    if (!nfc_a.mifareClassicAuthenticateA(stb, akey)) {
        M5_LOGE("Failed to AUTH A %u/%u", block, stb);
        return;
    }

    M5.Log.printf("==== To be normal block\n");
    nfc_a.dump(block);
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
    bool clicked = M5.BtnA.wasClicked();  // For decrement
    bool held    = M5.BtnA.wasHold();     // For increment

    if (clicked || held) {
        PICC picc{};
        if (nfc_a.detect(picc)) {
            if (nfc_a.identify(picc) && nfc_a.reactivate(picc)) {
                M5.Log.printf("PICC:%s %s %u/%u\n", picc.uidAsString().c_str(), picc.typeAsString().c_str(),
                              picc.userAreaSize(), picc.totalSize());
                if (picc.isMifareClassic()) {
                    if (clicked) {
                        M5.Speaker.tone(2000, 30);
                        lcd.fillScreen(TFT_BLUE);
                        M5.Log.print("Non rechargeable\n");
                        non_rechargeable_value_block(picc.blocks - 2, keyA, keyB);
                    } else if (held) {
                        M5.Speaker.tone(4000, 30);
                        lcd.fillScreen(TFT_YELLOW);
                        M5.Log.print("Rechargeable\n");
                        rechargeable_value_block(picc.blocks - 2, keyA, keyB);
                    }
                    M5.Log.printf("Please remove the PICC from the reader\n");
                } else {
                    M5.Log.printf("Not support the value block\n");
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
