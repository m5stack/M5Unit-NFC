/*
 * SPDX-FileCopyrightText: 2024 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916
  Read/Write with MAC example for FeliCa Lite-S

  *******************************************************************************************************************
  NOTICE: Please note that cards that have undergone the initial issuance procedure cannot be read without subsequent
  authentication.
  *******************************************************************************************************************
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedNFC.h>
#include <M5Utility.h>
#include <vector>
#include <esp_random.h>
#include <mbedtls/md.h>

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
using m5::utility::crypto::TripleDES;

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

// The master key used for create CK
// For the sake of this example, it's written as source code, but it should actually outside externally (SD, Cloud...)
constexpr uint8_t example_master_key[24] = {0xE3, 0x92, 0xCA, 0xC2, 0xF9, 0x21, 0x3B, 0xF2, 0xC0, 0x4F, 0x65, 0xC4,
                                            0x8E, 0xB6, 0xF6, 0x34, 0x5F, 0x02, 0x36, 0xD6, 0x26, 0xD5, 0x97, 0xA1};
//  Card key version(Format is free)
// For the sake of this example, it's written as source code, but it should actually outside externally (SD, Cloud...)
constexpr uint16_t example_ckv{0x0509};

// HMAC-SHA256
void hmac_sha256(uint8_t out[32], const uint8_t* key, const uint32_t key_len, const uint8_t* input,
                 const uint32_t input_len)
{
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1 /* HMAC */);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char*)key, key_len);
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)input, input_len);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

/*
  Example of Creating a Card Key from the Master Key
  We are uniquely determining each card's CK from the IDm and master_key
  If you want a different method, please implement it yourself.

  CK = first 16 bytes (HMAC-SHA256(master_key, "M5Stack" || CKV || IDm))
*/
void derive_card_key(uint8_t ck[16], const uint8_t master_key[24], const uint16_t ckv, const uint8_t idm[8])
{
    uint8_t msg[32]{};
    uint32_t pos = 0;
    // Any prefix
    msg[pos++] = 'M';
    msg[pos++] = '5';
    msg[pos++] = 'S';
    msg[pos++] = 't';
    msg[pos++] = 'a';
    msg[pos++] = 'c';
    msg[pos++] = 'k';
    // Key version
    msg[pos++] = (ckv >> 8) & 0xFF;
    msg[pos++] = (ckv >> 0) & 0xFF;
    // IDm
    std::memcpy(msg + pos, idm, 8);
    pos += 8;
    // Additional context information may be added if necessary
    //...

    uint8_t digest[32]{};
    hmac_sha256(digest, master_key, 24, msg, pos);
    std::memcpy(ck, digest, 16);
}

bool internal_auth()
{
    const auto& picc = nfc_f.activatedPICC();
    if (!picc.valid()) {
        return false;
    }

    uint8_t ck[16]{};
    derive_card_key(ck, example_master_key, example_ckv, picc.idm.data());
    //    M5.Log.printf("==== CK:\n");
    //    m5::utility::log::dump(ck, 16, false);

    // Make random challenge
    uint8_t rc[16]{};
    for (auto& r : rc) {
        r = esp_random();
    }
    //    m5::utility::log::dump(rc, 16, false);

    // Authenticattion
    return nfc_f.internalAuthenticate(ck, example_ckv, rc);
}

bool external_auth()
{
    const auto& picc = nfc_f.activatedPICC();
    if (!picc.valid()) {
        return false;
    }

    uint8_t ck[16]{};
    derive_card_key(ck, example_master_key, example_ckv, picc.idm.data());
    //    M5.Log.printf("==== CK:\n");
    //    m5::utility::log::dump(ck, 16, false);

    // Authenticattion
    return nfc_f.externalAuthenticate(ck, example_ckv);
}

void read_example()
{
    uint8_t rx[16]{};

    // nfc_f.dump(lite_s::MC);

    if (!nfc_f.read16(rx, 1)) {
        M5.Log.printf("Failed to read 1 (need auth)\n");
    } else {
        M5.Log.printf("read block 1 without auth OK\n");
        // m5::utility::log::dump(rx, 16, false);
    }
    if (!nfc_f.read16(rx, 0)) {
        M5.Log.printf("Failed to read 0 (need auth)\n");
    } else {
        M5.Log.printf("read block 0 without auth OK\n");
        // m5::utility::log::dump(rx, 16, false);
    }

    if (!internal_auth()) {
        // ******************************************************************************
        // If the first_issuance_procedure_lite_s() has not been executed, an error will occur here.
        // ******************************************************************************
        M5_LOGE("Failed to internalAuthenticate");
        lcd.fillScreen(TFT_RED);
        return;
    }
    M5.Log.printf("internal auth OK\n");

    // Read block
    if (nfc_f.readWithMAC16(rx, 1)) {
        M5.Log.printf("Read block 1 OK\n");
        m5::utility::log::dump(rx, 16, false);
    } else {
        M5_LOGE("Failed to read 1");
    }

    // Read block 0
    if (!external_auth()) {
        M5_LOGE("Failed to externalAuthenticate");
        lcd.fillScreen(TFT_RED);
        return;
    }
    M5.Log.printf("external auth OK\n");

    if (!nfc_f.read16(rx, 0)) {
        M5.Log.printf("You can NOT read16");
    } else {
        M5_LOGE("Oops!");
        m5::utility::log::dump(rx, 16, false);
    }
    if (nfc_f.readWithMAC16(rx, 0)) {
        M5.Log.printf("Read block 0 OK\n");
        m5::utility::log::dump(rx, 16, false);
    } else {
        M5_LOGE("Failed to read 0");
    }

    lcd.fillScreen(0);
}

bool first_issuance_procedue_lite_s(const PICC& picc, const uint8_t master_key[24], const uint16_t ckv)
{
    uint8_t rbuf[16 * 4]{};

    M5.Log.printf("First issuance procedue...\n");

    // 7.3.2 Write ID (No DFC)
    if (!nfc_f.write16(lite_s::ID, picc.idm.data(), 8) || !nfc_f.read16(rbuf, lite_s::ID)) {
        M5_LOGE("Failed to write/read ID");
        return false;
    }
    if (memcmp(rbuf, picc.idm.data(), 8) != 0) {
        M5_LOGE("Failed to verify ID");
        return false;
    }
    M5.Log.printf("  Write ID OK\n");

    // 7.3.3 Write CK
    uint8_t ck[16]{};
    uint8_t wbuf[2]{};
    wbuf[0] = ckv >> 8;
    wbuf[1] = ckv & 0xFF;
    derive_card_key(ck, master_key, ckv, picc.idm.data());

    //    M5.Log.printf("==== CK:\n");
    //    m5::utility::log::dump(ck, 16, false);

    if (!nfc_f.write16(lite_s::CK, ck, sizeof(ck)) || !nfc_f.write16(lite_s::CKV, wbuf, 2)) {
        M5_LOGE("Failed to write/read CK");
        return false;
    }

    M5.Log.printf("  Write CK OK\n");

    // 7,3.4 Verify CK
    uint8_t rc[16]{};
    for (auto& r : rc) {
        r = esp_random();
    }
    if (!nfc_f.internalAuthenticate(ck, ckv, rc)) {
        M5_LOGE("Failed to verify CK");
        return false;
    }
    nfc_f.clearAuthenticate();

    M5.Log.printf("  Verify CK OK\n");

    // 7.3.5 Write CKV
    wbuf[0] = ckv >> 8;
    wbuf[1] = ckv & 0xFF;
    m5::utility::log::dump(wbuf, 2, false);
    if (!nfc_f.write16(lite_s::CKV, wbuf, 2) || !nfc_f.read16(rbuf, lite_s::CKV)) {
        M5_LOGE("Failed to write/read CKV");
        return false;
    }
    if (memcmp(wbuf, rbuf, 2) != 0) {
        M5_LOGE("Failed to verify CKV");
        return false;
    }

    M5.Log.printf("  Write/Verify CKV OK\n");

#if 0    
    // 7.3.6 Write user block (optional)
    constexpr char msg[16] = "M5Stack-NFC";
    if (!nfc_f.write16(0, (uint8_t*)msg, sizeof(msg)) || !nfc_f.read16(rbuf, 0)) {
        M5_LOGE("Failed to write/read 0");
        return false;
    }
    if (memcmp(msg, rbuf, sizeof(msg)) != 0) {
        M5_LOGE("Failed to verify 0");
        return false;
    }
#endif

    // 7.3.7 MC settings
    uint8_t mc[16]{};
    if (!nfc_f.read16(mc, lite_s::MC)) {
        M5_LOGE("Failed to read MC");
        return false;
    }
    // MC_SP_REG_W_MAC_A (Must be MC_SP_REG_W_RESTR,MC_SP_REG_R_RESTR bit on)
    mc[10] = 0x01;  // Write SPAD_0 needs MAC -> external auth
    // MC_SP_REG_W_RESTR
    mc[8] = 0x01;  // Write SPAD_0,1 needs Auth
    // MC_SP_REG_R_RESTR
    mc[6] = 0x01;  // Read SPAD_0,1 needs Auth
    // MC_CKCKV_W_MAC_A
    // mc[5]  = 0x01;  // Write CK and CKV needs MAC
    // RF_PRM
    mc[4] = 0x07;  // Fixed value
    // SYS_OP
    mc[3] = 0x00;  // 0x01 NDEF
    // MC_ALL
    mc[2] = 0xFF;

    // Some blocks should be set to read-only (not done in this example)
    if (!nfc_f.write16(lite_s::MC, mc, 16) || !nfc_f.read16(rbuf, lite_s::MC)) {
        M5_LOGE("Failed to write/read MC");
        return false;
    }
    if (memcmp(mc, rbuf, 16) != 0) {
        M5_LOGE("Failed to verify MC");
        return false;
    }

    M5.Log.printf("  Permission settings OK\n");

    // 7.3.8 Confirmed (Disconnection of power supply from the reader)
    if (unit.disableField()) {
        m5::utility::delay(50);
        if (unit.enableField()) {
            M5.Log.printf("  DONE\n");
            return true;
        }
    }
    M5_LOGE("Failed to confirm");
    return false;
}

void issuance_write_example()
{
    // nfc_f.dump(lite_s::MC);

    const auto& picc = nfc_f.activatedPICC();

    if (internal_auth() && external_auth()) {
        M5.Log.printf("Already first_issuance_procedue_lite_s\n");
        return;
    }

    // First issuance procedue
    if (!first_issuance_procedue_lite_s(picc, example_master_key, example_ckv)) {
        lcd.fillScreen(TFT_RED);
        M5_LOGE("Failed to first_issuance_procedue");
        return;
    }

#if 1
    // Write with MAC
    if (!internal_auth() || !external_auth()) {
        M5_LOGE("Failed to auth");
        return;
    }
    constexpr char txt[16] = "writeWithMAC";
    if (!nfc_f.writeWithMAC16(0, (const uint8_t*)txt, sizeof(txt))) {
        M5_LOGE("Failed to writeWithMAC");
        return;
    }
#endif

    lcd.fillScreen(0);
}

}  // namespace

void setup()
{
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);

    auto cfg = unit.config();
    cfg.mode = NFC::F;
    unit.config(cfg);

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

    if (lcd.width() < lcd.height()) {
        lcd.setRotation(1);
    }
    lcd.setFont(&fonts::Font0);
    lcd.fillScreen(0);
    lcd.setCursor(0, 0);
    lcd.printf("Please put the PICC and click/hold G0");
    M5.Log.printf("Please put the PICC and click/hold G0\n");
}

void loop()
{
    M5.update();
    Units.update();

    bool clicked = M5.BtnA.wasClicked();  // For read
    bool held    = M5.BtnA.wasHold();     // For write

    if (clicked || held) {
        lcd.fillRect(0, lcd.fontHeight(), lcd.width(), lcd.height() - lcd.fontHeight());
        PICC picc{};
        if (nfc_f.detect(picc)) {
            M5.Log.printf("%s:%s %s F:%02X DF:%04X\n", picc.idmAsString().c_str(), picc.pmmAsString().c_str(),
                          picc.typeAsString().c_str(), picc.format, picc.dfc_format);
            if (picc.type == Type::FeliCaLiteS) {
                if (nfc_f.activate(picc)) {
                    if (clicked) {
                        read_example();
                    } else {
                        issuance_write_example();
                    }
                    nfc_f.deactivate();
                }
            } else {
                M5.Log.printf("Not support\n");
            }
            lcd.setCursor(0, 0);
            lcd.printf("Please put the PICC and click/hold G0");
            M5.Log.printf("Please put the PICC and click/hold G0\n");
        } else {
            M5.Log.printf("PICC NOT exists\n");
        }
    }
}
