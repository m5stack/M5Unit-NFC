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
  read4/write4, read16/write16 allows access to any position by setting safety == false, or use the  unit-side API.
  See also each header and Doxygen document.
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

using namespace m5::nfc;
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

constexpr int8_t access_denied{-1};
constexpr int8_t access_free{-2};
int8_t required_key_no_for_read(const uint16_t access_rights)
{
    const uint8_t read_key = (access_rights >> 12) & 0x0F;  // Read
    const uint8_t rw_key   = (access_rights >> 4) & 0x0F;   // Read/Write
    if (read_key == 0x0E) {
        return access_free;
    }
    if (read_key != 0x0F) {
        return read_key;
    }
    if (rw_key == 0x0E) {
        return access_free;
    }
    if (rw_key != 0x0F) {
        return rw_key;
    }
    return access_denied;
}

int8_t required_key_no_for_write(const uint16_t access_rights)
{
    const uint8_t write_key = (access_rights >> 8) & 0x0F;  // Write
    const uint8_t rw_key    = (access_rights >> 4) & 0x0F;  // Read/Write
    if (write_key == 0x0E) {
        return access_free;
    }
    if (write_key != 0x0F) {
        return write_key;
    }
    if (rw_key == 0x0E) {
        return access_free;
    }
    if (rw_key != 0x0F) {
        return rw_key;
    }
    return access_denied;
}

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

#if 0
void read_all_user_area()
{
    auto& picc = nfc_a.activatedPICC();

    if (!picc.isFileSystemMemory()) {
        return;
    }

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
#endif

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

// For DESFire
bool read_write_desfire()
{
    constexpr uint8_t aid[3]{0x00, 0x00, 0x02};
    constexpr uint8_t file_no{0x05};
    constexpr uint16_t iso_fid{0xF005};
    constexpr uint8_t comm_mode{0x00};
    constexpr uint16_t access_rights{0xEEEE};
    constexpr char data[]        = "aBcDeFg";
    constexpr uint32_t file_size = sizeof(data);

    std::vector<uint8_t> rbuf{};

    auto isoDEP = nfc_a.isoDEP();
    if (!isoDEP) {
        return false;
    }
    // M5_LOGI("DESFire RW: aid=%02X%02X%02X file_no=%u iso_fid=%04X size=%lu", aid[0], aid[1], aid[2], file_no,
    // iso_fid,
    //        static_cast<unsigned long>(file_size));

    desfire::DESFireFileSystem dfs(nfc_a);
    // Select PICC
    if (!dfs.selectApplication()) {
        M5_LOGE("Failed to select PICC application");
        return false;
    }

    // PICC Auth
    const uint8_t* default_key = desfire::DESFIRE_DEFAULT_KEY;
    bool picc_auth_des         = dfs.authenticateDES(0x00, default_key);
    bool picc_auth_iso         = !picc_auth_des && dfs.authenticateISO(0x00, default_key);
    bool picc_auth_aes         = (!picc_auth_des && !picc_auth_iso) && dfs.authenticateAES(0x00, default_key);
    bool picc_auth_ok          = picc_auth_des || picc_auth_iso || picc_auth_aes;
    if (!picc_auth_ok) {
        M5_LOGE("PICC master auth failed");
        return false;
    }
    // M5_LOGI("PICC master auth: %s", picc_auth_des ? "DES" : picc_auth_iso ? "ISO" : "AES");

    // Select app
    if (!dfs.selectApplication(aid)) {
        auto created = dfs.createApplication(aid, 0x09, 0x21);
        if (!created.has_value()) {
            M5_LOGE("create application failed (0x%02X)", created.error());
            return false;
        }
        // M5_LOGI("create application: OK");
        if (!dfs.selectApplication(aid)) {
            M5_LOGE("Failed to select application");
            return false;
        }
    }

    // App auth
    bool app_auth_des = dfs.authenticateDES(0x00, default_key);
    bool app_auth_iso = !app_auth_des && dfs.authenticateISO(0x00, default_key);
    bool app_auth_aes = (!app_auth_des && !app_auth_iso) && dfs.authenticateAES(0x00, default_key);
    bool app_auth_ok  = app_auth_des || app_auth_iso || app_auth_aes;
    if (!app_auth_ok) {
        M5_LOGE("App master auth failed");
        return false;
    }
    // M5_LOGI("App master auth: %s", app_auth_des ? "DES" : app_auth_iso ? "ISO" : "AES");

    // Is file exist?
    bool have_file = false;
    std::vector<uint8_t> file_ids;
    if (dfs.getFileIDs(file_ids)) {
        // M5_LOGI("getFileIDs: %u", static_cast<unsigned>(file_ids.size()));
        for (auto id : file_ids) {
            // M5_LOGI("  file_id: %u", id);
            if (id == file_no) {
                have_file = true;
                break;
            }
        }
    } else {
        M5_LOGE("getFileIDs failed");
    }

    // Check settings
    if (have_file) {
        desfire::FileSettings settings{};
        if (!dfs.getFileSettings(settings, file_no)) {
            M5_LOGE("Failed to getFileSettings %u", file_no);
            return false;
        }
        // M5_LOGI("getFileSettings: comm=%u ar=%04X size=%lu", settings.comm_mode, settings.access_rights,
        //         static_cast<unsigned long>(settings.file_size));
        if (settings.access_rights != access_rights || settings.comm_mode != comm_mode) {
            M5_LOGE("File settings not compatible (ar:%04X comm:%u)", settings.access_rights, settings.comm_mode);
            return false;
        }
    }

    // create STD file if not exists
    if (!have_file &&
        !dfs.createStdDataFile(file_no, iso_fid, comm_mode, access_rights, static_cast<uint32_t>(file_size))) {
        M5_LOGE("Failed to createStdDataFile %u", file_no);
        return false;
    }
    if (!have_file) {
        // M5_LOGI("createStdDataFile: OK");
    }

    // Write
    M5.Log.printf("================================ WRITE DESFire %02X len:%lu\n", file_no,
                  static_cast<unsigned long>(file_size));
    if (!dfs.writeData(file_no, 0, reinterpret_cast<const uint8_t*>(data), static_cast<uint32_t>(file_size))) {
        M5_LOGE("Failed to write");
        return false;
    }
    lcd.fillScreen(TFT_ORANGE);

    // Read
    if (!dfs.selectApplication(aid)) {
        M5_LOGE("Re-select application failed before read");
        return false;
    }
    if (!(dfs.authenticateDES(0x00, default_key) || dfs.authenticateISO(0x00, default_key) ||
          dfs.authenticateAES(0x00, default_key))) {
        M5_LOGE("Re-auth failed before read");
        return false;
    }
    // M5_LOGI("readData: file_no=%u offset=0 len=%lu", file_no, static_cast<unsigned long>(file_size));

    if (!dfs.readData(rbuf, file_no, 0, static_cast<uint32_t>(file_size))) {
        M5_LOGE("Failed to read");
        return false;
    }
    lcd.fillScreen(TFT_BLUE);

    bool compare = (rbuf.size() == file_size) && (memcmp(rbuf.data(), data, file_size) == 0);
    M5.Log.printf("================================ VERIFY:%s\n", compare ? "OK" : "NG");
    if (!compare) {
        M5_LOGE("VERIFY NG!!");
    }
    m5::utility::log::dump(rbuf.data(), rbuf.size(), false);

    // Clear (write 0x00...)
    const uint8_t clear[sizeof(data)]{};
    lcd.fillScreen(TFT_MAGENTA);
    if (!dfs.writeData(file_no, 0, clear, sizeof(clear))) {
        M5_LOGE("Failed to write(clear)");
        return false;
    }

    M5.Log.printf("================================ CLEAR\n");
    if (!dfs.readData(rbuf, file_no, 0, static_cast<uint32_t>(file_size))) {
        M5_LOGE("Failed to read");
        return false;
    }
    m5::utility::log::dump(rbuf.data(), rbuf.size(), false);

    return true;
}

bool read_write_desfire_light()
{
    constexpr uint8_t file_no{0x04};            // StdFile
    constexpr uint32_t default_file_size{256};  // Fixed size 256
    constexpr char data[]       = "aBcDeFg";
    constexpr uint32_t data_len = sizeof(data);
    std::vector<uint8_t> rbuf{};

    auto isoDEP = nfc_a.isoDEP();
    if (!isoDEP) {
        return false;
    }

    desfire::DESFireFileSystem dfs(nfc_a);

    const uint8_t* default_key = desfire::DESFIRE_DEFAULT_KEY;
    desfire::Ev2Context ev2_ctx{};
    bool ev2_ok        = false;
    uint8_t ev2_key_no = 0x00;
    auto ensure_ev2    = [&]() -> bool {
        if (ev2_ok) {
            return true;
        }
        ev2_ok = dfs.authenticateEV2First(ev2_key_no, default_key, ev2_ctx);
        // M5_LOGI("Light auth EV2: key=%u %s", ev2_key_no, ev2_ok ? "OK" : "NG");
        return ev2_ok;
    };

    desfire::FileSettings fs{};
    bool settings_ok = false;
    if (ensure_ev2()) {
        settings_ok = dfs.getFileSettingsEV2(fs, file_no, ev2_ctx);
        if (!settings_ok) {
            settings_ok = dfs.getFileSettingsEV2Full(fs, file_no, ev2_ctx);
        }
    }
    if (!settings_ok) {
        if (!dfs.selectDfNameAuto(m5::nfc::ndef::type4::NDEF_AID, sizeof(m5::nfc::ndef::type4::NDEF_AID))) {
            dfs.selectDfNameAuto(desfire::DESFIRE_LIGHT_DF_NAME, sizeof(desfire::DESFIRE_LIGHT_DF_NAME));
        }
        ev2_ok = false;
        if (ensure_ev2()) {
            settings_ok = dfs.getFileSettingsEV2(fs, file_no, ev2_ctx);
            if (!settings_ok) {
                settings_ok = dfs.getFileSettingsEV2Full(fs, file_no, ev2_ctx);
            }
        }
    }
    if (!settings_ok) {
        M5_LOGE("Failed to get file settings");
        return false;
    }
    const uint32_t file_size = fs.file_size ? fs.file_size : default_file_size;
    // M5_LOGI("Light file settings: comm=%u ar=%04X size=%lu", fs.comm_mode, fs.access_rights,
    //         static_cast<unsigned long>(file_size));
    fs.file_size = file_size;

    if (data_len > file_size) {
        M5_LOGE("Data too large for file size");
        return false;
    }

    const uint32_t offset = file_size - data_len;

    const bool use_ev2     = fs.comm_mode != 0;
    const bool use_full    = fs.comm_mode == 3;
    const int8_t read_key  = required_key_no_for_read(fs.access_rights);
    const int8_t write_key = required_key_no_for_write(fs.access_rights);
    if (read_key == access_denied || write_key == access_denied) {
        M5_LOGE("Access denied for file (read=%d write=%d)", read_key, write_key);
        return false;
    }

    auto auth_with_key = [&](const int8_t key) -> bool {
        if (key == access_denied) {
            return false;
        }
        if (key == access_free && !use_ev2) {
            return true;
        }
        const uint8_t desired_key = (key == access_free) ? 0x00 : static_cast<uint8_t>(key);
        if (!ev2_ok || ev2_key_no != desired_key) {
            ev2_ok     = false;
            ev2_key_no = desired_key;
        }
        return ensure_ev2();
    };

    M5.Log.printf("================================ WRITE DESFire Light %02X len:%lu offset:%lu\n", file_no,
                  static_cast<unsigned long>(data_len), static_cast<unsigned long>(offset));
    if (!auth_with_key(write_key)) {
        return false;
    }
    bool write_ok = false;
    if (!use_ev2) {
        write_ok = dfs.writeDataLight(file_no, offset, reinterpret_cast<const uint8_t*>(data), data_len);
    } else if (use_full) {
        write_ok =
            dfs.writeDataLightEV2Full(file_no, offset, reinterpret_cast<const uint8_t*>(data), data_len, ev2_ctx);
    } else {
        write_ok = dfs.writeDataLightEV2(file_no, offset, reinterpret_cast<const uint8_t*>(data), data_len, ev2_ctx);
    }
    if (!write_ok) {
        M5_LOGE("Failed to write");
        return false;
    }
    lcd.fillScreen(TFT_ORANGE);

    bool read_ok = false;
    if (!auth_with_key(read_key)) {
        return false;
    }
    if (!use_ev2) {
        read_ok = dfs.readDataLight(rbuf, file_no, offset, data_len);
    } else if (use_full) {
        read_ok = dfs.readDataLightEV2Full(rbuf, file_no, offset, data_len, ev2_ctx);
    } else {
        read_ok = dfs.readDataLightEV2(rbuf, file_no, offset, data_len, ev2_ctx);
    }
    if (!read_ok) {
        M5_LOGE("Failed to read");
        return false;
    }
    lcd.fillScreen(TFT_BLUE);

    bool compare = (rbuf.size() == data_len) && (memcmp(rbuf.data(), data, data_len) == 0);
    M5.Log.printf("================================ VERIFY:%s\n", compare ? "OK" : "NG");
    if (!compare) {
        M5_LOGE("VERIFY NG!!");
    }
    m5::utility::log::dump(rbuf.data(), rbuf.size(), false);

    const uint8_t clear[sizeof(data)]{};
    lcd.fillScreen(TFT_MAGENTA);
    bool clear_ok = false;
    if (!auth_with_key(write_key)) {
        return false;
    }
    if (!use_ev2) {
        clear_ok = dfs.writeDataLight(file_no, offset, clear, sizeof(clear));
    } else if (use_full) {
        clear_ok = dfs.writeDataLightEV2Full(file_no, offset, clear, sizeof(clear), ev2_ctx);
    } else {
        clear_ok = dfs.writeDataLightEV2(file_no, offset, clear, sizeof(clear), ev2_ctx);
    }
    if (!clear_ok) {
        M5_LOGE("Failed to write(clear)");
        return false;
    }

    M5.Log.printf("================================ CLEAR\n");
    if (!auth_with_key(read_key)) {
        return false;
    }
    if (!use_ev2) {
        read_ok = dfs.readDataLight(rbuf, file_no, offset, data_len);
    } else if (use_full) {
        read_ok = dfs.readDataLightEV2Full(rbuf, file_no, offset, data_len, ev2_ctx);
    } else {
        read_ok = dfs.readDataLightEV2(rbuf, file_no, offset, data_len, ev2_ctx);
    }
    if (!read_ok) {
        M5_LOGE("Failed to read");
        return false;
    }
    m5::utility::log::dump(rbuf.data(), rbuf.size(), false);

    return true;
}

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
    M5_LOGI("M5UnitUnified initialized");
    M5_LOGI("%s", Units.debugInfo().c_str());

    lcd.setCursor(0, lcd.height() / 2);
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
                    if (picc.isFileSystemMemory() &&
                        (picc.isMifarePlus() ? (picc.security_level == 1 || picc.security_level == 3) : true)) {
                        // read_all_user_area();
                        auto ret = read_write(picc.firstUserBlock(), picc.userAreaSize() >= 120 ? long_msg : short_msg);
                        lcd.fillScreen(ret ? 0 : TFT_RED);
                    } else if (picc.isMifareDESFire()) {
                        auto ret =
                            picc.type == Type::MIFARE_DESFire_Light ? read_write_desfire_light() : read_write_desfire();
                        lcd.fillScreen(ret ? 0 : TFT_RED);
                    } else {
                        M5.Log.printf("This example is not supported\n");
                    }
                } else if (held) {
                    // nfc_a.dump();
                    M5.Speaker.tone(4000, 30);
                    if (picc.isMifareClassic()) {
                        read_write_sector_structure(picc.blocks - 2);
                    } else if (picc.supportsNFC()) {
                        read_write_page_structure(picc, 10);
                    } else {
                        M5.Log.printf("This example is not supported\n");
                    }
                }
                nfc_a.deactivate();
            } else {
                M5_LOGE("Failed to identify/activate %s", picc.uidAsString().c_str());
            }
        } else {
            M5.Log.printf("PICC NOT exists\n");
        }
        lcd.setCursor(0, lcd.height() / 2);
        lcd.printf("Please put the PICC and click/hold BtnA");
        M5.Log.printf("Please put the PICC and click/hold BtnA\n");
    }
}
