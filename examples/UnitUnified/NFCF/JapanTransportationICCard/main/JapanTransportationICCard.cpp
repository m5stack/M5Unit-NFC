/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916
  Read JapanTransportationICCard
  日本国内の交通系カード(CJRC規格準拠)の認証のいらない領域の表示サンプル
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedNFC.h>
#include <M5Utility.h>
#include <vector>
#include <ctime>

// *************************************************************
// Choose one define symbol to match the unit you are using
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_CAP_CC1101)
// For UnitNFC
// #define USING_UNIT_NFC
// For CapNFC
// #define USING_CAP_CC1101
#endif

using namespace m5::nfc;
using namespace m5::nfc::f;

namespace {
auto& lcd = M5.Display;
m5::unit::UnitUnified Units;

#if defined(USING_UNIT_NFC)
#pragma message "Choose UnitNFC"
m5::unit::UnitNFC unit{};  // I2C
#elif defined(USING_CAP_CC1101)
#pragma message "Choose CapCC1101NFC"
m5::unit::CapCC1101NFC unit{};  // CapCC1101 (SPI)
#else
#error Choose unit please!
#endif
m5::nfc::NFCLayerF nfc_f{unit};

constexpr uint16_t jtic_system_code[] = {
    0x0003,  // Suica,PASMO,ICOCA,PiTaPa,TOICA ...
    0x80DE,  // IruCa
};

// Service code
constexpr uint16_t service_balance{0x008B};
constexpr uint16_t service_usage_history{0x090F};
constexpr uint16_t service_gate_history{0x108F};
constexpr uint16_t service_intermediate_gate_history{0x10CB};
constexpr uint16_t service_ticket_information{0x184B};

struct tm buf_to_tm(const uint8_t date[2], const uint8_t time[2] = nullptr)
{
    struct tm dt = {};

    uint16_t u16 = ((uint16_t)date[0] << 8) | date[1];
    dt.tm_year   = ((u16 >> 9) & 0x1F) + 2000 - 1900;
    dt.tm_mon    = ((u16 >> 5) & 0x0F) - 1;
    dt.tm_mday   = (u16 & 0x1F);

    if (time) {
        u16        = ((uint16_t)time[0] << 8) | time[1];
        dt.tm_hour = (u16 >> 11) & 0x1F;
        dt.tm_min  = (u16 >> 5) & 0x3F;
        dt.tm_sec  = (u16 & 0x1F) << 1;
    }
    return dt;
}

void dump_jtic()
{
    uint16_t sc[255]{};
    uint8_t sc_num{};
    if (!nfc_f.requestSystemCode(sc, sc_num)) {
        return;
    }
    M5.Log.printf("System code %u\n", sc_num);
    for (uint_fast8_t i = 0; i < sc_num; ++i) {
        M5.Log.printf("  %04X\n", sc[i]);
    }

    standard::Mode m{};
    if (!nfc_f.requestResponse(m)) {
        return;
    }
    M5.Log.printf("Mode:%u\n", m);

    // Balance
    uint16_t key_version{};
    if (nfc_f.requestService(key_version, service_balance) && key_version != 0xFFFF) {
        uint8_t buf[16]{};
        if (nfc_f.read16(buf, block_t(0), service_balance)) {
            M5.Log.printf("Type:%02X Balance:%u Update:%u\n",
                          buf[8],                              //
                          ((uint16_t)buf[12] << 8) | buf[11],  // LE
                          ((uint16_t)buf[14] << 8) | buf[15]);
        } else {
            M5_LOGE("Failed to read");
        }
    }

    // Usage history
    if (nfc_f.requestService(key_version, service_usage_history) && key_version != 0xFFFF) {
        uint8_t buf[16]{};
        M5.Log.printf("Usage history:\n");
        for (uint_fast8_t i = 0; i < 20; ++i) {
            if (!nfc_f.read16(buf, i, service_usage_history)) {
                break;
            }
            auto dt = buf_to_tm(buf + 4, (buf[1] == 0x46) ? buf + 6 : nullptr);
            M5.Log.printf("  [%2u]:%4u/%02u/%02u Machine:%02X Usage:%02X Payment:%02X Entry/Exit:%02X Balance:%5u",  //
                          i, dt.tm_year + 1900, dt.tm_mon + 1, dt.tm_mday, buf[0], buf[1] & 0x7F, buf[2], buf[3],
                          ((uint16_t)buf[11] << 8) | buf[10]);

            if (buf[1] == 0x46) {  // In the case of merchandise sales, a time exists
                M5.Log.printf(" %02u:%02u:%02u", dt.tm_hour, dt.tm_min, dt.tm_sec);
            }
            M5.Log.printf("\n");
        }
    }

    // Gate history
    if (nfc_f.requestService(key_version, service_gate_history) && key_version != 0xFFFF) {
        uint8_t buf[16]{};
        M5.Log.printf("Gate history:\n");
        for (uint_fast8_t i = 0; i < 3; ++i) {
            if (!nfc_f.read16(buf, i, service_gate_history)) {
                break;
            }
            auto dt = buf_to_tm(buf + 6);
            M5.Log.printf("  [%2u]:%4u/%02u/%02u %1u%1u:%1u%1u Entry/Exit:%02X Gate:%03u-%03u/%04X Actuarial:%5u\n",  //
                          i, dt.tm_year + 1900, dt.tm_mon + 1, dt.tm_mday,                                            //
                          buf[8] >> 4, buf[8] & 0x0F, buf[9] >> 4, buf[9] & 0x0F,  // BCD hour and min
                          buf[0], buf[2], buf[3],                                  // Station code if train
                          ((uint16_t)buf[4] << 8) | buf[5],                        //
                          ((uint16_t)buf[11] << 8) | buf[10]);
        }
    }

    // Intermediate gate history
    if (nfc_f.requestService(key_version, service_intermediate_gate_history) && key_version != 0xFFFF) {
        uint8_t buf[16]{};
        M5.Log.printf("Intermediate gate history:\n");
        for (uint_fast8_t i = 0; i < 2; ++i) {
            if (!nfc_f.read16(buf, i, service_intermediate_gate_history)) {
                M5_LOGE("Failed to read");
                break;
            }
            if (i == 0) {
                continue;
            }
            auto dt = buf_to_tm(buf + 0);
            M5.Log.printf("  %4u/%02u/%02u Entry:%1u%1u:%1u%1u Code:%03u-%03u Exit:%1u%1u:%1u%1u Code:%03u-%03u\n",
                          dt.tm_year + 1900, dt.tm_mon + 1, dt.tm_mday,            //
                          buf[2] >> 4, buf[2] & 0x0F, buf[3] >> 4, buf[3] & 0x0F,  // BCD hour and min
                          buf[4], buf[5],                                          // Station code
                          buf[7] >> 4, buf[7] & 0x0F, buf[8] >> 4, buf[8] & 0x0F,  // BCD hour and min
                          buf[9], buf[10]);                                        // Station code
        }
    }

    // Ticket Information
    if (nfc_f.requestService(key_version, service_ticket_information) && key_version != 0xFFFF) {
        uint8_t buf[16]{};
        M5.Log.printf("Ticket information:\n");
        for (uint_fast8_t i = 0; i < 36; ++i) {
            if (!nfc_f.read16(buf, i, service_ticket_information) || (!buf[0] && !buf[1])) {
                break;
            }
            auto dt1 = buf_to_tm(buf + 4, buf + 6);
            auto dt2 = buf_to_tm(buf + 4, buf + 14);
            M5.Log.printf(
                "  [%2u]:Departure:%03u-%03u Arrival:%03u-%03u Expired:%04u/%03u/%02u Issuance:%02u:%02u:%02u "
                "Amount:%u Gate:%03u-%03u %02u:%02u:%02u\n",      //
                i, buf[0], buf[1], buf[2], buf[3],                // Station code
                dt1.tm_year + 1900, dt1.tm_mon + 1, dt1.tm_mday,  //
                dt1.tm_hour, dt1.tm_min, dt1.tm_sec,              //
                buf[9] * 10,                                      // amount
                buf[12], buf[13],                                 // Station code
                dt2.tm_hour, dt2.tm_min, dt2.tm_sec);
        }
    }
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
    auto board = M5.getBoard();
    bool unit_ready{};
    // NessoN1: SoftwareI2C too slow for NFC RF timing -> use port_a (Wire) via else branch
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

    if (lcd.height() > lcd.width()) {
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
        std::vector<PICC> piccs{};
        if (nfc_f.detect(piccs, jtic_system_code, sizeof(jtic_system_code), TimeSlot::Slot1, 50)) {
            PICC picc = piccs.front();
            if (nfc_f.activate(picc)) {
                M5.Speaker.tone(2500, 20);
                M5.Log.printf("%s:%s %s F:%02X DF:%04X\n", picc.idmAsString().c_str(), picc.pmmAsString().c_str(),
                              picc.typeAsString().c_str(), picc.format, picc.dfc_format);
                dump_jtic();
                nfc_f.deactivate();
            }
        } else {
            M5.Log.printf("PICC NOT exists\n");
        }
    }
}
