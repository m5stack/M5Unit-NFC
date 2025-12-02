/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for M5Cardputer-ADV with HackerCap
  JapanTransportationICCard example
  日本国内の交通系カード(CJRC規格準拠)の認証のいらない領域の表示サンプル
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedNFC.h>
#include <M5Utility.h>
#include <vector>
#include <ctime>

using namespace m5::nfc;
using namespace m5::nfc::f;

namespace {
auto& lcd = M5.Display;
m5::unit::UnitUnified Units;
m5::unit::CapST25R3916 cap;  // ST25R3916 in the HackerCap
m5::unit::nfc::NFCLayerF nfc_f{cap};

constexpr uint16_t jtic_system_code[] = {
    0x0003,  // Suica,PASMO,ICOCA,PiTaPa,TOICA など
    // 0x802B,  // せたまる (EOL)
    0x80DE,  // IruCa
};

// Service code
constexpr uint16_t service_balance{0x008B};
constexpr uint16_t service_boarding_history{0x090F};
constexpr uint16_t service_gate_history{0x108F};
constexpr uint16_t service_intermediate_gate_history{0x10CB};

struct tm buf_to_tm(const uint8_t date[2], const uint8_t time[2] = nullptr)
{
    struct tm dt{};
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
    // Balance
    uint16_t key_version{};
    if (nfc_f.requestService(key_version, service_balance) && key_version != 0xFFFF) {
        uint8_t buf[16]{};
        if (nfc_f.read16(buf, 0, service_balance)) {
            M5.Log.printf("   Type:%02X\n", buf[8]);
            M5.Log.printf("Balance:%u\n", ((uint16_t)buf[12] << 8) | buf[11]);  // LE
            M5.Log.printf(" Update:%u\n", ((uint16_t)buf[14] << 8) | buf[15]);

        } else {
            M5_LOGE("Failed to read");
        }
    }

    // Boarding history
    if (nfc_f.requestService(key_version, service_boarding_history) && key_version != 0xFFFF) {
        uint8_t buf[16]{};
        M5.Log.printf("Boarding history:\n");
        for (uint_fast8_t i = 0; i < 20; ++i) {
            if (!nfc_f.read16(buf, i, service_boarding_history)) {
                M5_LOGE("Failed to read");
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
                M5_LOGE("Failed to read");
                break;
            }
            auto dt = buf_to_tm(buf + 6);
            M5.Log.printf("  [%2u]:%4u/%02u/%02u %1u%1u:%1u%1u Enrty/Exit:%02X Gate:%04X/%04X Actuarial:%5u\n",  //
                          i, dt.tm_year + 1900, dt.tm_mon + 1, dt.tm_mday,                                       //
                          buf[8] >> 4, buf[8] & 0x0F, buf[9] >> 4, buf[9] & 0x0F,  // BCD hour and min
                          buf[0],
                          ((uint16_t)buf[2] << 8) | buf[3],  // Station code if train
                          ((uint16_t)buf[4] << 8) | buf[5],  //
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
            M5.Log.printf("  %4u/%02u/%02u Entry:%1u%1u:%1u%1u Code:%04X Exit:%1u%1u:%1u%1u Code:%04X\n",
                          dt.tm_year + 1900, dt.tm_mon + 1, dt.tm_mday,            //
                          buf[2] >> 4, buf[2] & 0x0F, buf[3] >> 4, buf[3] & 0x0F,  // BCD hour and min
                          ((uint16_t)buf[4] << 8) | buf[5],                        // Station code
                          buf[7] >> 4, buf[7] & 0x0F, buf[8] >> 4, buf[8] & 0x0F,  // BCD hour and min
                          ((uint16_t)buf[9] << 8) | buf[10]);                      // Station code
        }
    }
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

    delay(1000);

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

    //
    //    cap.dumpRegister();
    //
}

void loop()
{
    M5.update();
    Units.update();
    bool clicked = M5.BtnA.wasClicked();  // For read
    bool held    = M5.BtnA.wasHold();     // For write

    if (clicked || held) {
        std::vector<PICC> piccs{};
        if (nfc_f.detect(piccs, jtic_system_code, sizeof(jtic_system_code), TimeSlot::Slot1, 50)) {
            PICC picc = piccs.front();
            if (nfc_f.activate(picc)) {
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
