/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file unit_ST25R3916_nfcv.cpp
  @brief class UnitST25R3916 implementation for NFC-V
*/
#include "unit_ST25R3916.hpp"
#include <M5Utility.hpp>

using namespace m5::utility::mmh3;

using namespace m5::unit::types;
using namespace m5::unit::st25r3916;
using namespace m5::unit::st25r3916::regval;
using namespace m5::unit::st25r3916::command;
using namespace m5::nfc;
using namespace m5::nfc::v;

// clang-format off
#pragma GCC optimize("O3")
// clang-format on

#define CHECK_MODE()                                   \
    do {                                               \
        if (!isNFCMode(NFC::V)) {                      \
            M5_LIB_LOGE("Illegal mode %u", NFCMode()); \
            return false;                              \
        }                                              \
    } while (0)

namespace {

#if 0
constexpr uint8_t val_table2[] = {
    0x07, 0x3C, 0xCB, 0x70, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x38, 0x01, 0x13, 0x2D, 0x00, 0x00, 0x41,
    0x00, 0x52, 0x20, 0x01, 0x84, 0x80, 0x85, 0xA7, 0x0F, 0x7B, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xB0, 0x00, 0xE0, 0x82, 0x82, 0x70, 0x5F, 0x13, 0x02, 0x00, 0xCB, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

constexpr uint8_t val_table[] = {
    0x07, 0x3C, 0xCB, 0x70, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x38, 0x02, 0x13, 0x2D, 0x00, 0x00, 0x41,
    0x00, 0x52, 0x20, 0x01, 0x84, 0x80, 0x85, 0xA7, 0x0F, 0x7B, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xB0, 0x00, 0xE0, 0x82, 0x82, 0x70, 0x5F, 0x13, 0x02, 0x00, 0xB9, 0x01, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
constexpr uint8_t mine2[] = {
    0X07, 0XBC, 0XCB, 0X70, 0X00, 0X00, 0X00, 0X00, 0X50, 0X00, 0X00, 0X13, 0X2D, 0X00, 0X00, 0X0C,
    0X00, 0X00, 0X00, 0X00, 0X00, 0X80, 0X00, 0X00, 0X00, 0X00, 0X00, 0X02, 0X00, 0X20, 0X00, 0X00,
    0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X82, 0X82, 0X70, 0X5F, 0X13, 0X02, 0X00, 0X00, 0X00, 0X00,
    0X00, 0X10, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
};

constexpr uint8_t mine[] = {
    0X07, 0XBC, 0X83, 0X70, 0X00, 0X00, 0X00, 0X00, 0X50, 0X00, 0X00, 0X13, 0X2D, 0X00, 0X00, 0X0C,
    0X00, 0X00, 0X00, 0X00, 0X00, 0X80, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
    0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X82, 0X82, 0X70, 0X5F, 0X13, 0X02, 0X00, 0X00, 0X00, 0X00,
    0X00, 0X12, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
};
inline uint32_t OCB(const uint8_t c)
{
    // printf("%08o", OCB(0x2d)); => 00101101
    return (c & 1) | (c & 2) << 2 | (c & 4) << 4 | (c & 8) << 6 | (c & 16) << 8 | (c & 32) << 10 | (c & 64) << 12 |
           (c & 128) << 14;
}
#endif

}  // namespace

namespace m5 {
namespace unit {
// -------------------------------- For NFC-V
bool UnitST25R3916::configure_nfc_v()
{
    constexpr uint8_t lp0{0x10};
    constexpr uint8_t h80{0x02};
    constexpr uint8_t z12k{0x01};
    // Low-pass 600Khz, First stage zero 12Khz, third stage zero 80Khz
    writeReceiverConfiguration1(lp0 | h80 | z12k);
    constexpr uint8_t sqm_dyn{0x20};
    constexpr uint8_t agc_en{0x08};
    constexpr uint8_t agc_m{0x04};
    constexpr uint8_t agc6_3{0x01};
    writeReceiverConfiguration2(sqm_dyn | agc_en | agc_m | agc6_3);
    writeReceiverConfiguration3(0x00);
    writeReceiverConfiguration4(0x00);

    writeTXDriver(0x70);  // modulation 40%

    writeIOConfiguration1(0x07);  // No LF clock on MCU_CLK, Disabled MCU clock
    set_bit_register8(REG_IO_CONFIGURATION_2, aat_en);
    set_bit_register8(REG_OPERATION_CONTROL, en_fd_c1 | en_fd_c0);
    writeStreamModeDefinition(0x38);  // fc32/424KHz, Num of pulse 2(BPSK only)
    writeAuxiliaryDefinition(0x02);

    // Space-B
    writeEMDSuppressionConfiguration(0x40);
    writeSubcarrierStartTimer(0x14);
    writeP2PReceiverConfiguration(0x0C);
    constexpr uint8_t corr_s4{0x10};  // RX bit rate 106kb/s = 33, RX bit rates 212 to 848 kb/s = 17
    constexpr uint8_t corr_s1{0x02};  // Collision detection level
    constexpr uint8_t corr_s0{0x01};  // 11 : 53%
    writeCorrelatorConfiguration1(corr_s4 | corr_s1 | corr_s0);
    constexpr uint8_t corr_s8{0x01};  // 1: 424 kHz subcarrier stream mode
    writeCorrelatorConfiguration2(corr_s8);
    writeSquelchTimer(0x00);
    writeNFCFieldOnGuardTimer(0x00);
    writeAuxiliaryModulationSetting(0x10);
    writeTXDriverTiming(0x7C);
    writeResistiveAMModulation(0x80);

    //
    writeModeDefinition(0x70);  // Sub carrier stream mode

#if 0
    uint8_t reg = 0x00;
    for (auto&& v : val_table) {
        //        write_register8(reg, v);
        if (v != mine[reg]) {
            M5_LIB_LOGE("REG %02X: %02X %08o %02X %08o", reg, v, OCB(v), mine[reg], OCB(mine[reg]));
        }
        ++reg;
    }

    if (0) {
        uint16_t r{};
        r = 0x05;
        writeRegister8(r, 0x40);
        r = 0x06;
        writeRegister8(r, 0x14);
        r = 0x0B;
        writeRegister8(r, 0x0C);
        r = 0x0C;
        writeRegister8(r, 0x13);
        r = 0x0D;
        writeRegister8(r, 0x01);
        r = 0x0F;
        writeRegister8(r, 0x00);
        r = 0x15;
        writeRegister8(r, 0x00);
        r = 0x28;
        writeRegister8(r, 0x10);
        r = 0x29;
        writeRegister8(r, 0x7C);
        r = 0x2A;
        writeRegister8(r, 0x80);
        // r = 0x2B;
        // writeRegister8(r, 0x04);
        //  r = 0x2C;
        // writeRegister8(r, 0xD0);
    }
#endif

    //    dumpRegister();

    nfc_initial_field_on();

    return true;
}

bool UnitST25R3916::nfcvTransceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                   const uint32_t timeout_ms, const ModulationMode mode)
{
    if (!nfcvTransmit(tx, tx_len, timeout_ms, mode)) {
        return false;
    }
    return nfcvReceive(rx, rx_len, timeout_ms);
}

bool UnitST25R3916::nfcvTransmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms,
                                 const ModulationMode mode)
{
    if (!tx || !tx_len) {
        return false;
    }

    CHECK_MODE();

    // m5::utility::log::dump(tx, tx_len, false);

    // Encode
    std::vector<uint8_t> frame{};
    if (!encode_VCD(frame, mode, tx, tx_len)) {
        M5_LIB_LOGD("Failed to encode");
        return false;
    }
    // m5::utility::log::dump(frame.data(), frame.size(), false);

    // Send
    if (timeout_ms && !write_fwt_timer(timeout_ms)) {
        return false;
    }
    if (!clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) || !writeFIFO(frame.data(), frame.size()) ||
        !writeNumberOfTransmittedBytes(frame.size(), 0) || !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
        return false;
    }
    // return true;
    auto irq = wait_for_interrupt(I_txe32, timeout_ms);
    //    M5_LIB_LOGE("TXE;%u", is_irq32_txe(irq));
    return is_irq32_txe(irq);
}

bool UnitST25R3916::nfcvReceive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms)
{
    const auto rx_len_org = rx_len;
    rx_len                = 0;
    if (!rx || !rx_len_org) {
        return false;
    }

    CHECK_MODE();

    uint8_t rbuf[256]{};
    if (!wait_for_FIFO(timeout_ms, sizeof(rbuf))) {
        return false;
    }
    uint16_t actual{};
    auto bb = readFIFO(actual, rbuf, sizeof(rbuf));
    if (!bb) {
        M5_LIB_LOGD("Failed to readFIFO %u/%u", actual, rx_len_org);
        return false;
    }

    // Decode
    std::vector<uint8_t> frame{};
    if (!decode_VICC(frame, rbuf, actual)) {
        M5_LIB_LOGD("Failed to decode");
        // m5::utility::log::dump(rx, rx_len, false);
        return false;
    }

    // m5::utility::log::dump(frame.data(), frame.size(), false);
    rx_len = std::min<uint32_t>(frame.size() - 2 /*CRC*/, rx_len_org);
    memcpy(rx, frame.data(), rx_len);
    return true;
}

}  // namespace unit
}  // namespace m5
