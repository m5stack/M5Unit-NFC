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
    constexpr uint8_t sqm_dyn{0x20};
    constexpr uint8_t agc_en{0x08};
    constexpr uint8_t agc_m{0x04};
    constexpr uint8_t agc6_3{0x01};

    if (!writeReceiverConfiguration1(lp0 | h80 | z12k) ||
        !writeReceiverConfiguration2(sqm_dyn | agc_en | agc_m | agc6_3) || !writeReceiverConfiguration3(0x00) ||
        !writeReceiverConfiguration4(0x00)) {
        return false;
    }

    if (!writeTXDriver(0x70)) {  // modulation 40%
        return false;
    }

    if (!writeIOConfiguration1(0x07) ||  // No LF clock on MCU_CLK, Disabled MCU clock
        !set_bit_register8(REG_IO_CONFIGURATION_2, aat_en) ||
        !set_bit_register8(REG_OPERATION_CONTROL, en_fd_c1 | en_fd_c0) ||
        !writeStreamModeDefinition(0x38) ||  // fc32/424KHz, Num of pulse 2(BPSK only)
        !writeAuxiliaryDefinition(0x02)) {
        return false;
    }

    // Space-B
    constexpr uint8_t corr_s4{0x10};  // RX bit rate 106kb/s = 33, RX bit rates 212 to 848 kb/s = 17
    constexpr uint8_t corr_s1{0x02};  // Collision detection level
    constexpr uint8_t corr_s0{0x01};  // 11 : 53%
    constexpr uint8_t corr_s8{0x01};  // 1: 424 kHz subcarrier stream mode

    if (!writeEMDSuppressionConfiguration(0x40) || !writeSubcarrierStartTimer(0x14) ||
        !writeP2PReceiverConfiguration(0x0C) || !writeCorrelatorConfiguration1(corr_s4 | corr_s1 | corr_s0) ||
        !writeCorrelatorConfiguration2(corr_s8) || !writeSquelchTimer(0x00) || !writeNFCFieldOnGuardTimer(0x00) ||
        !writeAuxiliaryModulationSetting(0x10) || !writeTXDriverTiming(0x7C) || !writeResistiveAMModulation(0x80)) {
        return false;
    }

    //
    if (!writeModeDefinition(0x70)) {  // Sub carrier stream mode
        return false;
    }
    return nfc_initial_field_on();
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
