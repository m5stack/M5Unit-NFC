/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file unit_ST25R3916_nfcf.cpp
  @brief class UnitST25R3916 implementation for NFC-F
*/
#include "unit_ST25R3916.hpp"
#include <M5Utility.hpp>

using namespace m5::unit::types;
using namespace m5::unit::st25r3916;
using namespace m5::unit::st25r3916::regval;
using namespace m5::unit::st25r3916::command;
using namespace m5::nfc;
using namespace m5::nfc::f;

// clang-format off
#pragma GCC optimize("O3")
// clang-format on

#define CHECK_MODE()                                   \
    do {                                               \
        if (!isNFCMode(NFC::F)) {                      \
            M5_LIB_LOGE("Illegal mode %u", NFCMode()); \
            return false;                              \
        }                                              \
    } while (0)

namespace {
/*
uint8_t val_table[] = {

    0x07, 0x3C, 0xCB, 0x1C, 0x11, 0x00, 0x00, 0x00, 0x5D, 0x00, 0x00, 0x13, 0x3D, 0x00, 0x00, 0x28,
    0x06, 0x11, 0x22, 0x02, 0xCA, 0x80, 0x85, 0xA6, 0x0F, 0x7B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x28, 0x00, 0xDF, 0x82, 0x82, 0x70, 0x5F, 0x13, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

};
*/
}  // namespace

namespace m5 {
namespace unit {
// -------------------------------- For NFC-F
bool UnitST25R3916::configure_nfc_f()
{
    if (!writeInitiatorOperationMode(InitiatorOperationMode::FeliCa, tr_am) ||  //
        !writeBitrate(Bitrate::Bps212K, Bitrate::Bps212K)) {
        return false;
    }

    return modify_bit_register8(REG_OPERATION_CONTROL, en_fd_c1 | en_fd_c0, 0x00) &&  //
           writeIOConfiguration1(0x07) &&                                             //
                                           // writeAuxiliaryDefinition(nfc_n0) && //
           writeAuxiliaryDefinition(0x00) &&       //
           writeReceiverConfiguration1(0x13) &&    //
           writeReceiverConfiguration2(0x3D) &&    //
           writeReceiverConfiguration3(0x00) &&    //
           writeReceiverConfiguration4(0x00) &&    //
           writeCorrelatorConfiguration1(0x54) &&  //
           writeCorrelatorConfiguration2(0x00) &&  //
           writeMaskInterrupts(0) &&               //
           nfc_initial_field_on();
}

bool UnitST25R3916::configure_emulation_f()
{
    _encrypted = false;

    return writeModeDefinition(0xE0) &&                 // target, NFC-F, Bit rate detection mode
           writeNFCIP1PassiveTargetDefinition(0x5C) &&  // fdel[7:4], disable d_ac_ap2p.d_214/424_1r, enable d_106_ac
           writeMaskPassiveTargetInterrupt(0x02) &&     // mask I_wu_ax
           writeTimerAndEMVControl(0x08);               // mrt_setp 512
}

bool UnitST25R3916::nfcfTransceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                   const uint32_t timeout_ms)
{
    return nfcfTransmit(tx, tx_len, timeout_ms) && nfcfReceive(rx, rx_len, timeout_ms);
}

bool UnitST25R3916::nfcfTransmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms)
{
    CHECK_MODE();

    if (!tx || !tx_len) {
        return false;
    }

    if (timeout_ms && !write_fwt_timer(timeout_ms)) {
        return false;
    }
    if (!clear_bit_register8(REG_AUXILIARY_DEFINITION, no_crc_rx) || !clearInterrupts() ||
        !writeDirectCommand(CMD_CLEAR_FIFO) || !writeFIFO(tx, tx_len) || !writeNumberOfTransmittedBytes(tx_len, 0) ||
        !writeDirectCommand(CMD_TRANSMIT_WITH_CRC)) {
        return false;
    }
    return wait_for_interrupt(I_txe32, timeout_ms) & I_txe32;
}

bool UnitST25R3916::nfcfEmulationTransmit(const uint8_t* tx, const uint16_t tx_len)
{
    if (!tx || !tx_len) {
        return false;
    }
    return writeDirectCommand(CMD_CLEAR_FIFO) &&  //
           writeFIFO(tx, tx_len) &&               //
           writeNumberOfTransmittedBytes(tx_len, 0) && writeDirectCommand(CMD_TRANSMIT_WITH_CRC);
}

bool UnitST25R3916::nfcfReceive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms)
{
    CHECK_MODE();

    const auto rx_len_org = rx_len;
    rx_len                = 0;

    if (!rx && !rx_len_org) {
        return false;
    }

    if (!wait_for_FIFO(timeout_ms, rx_len_org)) {
        M5_LIB_LOGD("Timeout");
        return false;
    }
    uint16_t actual{};
    if (readFIFO(actual, rx, rx_len_org)) {
        rx_len = actual;
        return true;
    }
    M5_LIB_LOGD("Failed to readFIFO %u/%u", actual, rx_len_org);
    return false;
}

}  // namespace unit
}  // namespace m5
