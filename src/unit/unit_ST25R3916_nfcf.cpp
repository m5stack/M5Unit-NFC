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

uint32_t get_block_list_size(const block_t* block_list, const uint8_t block_num)
{
    uint32_t sz{};
    if (block_list && block_num) {
        for (uint_fast16_t i = 0; i < block_num; ++i) {
            sz += 2 + block_list[i].is_3byte();
        }
    }
    return sz;
}
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

#if 0
    if (ret) {
        uint8_t reg = 0x00;
        for (auto&& v : val_table) {
            //            if (reg < 0x3F) {
            // if(reg <= 0x20){ // OK
            //            if(reg <= 0x10){ // NG
            // if(reg <= 0x18){ // OK
            // if(reg <= 0x14){ // NG
            // if(reg <= 0x16){ // OK
            // if(reg <= 0x15){  // NG
            if (reg >= 0x16 && reg <= 0x19) {
                write_register8(reg, v);
            }
            ++reg;
        }
    }
    return true;
#endif
}

bool UnitST25R3916::configure_emulation_f()
{
    _encrypted = false;

    writeModeDefinition(0xE0);                 // target, NFC-F, Bit rate detection mode
    writeNFCIP1PassiveTargetDefinition(0x5C);  // fdel[7:4], disable d_ac_ap2p.d_214/424_1r, enable d_106_ac
    writeMaskPassiveTargetInterrupt(0x02);     // mask I_wu_ax
    writeTimerAndEMVControl(0x08);             // mrt_setp 512

    return true;
}

bool UnitST25R3916::nfcfTransceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                   const uint32_t timeout_ms)
{
#if 0
    CHECK_MODE();

    const auto rx_len_org = rx_len;
    rx_len                = 0;

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
    auto irq32 = wait_for_interrupt(I_txe32, timeout_ms) & I_txe32;
    if (!irq32) {
        return false;
    }
    // Send only
    if (!rx && !rx_len) {
        return true;
    }

    if (rx && rx_len_org) {
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
    }
    return false;
#else
    return nfcfTransmit(tx, tx_len, timeout_ms) && nfcfReceive(rx, rx_len, timeout_ms);
#endif
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

bool UnitST25R3916::nfcfPolling(m5::nfc::f::PICC& picc, const uint16_t system_code,
                                const m5::nfc::f::RequestCode request_code, const m5::nfc::f::TimeSlot time_slot)
{
    CHECK_MODE();

    picc = {};

    uint8_t packet[] = {m5::stl::to_underlying(CommandCode::Polling), (uint8_t)(system_code >> 8),
                        (uint8_t)(system_code & 0xFF), m5::stl::to_underlying(request_code),
                        m5::stl::to_underlying(time_slot)};

    // m5::utility::log::dump(packet, sizeof(packet), false);

    uint32_t timeout_ms = TIMEOUT_POLLING * TIMEOUT_POLLING_PICC * timeslot_to_slot(time_slot);

    uint8_t rbuf[18 + ((request_code != RequestCode::None) ? 2 : 0)]{};
    uint16_t rx_len = sizeof(rbuf);
    if (!nfcfTransceive(rbuf, rx_len, packet, sizeof(packet), timeout_ms)  //
        || rx_len < sizeof(rbuf) || rbuf[1] != m5::stl::to_underlying(ResponseCode::Polling)) {
        if (rx_len) {
            M5_LIB_LOGE("Failed to Polling %u %u %u", rx_len, rbuf[0], rbuf[1]);
        }
        return false;
    }

    // M5_LIB_LOGE("SC:%X",system_code);
    // m5::utility::log::dump(rbuf, rx_len, false);
    if (rx_len >= 18 && rbuf[0] >= 18) {
        memcpy(picc.idm, rbuf + 2, sizeof(picc.idm));
        memcpy(picc.pmm, rbuf + 10, sizeof(picc.pmm));
        picc.request_code = request_code;
        if (rbuf[0] >= 20) {
            picc.request_data = ((uint16_t)rbuf[18]) << 8;
            picc.request_data |= (uint16_t)rbuf[19];
        }
        return true;
    }
    return false;
}

bool UnitST25R3916::nfcfRequestService(uint16_t key_version[], const m5::nfc::f::PICC& picc, const uint16_t* node_code,
                                       const uint8_t node_num)
{
    CHECK_MODE();

    if (!key_version || !node_code || !node_num || picc.type != Type::FeliCaStandard) {
        return false;
    }

    std::vector<uint8_t> packet{};
    uint32_t timeout_ms = 10;  // TODO

    packet.resize(1 + 8 + 1 + (2 * node_num));

    packet[0] = m5::stl::to_underlying(CommandCode::RequestService);
    memcpy(packet.data() + 1, picc.idm, sizeof(picc.idm));
    packet[9]  = node_num;
    uint8_t* p = packet.data() + 10;
    for (uint_fast8_t i = 0; i < node_num; ++i) {
        *p++ = node_code[i] & 0xFF;
        *p++ = node_code[i] >> 8;
    }

    uint8_t rbuf[packet.size() + 1 /*LEN*/]{};
    uint16_t rx_len = sizeof(rbuf);

    // m5::utility::log::dump(packet.data(), packet.size(), false);

    if (!nfcfTransceive(rbuf, rx_len, packet.data(), packet.size(), timeout_ms)  //
        || rx_len < sizeof(rbuf) || rbuf[1] != m5::stl::to_underlying(ResponseCode::RequestService)) {
        M5_LIB_LOGE("Failed to RequestService %u", rx_len);
        return false;
    }

    // m5::utility::log::dump(rbuf, rx_len, false);

    for (uint_fast8_t i = 0; i < rbuf[10]; ++i) {
        key_version[i] = ((uint16_t)rbuf[12 + i * 2] << 8) | rbuf[11 + i * 2];
    }
    return true;
}

bool UnitST25R3916::nfcfRequestResponse(m5::nfc::f::standard::Mode& mode, const m5::nfc::f::PICC& picc)
{
    CHECK_MODE();

    mode = standard::Mode::Mode0;

    if (picc.type != Type::FeliCaStandard) {
        M5_LIB_LOGE("========================");
        return false;
    }

    std::vector<uint8_t> packet{};
    uint32_t timeout_ms = 10;  // TODO

    packet.resize(1 + 8);

    packet[0] = m5::stl::to_underlying(CommandCode::RequestResponse);
    memcpy(packet.data() + 1, picc.idm, sizeof(picc.idm));

    uint8_t rbuf[packet.size() + 1 /*LEN*/ + 1]{};
    uint16_t rx_len = sizeof(rbuf);

    // m5::utility::log::dump(packet.data(), packet.size(), false);

    if (!nfcfTransceive(rbuf, rx_len, packet.data(), packet.size(), timeout_ms)  //
        || rx_len < sizeof(rbuf) || rbuf[1] != m5::stl::to_underlying(ResponseCode::RequestResponse)) {
        M5_LIB_LOGE("Failed to RequestResponse %u", rx_len);
        return false;
    }

    // m5::utility::log::dump(rbuf, rx_len, false);

    mode = static_cast<standard::Mode>(rbuf[10]);
    return true;
}

bool UnitST25R3916::nfcfRequestSystemCode(uint16_t code_list[255], uint8_t& code_num, const m5::nfc::f::PICC& picc)
{
    CHECK_MODE();

    memset(code_list, 0x00, 2 * 255);

    if (!code_list || picc.type != Type::FeliCaStandard) {
        return false;
    }

    std::vector<uint8_t> packet{};
    uint32_t timeout_ms = 10;  // TODO

    packet.resize(1 + 8);

    packet[0] = m5::stl::to_underlying(CommandCode::RequestSystemCode);
    memcpy(packet.data() + 1, picc.idm, sizeof(picc.idm));

    // m5::utility::log::dump(packet.data(), packet.size(), false);

    uint8_t rbuf[1 + 1 + 8 + 1 + 2 * 255]{};
    uint16_t rx_len = sizeof(rbuf);

    if (!nfcfTransceive(rbuf, rx_len, packet.data(), packet.size(), timeout_ms)  //
        || rx_len < 11 || rbuf[1] != m5::stl::to_underlying(ResponseCode::RequestSystemCode)) {
        M5_LIB_LOGE("Failed to RequestResponse %u", rx_len);
        return false;
    }

    // m5::utility::log::dump(rbuf, rx_len, false);

    code_num      = rbuf[10];
    const auto* p = rbuf + 11;
    for (uint_fast16_t i = 0; i < code_num; ++i) {
        code_list[i] = p[1] | ((uint16_t)p[0] << 8);
        p += 2;
    }
    return true;
}

bool UnitST25R3916::nfcfReadWithoutEncryption(uint8_t* rx, uint16_t& rx_len, const m5::nfc::f::PICC& picc,
                                              const uint16_t* service_code, const uint8_t service_num,
                                              const block_t* block_list, const uint8_t block_num)
{
    CHECK_MODE();

    auto rx_org_len = rx_len;
    rx_len          = 0;

    if (!rx || !rx_org_len || !service_code || service_num > 16 || !block_num) {
        return false;
    }

    std::vector<uint8_t> packet{};
    const uint32_t block_size = get_block_list_size(block_list, block_num);
    uint32_t timeout_ms       = 50;  // TODO

    packet.resize(1 + 8 + 1 + (2 * service_num) + 1 + block_size);

    packet[0] = m5::stl::to_underlying(CommandCode::ReadWithoutEncryption);
    memcpy(packet.data() + 1, picc.idm, sizeof(picc.idm));
    packet[9]  = service_num;
    uint8_t* p = packet.data() + 10;
    for (uint_fast8_t i = 0; i < service_num; ++i) {
        *p++ = service_code[i] & 0xFF;
        *p++ = service_code[i] >> 8;
    }
    *p++ = block_num;
    for (uint_fast8_t i = 0; i < block_num; ++i) {
        block_t ble = block_list[i];
        p += ble.store(p);
    }

    // m5::utility::log::dump(packet.data(), packet.size(), false);

    uint8_t rbuf[1 + 1 + 8 + 1 + 1 + 1 + 16 * block_num]{};
    uint16_t actual = sizeof(rbuf);
    if (!nfcfTransceive(rbuf, actual, packet.data(), packet.size(), timeout_ms) || actual < 12 || (rbuf[0] < 11) ||
        rbuf[1] != m5::stl::to_underlying(ResponseCode::ReadWithoutEncryption) ||  //
        (rbuf[10] /*status 1*/ != 0x00) || (rbuf[11] /*status 2*/ != 0x00)) {
        M5_LIB_LOGE("Failed to readWithoutEncryption (%02X, %u) %u %u %02X %02X", block_list[0].block(), rx_org_len,
                    actual, rbuf[0], rbuf[10], rbuf[11]);
        return false;
    }

    // m5::utility::log::dump(rbuf, actual, false);

    //    const uint8_t blocks = rbuf[11];
    rx_len = std::min<uint16_t>(actual - 13, rx_org_len);
    memcpy(rx, rbuf + 13, rx_len);
    return true;
}

bool UnitST25R3916::nfcfWriteWithoutEncryption(const m5::nfc::f::PICC& picc, const uint16_t* service_code,
                                               const uint8_t service_num, const m5::nfc::f::block_t* block_list,
                                               const uint8_t block_num, const uint8_t* tx, const uint16_t tx_len)
{
    CHECK_MODE();
    if (!tx || !tx_len || !service_code || service_num > 16 || !block_num) {
        return false;
    }

    std::vector<uint8_t> packet{};
    const uint32_t block_size = get_block_list_size(block_list, block_num);
    uint32_t timeout_ms       = 10;  // TODO

    packet.resize(1 + 8 + 1 + (2 * service_num) + 1 + block_size + tx_len);

    packet[0] = m5::stl::to_underlying(CommandCode::WriteWithoutEncryption);
    memcpy(packet.data() + 1, picc.idm, sizeof(picc.idm));
    packet[9]  = service_num;
    uint8_t* p = packet.data() + 10;
    for (uint_fast8_t i = 0; i < service_num; ++i) {
        *p++ = service_code[i] & 0xFF;
        *p++ = service_code[i] >> 8;
    }
    *p++ = block_num;
    for (uint_fast8_t i = 0; i < block_num; ++i) {
        block_t ble = block_list[i];
        p += ble.store(p);
    }
    memcpy(p, tx, tx_len);

    // m5::utility::log::dump(packet.data(), packet.size(), false);

    uint8_t rbuf[1 + 1 + 8 + 1 + 1]{};
    uint16_t actual = sizeof(rbuf);
    if (!nfcfTransceive(rbuf, actual, packet.data(), packet.size(), timeout_ms) || actual < 12 || (rbuf[0] < 11) ||
        rbuf[1] != m5::stl::to_underlying(ResponseCode::WriteWithoutEncryption) ||  //
        (rbuf[10] /*status 1*/ != 0x00) || (rbuf[11] /*status 2*/ != 0x00)) {
        // m5::utility::log::dump(rbuf, actual, false);
        M5_LIB_LOGE("Failed to writeWithoutEncryption (%02X, %u) %u %u %02X %02X", block_list[0].block(), tx_len,
                    actual, rbuf[0], rbuf[10], rbuf[11]);
        return false;
    }
    return true;
}

}  // namespace unit
}  // namespace m5

#if 0
/*
RFAL
14:34:49.261 > DUMP:0x3fcebc8b 5 bytes
14:34:49.267 > 0x3fcebc8b| 00 FF FF 00 03                                  |.....
14:34:49.268 > SpaceA
14:34:49.270 > Reg[0x00]:0x07:00000111
14:34:49.272 > Reg[0x01]:0x3C:00111100
14:34:49.274 > Reg[0x02]:0xCB:11001011
14:34:49.276 > Reg[0x03]:0x1C:00011100
14:34:49.278 > Reg[0x04]:0x11:00010001
14:34:49.280 > Reg[0x05]:0x00:00000000
14:34:49.283 > Reg[0x06]:0x00:00000000
14:34:49.285 > Reg[0x07]:0x00:00000000
14:34:49.287 > Reg[0x08]:0x5D:01011101
14:34:49.289 > Reg[0x09]:0x00:00000000
14:34:49.291 > Reg[0x0A]:0x00:00000000
14:34:49.293 > Reg[0x0B]:0x13:00010011
14:34:49.296 > Reg[0x0C]:0x3D:00111101
14:34:49.298 > Reg[0x0D]:0x00:00000000
14:34:49.300 > Reg[0x0E]:0x00:00000000
14:34:49.302 > Reg[0x0F]:0x28:00101000
14:34:49.304 > Reg[0x10]:0x06:00000110
14:34:49.306 > Reg[0x11]:0x11:00010001
14:34:49.309 > Reg[0x12]:0x22:00100010
14:34:49.311 > Reg[0x13]:0x02:00000010
14:34:49.313 > Reg[0x14]:0xCA:11001010
14:34:49.315 > Reg[0x15]:0x80:10000000
14:34:49.317 > Reg[0x16]:0x85:10000101 Mask M_osc, RFU, M_col
14:34:49.319 > Reg[0x17]:0xA6:10100110 M_dct, M_gpe, M_cac, M_cat
14:34:49.322 > Reg[0x18]:0x0F:00001111 
14:34:49.324 > Reg[0x19]:0x7B:01111011 M_sl_wl, M_apon, M_rxe_pta, M_wu_f, M_wu_a_, M_wu_a
14:34:49.326 > Reg[0x1A]:0x00:00000000 
14:34:49.328 > Reg[0x1B]:0x00:00000000
14:34:49.330 > Reg[0x1C]:0x00:00000000
14:34:49.332 > Reg[0x1D]:0x00:00000000
14:34:49.335 > Reg[0x1E]:0x00:00000000
14:34:49.337 > Reg[0x1F]:0x00:00000000
14:34:49.339 > Reg[0x20]:0x00:00000000
14:34:49.341 > Reg[0x21]:0x00:00000000
14:34:49.343 > Reg[0x22]:0x00:00000000
14:34:49.345 > Reg[0x23]:0x28:00101000
14:34:49.348 > Reg[0x24]:0x00:00000000
14:34:49.350 > Reg[0x25]:0xDF:11011111
14:34:49.352 > Reg[0x26]:0x82:10000010
14:34:49.354 > Reg[0x27]:0x82:10000010
14:34:49.356 > Reg[0x28]:0x70:01110000
14:34:49.358 > Reg[0x29]:0x5F:01011111
14:34:49.361 > Reg[0x2A]:0x13:00010011
14:34:49.363 > Reg[0x2B]:0x02:00000010
14:34:49.365 > Reg[0x2C]:0x00:00000000
14:34:49.367 > Reg[0x2D]:0x00:00000000
14:34:49.369 > Reg[0x2E]:0x00:00000000
14:34:49.372 > Reg[0x2F]:0x00:00000000
14:34:49.374 > Reg[0x30]:0x00:00000000
14:34:49.376 > Reg[0x31]:0x10:00010000
14:34:49.378 > Reg[0x32]:0x00:00000000
14:34:49.380 > Reg[0x33]:0x00:00000000
14:34:49.382 > Reg[0x34]:0x00:00000000
14:34:49.385 > Reg[0x35]:0x00:00000000
14:34:49.387 > Reg[0x36]:0x00:00000000
14:34:49.389 > Reg[0x37]:0x00:00000000
14:34:49.391 > Reg[0x38]:0x00:00000000
14:34:49.393 > Reg[0x39]:0x00:00000000
14:34:49.395 > Reg[0x3A]:0x00:00000000
14:34:49.398 > Reg[0x3B]:0x00:00000000
14:34:49.400 > Reg[0x3C]:0x00:00000000
14:34:49.402 > Reg[0x3D]:0x00:00000000
14:34:49.404 > Reg[0x3E]:0x00:00000000
14:34:49.406 > Reg[0x3F]:0x2A:00101010
14:34:49.407 > SpaceB
14:34:49.409 > Reg[0x00]:0x40:01000000
14:34:49.411 > Reg[0x01]:0x14:00010100
14:34:49.414 > Reg[0x02]:0x0C:00001100
14:34:49.416 > Reg[0x03]:0x54:01010100
14:34:49.418 > Reg[0x04]:0x00:00000000
14:34:49.420 > Reg[0x05]:0x00:00000000
14:34:49.422 > Reg[0x06]:0x00:00000000
14:34:49.424 > Reg[0x07]:0x10:00010000
14:34:49.426 > Reg[0x08]:0x7C:01111100
14:34:49.429 > Reg[0x09]:0x80:10000000
14:34:49.431 > Reg[0x0A]:0x04:00000100
14:34:49.433 > Reg[0x0B]:0xD0:11010000
14:34:49.435 > Reg[0x0C]:0x00:00000000
14:34:49.437 > Reg[0x0D]:0x00:00000000
14:34:49.439 > Reg[0x0E]:0x00:00000000
14:34:49.442 > Reg[0x0F]:0x00:00000000
14:34:49.445 > ST25R3916_CMD_TRANSMIT_WITH_CRC

----
MINE
14:36:51.267 > DUMP:0x3fcebce7 5 bytes
14:36:51.267 > 0x3fcebce7| 00 FF FF 00 03                                  |.....
14:36:51.269 > [  4100][I][unit_ST25R3916.cpp:627] dumpRegister(): SpaceA
14:36:51.275 > [  4102][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X00]:0X00:00000000
14:36:51.282 > [  4109][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X01]:0X98:10011000
14:36:51.289 > [  4115][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X02]:0X88:10001000
14:36:51.295 > [  4122][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X03]:0X1C:00011100
14:36:51.302 > [  4129][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X04]:0X11:00010001
14:36:51.309 > [  4135][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X05]:0X00:00000000
14:36:51.315 > [  4142][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X06]:0X00:00000000
14:36:51.322 > [  4149][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X07]:0X00:00000000
14:36:51.329 > [  4155][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X08]:0X00:00000000
14:36:51.336 > [  4162][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X09]:0X00:00000000
14:36:51.342 > [  4169][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X0A]:0X01:00000001
14:36:51.349 > [  4175][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X0B]:0X13:00010011
14:36:51.356 > [  4182][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X0C]:0X3D:00111101
14:36:51.362 > [  4189][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X0D]:0X00:00000000
14:36:51.369 > [  4195][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X0E]:0X00:00000000
14:36:51.376 > [  4202][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X0F]:0X0C:00001100
14:36:51.382 > [  4209][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X10]:0X4F:01001111
14:36:51.389 > [  4215][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X11]:0X74:01110100
14:36:51.396 > [  4222][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X12]:0X00:00000000
14:36:51.402 > [  4229][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X13]:0X00:00000000
14:36:51.409 > [  4236][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X14]:0X00:00000000
14:36:51.416 > [  4242][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X15]:0X80:10000000

14:36:51.422 > [  4249][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X16]:0XFF:11111111
14:36:51.429 > [  4256][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X17]:0XFF:11111111
14:36:51.436 > [  4262][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X18]:0X00:00000000
14:36:51.443 > [  4269][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X19]:0XFB:11111011

14:34:49.317 > Reg[0x16]:0x85:10000101 Mask M_osc, RFU, M_col
14:34:49.319 > Reg[0x17]:0xA6:10100110 M_dct, M_gpe, M_cac, M_cat
14:34:49.322 > Reg[0x18]:0x0F:00001111 Error mask
14:34:49.324 > Reg[0x19]:0x7B:01111011 M_sl_wl, M_apon, M_rxe_pta, M_wu_f, M_wu_a_, M_wu_a



14:36:51.449 > [  4276][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X1A]:0X00:00000000
14:36:51.456 > [  4282][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X1B]:0X00:00000000
14:36:51.463 > [  4289][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X1C]:0X00:00000000
14:36:51.469 > [  4296][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X1D]:0X00:00000000
14:36:51.476 > [  4302][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X1E]:0X00:00000000
14:36:51.483 > [  4309][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X1F]:0X00:00000000
14:36:51.489 > [  4316][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X20]:0X00:00000000
14:36:51.496 > [  4322][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X21]:0X00:00000000
14:36:51.503 > [  4329][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X22]:0X00:00000000
14:36:51.509 > [  4336][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X23]:0X28:00101000
14:36:51.516 > [  4342][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X24]:0X00:00000000
14:36:51.523 > [  4349][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X25]:0X00:00000000
14:36:51.529 > [  4356][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X26]:0X80:10000000
14:36:51.536 > [  4363][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X27]:0X80:10000000
14:36:51.543 > [  4369][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X28]:0XD0:11010000
14:36:51.549 > [  4376][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X29]:0X60:01100000
14:36:51.556 > [  4383][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X2A]:0X33:00110011
14:36:51.563 > [  4389][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X2B]:0X22:00100010
14:36:51.569 > [  4396][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X2C]:0X00:00000000
14:36:51.576 > [  4403][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X2D]:0X00:00000000
14:36:51.583 > [  4409][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X2E]:0X00:00000000
14:36:51.589 > [  4416][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X2F]:0X00:00000000
14:36:51.596 > [  4423][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X30]:0X00:00000000
14:36:51.603 > [  4429][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X31]:0X10:00010000
14:36:51.610 > [  4436][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X32]:0X00:00000000
14:36:51.616 > [  4443][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X33]:0X00:00000000
14:36:51.623 > [  4449][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X34]:0X00:00000000
14:36:51.630 > [  4456][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X35]:0X00:00000000
14:36:51.636 > [  4463][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X36]:0X00:00000000
14:36:51.643 > [  4469][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X37]:0X00:00000000
14:36:51.650 > [  4476][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X38]:0X00:00000000
14:36:51.656 > [  4483][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X39]:0X00:00000000
14:36:51.663 > [  4490][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X3A]:0X00:00000000
14:36:51.670 > [  4496][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X3B]:0X00:00000000
14:36:51.676 > [  4503][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X3C]:0X00:00000000
14:36:51.683 > [  4510][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X3D]:0X00:00000000
14:36:51.690 > [  4516][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X3E]:0X00:00000000
14:36:51.696 > [  4523][I][unit_ST25R3916.cpp:631] dumpRegister(): Reg[0X3F]:0X2A:00101010
14:36:51.702 > [  4530][I][unit_ST25R3916.cpp:652] dumpRegister(): SpaceB
14:36:51.708 > [  4535][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X05]:0X00:00000000
14:36:51.715 > [  4542][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X06]:0X00:00000000
14:36:51.722 > [  4548][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X0B]:0X0C:00001100
14:36:51.728 > [  4555][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X0C]:0X54:01010100
14:36:51.735 > [  4562][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X0D]:0X00:00000000
14:36:51.742 > [  4568][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X0F]:0X00:00000000
14:36:51.748 > [  4575][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X15]:0X33:00110011
14:36:51.755 > [  4582][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X28]:0X10:00010000
14:36:51.762 > [  4588][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X29]:0X7C:01111100
14:36:51.768 > [  4595][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X2A]:0X00:00000000
14:36:51.775 > [  4602][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X2B]:0X04:00000100
14:36:51.782 > [  4608][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X2C]:0XF0:11110000
14:36:51.789 > [  4615][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X30]:0X00:00000000
14:36:51.795 > [  4622][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X31]:0X00:00000000
14:36:51.802 > [  4628][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X32]:0X00:00000000
14:36:51.809 > [  4635][I][unit_ST25R3916.cpp:656] dumpRegister(): Reg[0X33]:0X00:00000000

14:34:49.407 > SpaceB
14:34:49.409 > Reg[0x05]:0x40:01000000
14:34:49.411 > Reg[0x06]:0x14:00010100
14:34:49.414 > Reg[0x0B]:0x0C:00001100
14:34:49.416 > Reg[0x0C]:0x54:01010100
14:34:49.418 > Reg[0x0D]:0x00:00000000
14:34:49.420 > Reg[0x0F]:0x00:00000000
14:34:49.422 > Reg[0x15]:0x00:00000000
14:34:49.424 > Reg[0x28]:0x10:00010000
14:34:49.426 > Reg[0x29]:0x7C:01111100
14:34:49.429 > Reg[0x2A]:0x80:10000000
14:34:49.431 > Reg[0x2B]:0x04:00000100
14:34:49.433 > Reg[0x2C]:0xD0:11010000
14:34:49.435 > Reg[0x30]:0x00:00000000
14:34:49.437 > Reg[0x31]:0x00:00000000
14:34:49.439 > Reg[0x32]:0x00:00000000
14:34:49.442 > Reg[0x33]:0x00:00000000



*/

#endif
