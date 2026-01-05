/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_v.cpp
  @brief Common layer for NFC-V
*/
#include "nfc_layer_v.hpp"
#include "nfc/ndef/ndef.hpp"
#include "nfc/ndef/ndef_tlv.hpp"
#include <inttypes.h>
#include <M5Utility.hpp>
#include <algorithm>
#include <esp_random.h>

using namespace m5::nfc::v;
using namespace m5::nfc::ndef;

namespace {

void parse_inventory(PICC& picc, const uint8_t rx[10])
{
    picc.dsfID = rx[1];
    for (uint_fast8_t i = 0; i < 8; ++i) {
        picc.uid[i] = rx[9 - i];
    }
}

void make_frame(uint8_t frame[10 /* at least */], const uint8_t req, const int8_t cmd, const PICC* picc = nullptr)
{
    if (frame) {
        frame[0] = req;
        frame[1] = cmd;
        if (picc) {
            for (int i = 0; i < 8; ++i) {
                frame[2 + i] = picc->uid[7 - i];
            }
        }
    }
}

inline bool exists_picc(const std::vector<PICC>& v, const PICC& picc)
{
    return std::find_if(v.begin(), v.end(), [&picc](const PICC& p) {  //
               return memcmp(p.uid, picc.uid, 8) == 0;
           }) != v.end();
}

void print_block(const uint8_t* buf, const uint8_t len, const int16_t block)
{
    char tmp[64 + 1] = "      ";
    uint32_t left{};
    // Block
    left += snprintf(tmp + left, 10, "[%03u/%02X]:", block, block);
    // Data
    for (uint8_t i = 0; i < len; ++i) {
        left += snprintf(tmp + left, 4, "%02X ", buf[i]);
    }
    ::puts(tmp);
}

constexpr char dump_header[] =
    "   Block:00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F ";
constexpr char dump_line[] =
    "---------------------------------------------------------------------------------------------------------";

}  // namespace

namespace m5 {
namespace nfc {

bool NFCLayerV::detect(PICC& picc, const uint32_t timeout_ms)
{
    std::vector<PICC> piccs;
    if (detect(piccs, timeout_ms)) {
        picc = piccs.front();
        return true;
    }
    return false;
}

bool NFCLayerV::detect(std::vector<PICC>& piccs, const uint32_t timeout_ms)
{
    piccs.clear();

    auto timeout_at = m5::utility::millis() + timeout_ms;

    do {
        PICC picc{};

        // Exists PICC?
        if (!detect_single(picc)) {
            m5::utility::delay(1);
            continue;
        }

        // Already exists?
        if (exists_picc(piccs, picc)) {
            m5::utility::delay(1);
            continue;
        }
        // Get system information
        if (!get_system_information(picc)) {
            continue;
        }
        picc.type   = identify_type(picc);
        _activePICC = picc;
        M5_LIB_LOGV("Detect:%s", picc.uidAsString().c_str());

        // To QUIET
        if (!stay_quiet(picc)) {
            continue;
        }
        // Append PICC
        piccs.emplace_back(picc);
        m5::utility::delay(1);
    } while (m5::utility::millis() <= timeout_at);

    _activePICC = {};
    return !piccs.empty();
}

bool NFCLayerV::activate(const m5::nfc::v::PICC& picc)
{
    _activePICC = PICC{};

    if (!picc.valid()) {
        return false;
    }

    uint8_t frame[10]{};
    make_frame(frame, address_flag | data_rate_flag, m5::stl::to_underlying(Command::Select), &picc);

    uint8_t rx[2]{};  // OK:1, NG 2bytes
    uint16_t rx_len = sizeof(rx);
    if (!_impl->transceive(rx, rx_len, frame, sizeof(frame), TIMEOUT_SELECT, modulationMode()) || !rx_len) {
        m5::utility::log::dump(rx, rx_len, false);
        M5_LIB_LOGD("Failed to Select %u", rx_len);
        return false;
    }
    if (rx[0] == 0x00) {
        _activePICC = picc;
    }
    return rx[0] == 0x00;
}

bool NFCLayerV::reactivate(const m5::nfc::v::PICC& picc)
{
    PICC tmp = picc;
    if (picc.valid()) {
        return ((tmp == _activePICC) ? reset_to_ready(nullptr) : reset_to_ready(&picc) && activate(picc));
    }
    return false;
}

bool NFCLayerV::deactivate()
{
    if (_activePICC.valid() && reset_to_ready(nullptr)) {
        _activePICC = PICC{};
        return true;
    }
    _activePICC = PICC{};
    return false;
}

bool NFCLayerV::readBlock(uint8_t rx[32], const uint8_t block)
{
    if (!rx || !_activePICC.valid()) {
        return false;
    }

    uint8_t frame[3]{};
    make_frame(frame, select_flag | data_rate_flag, m5::stl::to_underlying(Command::ReadSingleBlock));
    frame[2] = block;

    uint8_t rbuf[32 + 1]{};
    uint16_t rx_len = sizeof(rbuf);
    if (!_impl->transceive(rbuf, rx_len, frame, sizeof(frame), TIMEOUT_READ_SINGLE_BLOCK, modulationMode()) ||
        !rx_len || rbuf[0] != 0x00) {
        M5_LIB_LOGD("Failed to transcieve %u %02X", rx_len, rbuf[1] /* error code */);
        return false;
    }
    memcpy(rx, rbuf + 1, rx_len - 1);
    return true;
}

bool NFCLayerV::read(uint8_t* rx, uint16_t& rx_len, const uint8_t sblock)
{
    if (!_activePICC.valid()) {
        return false;
    }

    auto rx_len_org = rx_len;
    rx_len          = 0;

    const uint8_t block_size = _activePICC.block_size;
    const uint16_t blocks    = rx_len_org / block_size;
    const uint16_t last      = std::min<uint16_t>(_activePICC.blocks - 1, (uint16_t)sblock + blocks - 1);
    if (!_activePICC.valid() || !rx || !rx_len_org) {
        return false;
    }

    uint16_t read_count{};
    uint16_t block = sblock;
    while (block <= last) {
        uint8_t rbuf[32]{};
        if (!readBlock(rbuf, block)) {
            return false;
        }
        memcpy(rx + read_count, rbuf, block_size);
        read_count += block_size;
        ++block;
    }
    rx_len = read_count;
    return true;
}

bool NFCLayerV::writeBlock(const uint8_t block, const uint8_t* tx, const uint8_t tx_len)
{
    if (!tx || !tx_len || tx_len > 32 || !_activePICC.valid()) {
        return false;
    }
    const bool need_opt = _activePICC.manufacturerCode() == 0x07;  // TI needs option flag

    uint8_t frame[2 + 1 + tx_len]{};
    make_frame(frame, select_flag | data_rate_flag | (need_opt ? option_flag : 0),
               m5::stl::to_underlying(Command::WriteSingleBlock));

    uint32_t offset = 2;
    frame[offset++] = block;
    memcpy(frame + offset, tx, tx_len);
    offset += tx_len;

    uint8_t rx[2]{};
    uint16_t rx_len = sizeof(rx);
    if (_impl->transceive(rx, rx_len, frame, offset, TIMEOUT_WRITE_SINGLE_BLOCK, modulationMode()) && rx_len &&
        rx[0] == 0x00) {
        return true;
    }

    /*
      From Tag-it document 1.6
      For reliable programming, we recommend a programming time >=10 ms before the reader
      sends the end of frame (EOF) to request the response from the transponder.
    */
    if (!need_opt) {
        return false;
    }

    // Verify
    {
        m5::utility::delay(10);
        uint8_t rx[32]{};
        if (readBlock(rx, block)) {
            return memcmp(rx, tx, tx_len) == 0;
        } else {
            M5_LIB_LOGD("Failed to read for verify");
        }
    }
    return false;
}

bool NFCLayerV::write(const uint8_t sblock, const uint8_t* tx, const uint16_t tx_len)
{
    const uint8_t block_size = _activePICC.block_size;
    const uint16_t blocks    = (tx_len + block_size - 1) / block_size;
    const uint16_t last      = std::min<uint16_t>(_activePICC.lastUserBlock(), blocks - 1);

    // M5_LIB_LOGE(">>>>WRITE %u %p %u (%u-%u) ", sblock, tx, tx_len, sblock, last);

    if (!_activePICC.valid() || !tx || !tx_len) {
        return false;
    }

    uint16_t written{};
    uint8_t wtmp[block_size]{};
    for (uint_fast16_t block = sblock; block <= last; ++block) {
        const uint16_t wsize = std::min<uint16_t>(tx_len - written, block_size);
        // M5_LIB_LOGE("    write:%02X %u", block, wsize);

        const uint8_t* wp = tx + written;
        // Adjust by block_size
        if (tx_len < block_size) {
            memcpy(wtmp, tx + written, wsize);
            wp = wtmp;
        }

        if (!writeBlock(block, wp, block_size)) {
            return false;
        }
        written += wsize;
    }
    return true;
}

bool NFCLayerV::ndefIsValidFormat(bool& valid)
{
    return _activePICC.valid() && _ndef.isValidFormat(valid, _activePICC.nfcForumTagType());
}

bool NFCLayerV::ndefRead(m5::nfc::ndef::TLV& msg)
{
    msg = TLV{};

    std::vector<TLV> tlvs{};
    if (_activePICC.valid() && _ndef.read(_activePICC.nfcForumTagType(), tlvs, tagBitsMessage)) {
        msg = !tlvs.empty() ? tlvs.front() : TLV{};
        return true;
    }
    return false;
}

bool NFCLayerV::ndefWrite(const m5::nfc::ndef::TLV& msg)
{
    std::vector<TLV> tlvs = {msg};
    return msg.isMessageTLV() && _activePICC.valid() && _ndef.write(_activePICC.nfcForumTagType(), tlvs);
}

bool NFCLayerV::detect_single(m5::nfc::v::PICC& picc)
{
    picc = PICC{};

    const uint8_t req = address_flag | inventory_flag | nb_slots_flag;
    uint8_t cmd[3]    = {req, m5::stl::to_underlying(Command::Inventory), 0x00 /* No mask */};

    uint8_t rx[160]{};
    uint16_t rx_len = sizeof(rx);
    if (!_impl->transceive(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_INVENTORY, modulationMode()) || rx_len < 10 ||
        rx[0] != 0x00) {
        M5_LIB_LOGD("Failed to Inventory %u", rx_len);
        return false;
    }

    parse_inventory(picc, rx);
    return true;
}

bool NFCLayerV::get_system_information(m5::nfc::v::PICC& picc)
{
    if (picc.uid[0] != 0xE0) {
        return false;
    }

    uint8_t frame[10]{};
    make_frame(frame, address_flag | data_rate_flag, m5::stl::to_underlying(Command::GetSystemInformaion), &picc);

    uint8_t rx[15]{};
    uint16_t rx_len = sizeof(rx);
    if (!_impl->transceive(rx, rx_len, frame, sizeof(frame), TIMEOUT_GET_SYSTEM_INFORMATION, modulationMode()) ||
        rx_len != sizeof(rx) || rx[0] != 0x00) {
        M5_LIB_LOGD("Failed to get system information %u %02X", rx_len, rx[1] /* error code */);
        return false;
    }
    // m5::utility::log::dump(rx, rx_len, false);

    const uint8_t info_flags = rx[1];
    uint32_t idx{2 + 8};

    // info_flags bit0: DSFID present
    if (info_flags & 0x01) {
        if (idx >= rx_len) {
            M5_LIB_LOGW("DSFID flag set but no data");
            return true;
        }
        picc.dsfID = rx[idx++];
    }

    // info_flags bit1: AFI present
    if (info_flags & 0x02) {
        if (idx >= rx_len) {
            M5_LIB_LOGW("AFI flag set but no data");
            return true;
        }
        picc.afi = rx[idx++];
    }

    // info_flags bit2: VICC memory size present
    if (info_flags & 0x04) {
        if (idx + 1 >= rx_len) {
            M5_LIB_LOGW("MemSize flag set but not enough data");
            return true;
        }
        const uint16_t nb = rx[idx++];  // number of blocks - 1
        const uint8_t bs  = rx[idx++];  // (block size - 1) in bits4..0
        picc.blocks       = nb + 1;
        picc.block_size   = (bs & 0x1FU) + 1U;
    }

    // info_flags bit3: IC reference present
    if (info_flags & 0x08) {
        if (idx >= rx_len) {
            M5_LIB_LOGW("ICRef flag set but no data");
            return true;
        }
        picc.icRef = rx[idx++];
    }

    return true;
}

bool NFCLayerV::reset_to_ready(const PICC* picc)
{
    if (picc && !picc->valid()) {
        return false;
    }

    uint8_t frame[10]{};
    make_frame(frame, ((picc ? address_flag : select_flag) | data_rate_flag),
               m5::stl::to_underlying(Command::ResetToReady), picc);

    uint8_t rx[8]{};
    uint16_t rx_len = sizeof(rx);
    if (!_impl->transceive(rx, rx_len, frame, (picc ? 10 : 2), TIMEOUT_RESET_TO_READY, modulationMode()) || !rx_len) {
        // m5::utility::log::dump(rx, rx_len, false);
        M5_LIB_LOGD("Failed to ResetToRequest %02X %p %u", frame[0], picc, rx_len);
        return false;
    }
    return rx[0] == 0x00;
}

bool NFCLayerV::stay_quiet(const m5::nfc::v::PICC& picc)
{
    if (!picc.valid()) {
        return false;
    }
    uint8_t frame[10]{};
    make_frame(frame, address_flag | data_rate_flag, m5::stl::to_underlying(Command::StayQuiet), &picc);

    if (!_impl->transmit(frame, sizeof(frame), TIMEOUT_STAY_QUIET, modulationMode())) {
        M5_LIB_LOGD("Failed to StayQuiet");
        return false;
    }
    // Error If exists response
    uint8_t rx[1]{};
    uint16_t rx_len{1};
    return !_impl->receive(rx, rx_len, 1);
}

//
bool NFCLayerV::dump()
{
    return _activePICC.valid() ? dump_all() : false;
}

bool NFCLayerV::dump(const uint8_t block)
{
    return _activePICC.valid() ? dump_block(block) : false;
}

bool NFCLayerV::dump_all()
{
    const uint8_t blocks = _activePICC.blocks;
    if (!blocks) {
        return false;
        ;
    }
    const uint8_t block_size = _activePICC.block_size;

    printf("%.*s\n", block_size * 3 + 8, dump_header);
    printf("%.*s\n", block_size * 3 + 8, dump_line);

    bool ret{true};
    for (int_fast8_t block = 0; block < blocks; ++block) {
        ret &= dump_block(block);
    }
    return ret;
}

bool NFCLayerV::dump_block(const uint8_t block)
{
    uint8_t rx[32]{};

    if (readBlock(rx, block)) {
        print_block(rx, _activePICC.block_size, block);
        return true;
    }
    puts("ERROR");
    return false;
}

}  // namespace nfc
}  // namespace m5
