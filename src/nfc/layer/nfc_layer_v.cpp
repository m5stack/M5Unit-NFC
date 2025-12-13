/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_v.cpp
  @brief Common layer for NFC-V related units
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
namespace unit {
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
        if (!_impl->get_system_information(picc)) {
            continue;
        }
        picc.type   = identify_type(picc.manufacturerCode(), picc.icIdentifier(), picc.icReference(), picc.uid[3]);
        _activePICC = picc;
        M5_LIB_LOGV("Detect:%s", picc.uidAsString().c_str());

        // To QUIET
        if (!_impl->stay_quiet(picc)) {
            M5_LIB_LOGD("Failed to quiet");
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
    if (_impl->select(picc)) {
        _activePICC = picc;
        return true;
    }
    return false;
}

bool NFCLayerV::reactivate(const m5::nfc::v::PICC& picc)
{
    PICC tmp = picc;
    if (picc.valid()) {
        if ((tmp == _activePICC) ? _impl->reset_to_ready() : _impl->reset_to_ready(picc) && _impl->select(picc)) {
            _activePICC = picc;
            return true;
        }
    }
    return false;
}

bool NFCLayerV::deactivate()
{
    if (_activePICC.valid() && _impl->reset_to_ready()) {
        _activePICC = PICC{};
        return true;
    }
    _activePICC = PICC{};
    return false;
}

bool NFCLayerV::readBlock(uint8_t rx[32], const uint8_t block)
{
    return _impl->read_single_block(rx, block);
}

bool NFCLayerV::read(uint8_t* rx, uint16_t& rx_len, const uint8_t sblock)
{
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
    return _impl->write_single_block(block, tx, tx_len);
}

bool NFCLayerV::write(const uint8_t sblock, const uint8_t* tx, const uint16_t tx_len)
{
    const uint8_t block_size = _activePICC.block_size;
    const uint16_t blocks    = (tx_len + block_size - 1) / block_size;
    const uint16_t last      = std::min<uint16_t>(_activePICC.lastUserBlock(), blocks - 1);

    //M5_LIB_LOGE(">>>>WRITE %u %p %u (%u-%u) ", sblock, tx, tx_len, sblock, last);

    if (!_activePICC.valid() || !tx || !tx_len) {
        return false;
    }

    uint16_t written{};
    uint8_t wtmp[block_size]{};
    for (uint_fast16_t block = sblock; block <= last; ++block) {
        const uint16_t wsize = std::min<uint16_t>(tx_len - written, block_size);
        //M5_LIB_LOGE("    write:%02X %u", block, wsize);

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
    return _ndef.isValidFormat(valid, _activePICC.nfcForumTagType());
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
    std::vector<PICC> piccs{};
    if (_impl->inventory(piccs)) {
        picc = piccs.front();
        return true;
    }
    return false;
}

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
}  // namespace unit
}  // namespace m5
