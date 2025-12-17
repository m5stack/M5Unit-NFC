/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file file_system.cpp
  @brief File system base using isoDEP
*/
#include "file_system.hpp"
#include "nfc/isodep/isoDEP.hpp"
#include "nfc/apdu/apdu.hpp"
#include <M5Utility.hpp>

using namespace m5::nfc::isodep;
using namespace m5::nfc::apdu;

namespace m5 {
namespace nfc {

bool FileSystem::selectFile(const uint8_t* aid, const uint8_t aid_len, const uint8_t param1, const uint8_t param2)
{
    if (!aid || !aid_len) {
        return false;
    }

    auto cmd = make_apdu_case4(0x00, m5::stl::to_underlying(INS::SELECT_FILE), param1, param2, aid, aid_len,
                               need_select_file_le(param2) ? 256 : 0);

    uint8_t rx[256]{};
    uint16_t rx_len = sizeof(rx);
    if (!_isoDEP.transceiveAPDU(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        M5_LIB_LOGE("Failed SELECT by DF name");
        return false;
    }
    // m5::utility::log::dump(rx, rx_len, false);

    auto tlvs = parse_tlv(rx, rx_len - 2);
    dump_tlv(tlvs);

    if (!is_response_OK(rx + rx_len - 2)) {
        M5_LIB_LOGE("SW:%02X:%02X", rx[rx_len - 2], rx[rx_len - 1]);
        M5_DUMPE(cmd.data(), cmd.size());
        return false;
    }
    return true;
}

bool FileSystem::selectFile(const uint16_t fid, const uint8_t param1, const uint8_t param2)
{
    const uint8_t file_id[2] = {
        static_cast<uint8_t>((fid >> 8) & 0xFF),
        static_cast<uint8_t>(fid & 0xFF),
    };

    auto cmd = make_apdu_case4(0x00, m5::stl::to_underlying(INS::SELECT_FILE), param1, param2, file_id, sizeof(file_id),
                               (need_select_file_le(param2) && fid != 0x3F00) ? 256 : 0);

    uint8_t rx[256]{};
    uint16_t rx_len = sizeof(rx);
    if (!_isoDEP.transceiveAPDU(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        M5_LIB_LOGE("Failed SELECT by File ID");
        return false;
    }
    // m5::utility::log::dump(rx, rx_len, false);

    auto tlvs = parse_tlv(rx, rx_len - 2);
    dump_tlv(tlvs);

    if (!is_response_OK(rx + rx_len - 2)) {
        M5_LIB_LOGE("SW:%02X:%02X", rx[rx_len - 2], rx[rx_len - 1]);
        M5_DUMPE(cmd.data(), cmd.size());
        return false;
    }
    return true;
}

bool FileSystem::verify(const uint8_t* password, const uint16_t pass_len, const uint8_t param2)
{
    if (!password || !pass_len) {
        return false;
    }

    auto cmd = make_apdu_case3(0x00, m5::stl::to_underlying(INS::VERIFY), 0x00, param2, password, pass_len);

    uint8_t rx[2]{};
    uint16_t rx_len = sizeof(rx);
    if (!_isoDEP.transceiveAPDU(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        M5_LIB_LOGE("Failed SELECT by File ID");
        return false;
    }
    if (!is_response_OK(rx + rx_len - 2)) {
        M5_LIB_LOGE("SW:%02X:%02X", rx[rx_len - 2], rx[rx_len - 1]);
        M5_DUMPE(cmd.data(), cmd.size());
        return false;
    }
    return true;
}

bool FileSystem::readBinary(std::vector<uint8_t>& out, const uint16_t offset,
                            const uint16_t le /* 1..256 recommended */)
{
    out.clear();

    if (le == 0) {
        return false;
    }

    const uint8_t p1 = static_cast<uint8_t>((offset >> 8) & 0xFF);
    const uint8_t p2 = static_cast<uint8_t>(offset & 0xFF);

    auto cmd = make_apdu_case2(0x00, m5::stl::to_underlying(INS::READ_BINARY), p1, p2, le);

    std::vector<uint8_t> rx;
    rx.resize(le + 2 + 16);

    uint16_t rx_len = static_cast<uint16_t>(rx.size());
    if (!_isoDEP.transceiveAPDU(rx.data(), rx_len, cmd.data(), static_cast<uint16_t>(cmd.size())) || rx_len < 2) {
        M5_LIB_LOGE("READ BINARY failed (transport)");
        return false;
    }

    // SW をチェック
    if (!is_response_OK(rx.data() + rx_len - 2)) {
        M5_LIB_LOGE("SW:%02X:%02X", rx[rx_len - 2], rx[rx_len - 1]);
        M5_DUMPE(cmd.data(), cmd.size());
        return false;
    }
    out.assign(rx.begin(), rx.begin() + (rx_len - 2));
    return true;
}
}  // namespace nfc
}  // namespace m5
