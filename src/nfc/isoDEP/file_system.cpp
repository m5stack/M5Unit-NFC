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
#include "nfc/isoDEP/isoDEP.hpp"
#include "nfc/apdu/apdu.hpp"
#include <M5Utility.hpp>
#include <algorithm>
#include <limits>

using namespace m5::nfc::isodep;
using namespace m5::nfc::apdu;

namespace {

inline uint16_t clamp_u16_size(const size_t size)
{
    constexpr size_t max_u16 = std::numeric_limits<uint16_t>::max();
    return static_cast<uint16_t>(size > max_u16 ? max_u16 : size);
}

}  // namespace

namespace m5 {
namespace nfc {

bool parseFCI(FCP& fcp, const uint8_t* data, const uint32_t len)
{
    if (!data || len < 2) {
        return false;
    }

    const auto tlvs    = parse_tlv(data, len);
    const TLV* fci_tlv = nullptr;
    for (const auto& tlv : tlvs) {
        if (tlv.tag == 0x6F) {
            fci_tlv = &tlv;
            break;
        }
    }
    if (!fci_tlv) {
        return false;
    }

    const auto fci_inner = parse_tlv(fci_tlv->v, fci_tlv->len);
    const TLV* fcp_tlv   = nullptr;
    for (const auto& tlv : fci_inner) {
        if (tlv.tag == 0x62) {
            fcp_tlv = &tlv;
            break;
        }
    }
    if (!fcp_tlv) {
        return false;
    }

    bool have_fid        = false;
    bool have_size       = false;
    const auto fcp_inner = parse_tlv(fcp_tlv->v, fcp_tlv->len);
    for (const auto& tlv : fcp_inner) {
        if (tlv.tag == 0x82 && tlv.len == 1) {
            fcp.file_descriptor = tlv.v[0];
            continue;
        }
        if (tlv.tag == 0x83 && tlv.len >= 2) {
            fcp.fid  = static_cast<uint16_t>((tlv.v[0] << 8) | tlv.v[1]);
            have_fid = true;
            continue;
        }
        if ((tlv.tag == 0x80 || tlv.tag == 0x81 || tlv.tag == 0x83 || (tlv.tag == 0x82 && tlv.len >= 2)) &&
            tlv.len >= 2) {
            fcp.file_size_tag = static_cast<uint8_t>(tlv.tag & 0xFF);
            fcp.file_size     = static_cast<uint16_t>((tlv.v[0] << 8) | tlv.v[1]);
            have_size         = true;
        }
    }

    return have_fid && have_size;
}

bool FileSystem::createFile(const uint8_t* fcp, const uint16_t fcp_len)
{
    auto cmd = make_apdu_case3(0x00, m5::stl::to_underlying(INS::CREATE_FILE), 0x00, 0x00, fcp, fcp_len);

    uint8_t rx[2]{};
    uint16_t rx_len = sizeof(rx);
    if (!_isoDEP.transceiveAPDU(rx, rx_len, cmd.data(), static_cast<uint16_t>(cmd.size())) || rx_len < 2) {
        M5_LIB_LOGE("CREATE FILE failed (transport) %u", rx_len);
        return false;
    }
    if (!is_response_OK(rx + rx_len - 2)) {
        M5_LIB_LOGE("Response error SW:%02X:%02X", rx[rx_len - 2], rx[rx_len - 1]);
        return false;
    }
    return true;
}

bool FileSystem::createFile(const FCP& fcp)
{
    const auto tlv = fcp.to_tlv();
    if (tlv.empty()) {
        return false;
    }
    return createFile(tlv.data(), tlv.size());
}

bool FileSystem::createFile(const uint16_t fid, const uint16_t file_size)
{
    FCP fcp{};
    fcp.fid       = fid;
    fcp.file_size = file_size;
    return createFile(fcp);
}

bool FileSystem::selectFile(const m5::nfc::apdu::SelectBy by, const m5::nfc::apdu::SelectOccurrence occ,
                            const m5::nfc::apdu::SelectResponse res, const uint8_t* param, const uint8_t param_len)
{
    _last_select_fci.clear();

    if (!param || !param_len) {
        return false;
    }

    const uint8_t p1  = m5::stl::to_underlying(by) | m5::stl::to_underlying(occ);
    const uint8_t p2  = m5::stl::to_underlying(res);
    const uint16_t le = need_select_file_le(p2) ? 256 : 0;
    auto cmd          = make_apdu_command(0x00, m5::stl::to_underlying(INS::SELECT_FILE), p1, p2, param, param_len, le);

    // M5_LIB_LOGE("SELECT p1:%02X p2:%02X le:%u len:%u", p1, p2, le, param_len);
    // m5::utility::log::dump(cmd.data(), cmd.size(), false);

    uint8_t rx[256]{};
    uint16_t rx_len = sizeof(rx);
    if (!_isoDEP.transceiveAPDU(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        M5_LIB_LOGE("Failed to selectFile");
        return false;
    }
    // m5::utility::log::dump(rx, rx_len, false);

    auto tlvs = parse_tlv(rx, rx_len - 2);
    //    dump_tlv(tlvs);

    /*
    // Debug: Show SELECT response
    M5_LIB_LOGE("SELECT response: rx_len=%u SW=%02X:%02X", rx_len, rx[rx_len - 2], rx[rx_len - 1]);
    if (rx_len > 2) {
        m5::utility::log::dump(rx, rx_len - 2, false);
    }
    */

    if (!is_response_OK(rx + rx_len - 2)) {
        // M5_LIB_LOGE("Response error SW:%02X:%02X", rx[rx_len - 2], rx[rx_len - 1]);
        //  M5_DUMPE(cmd.data(), cmd.size());
        return false;
    }

    if (res == SelectResponse::FCI) {
        _last_select_fci.assign(rx, rx + rx_len - 2);
    }

    return true;
}

bool FileSystem::selectByFileId(const uint16_t fid, const m5::nfc::apdu::SelectResponse res,
                                const m5::nfc::apdu::SelectOccurrence occ)
{
    const uint8_t file_id[2] = {
        static_cast<uint8_t>((fid >> 8) & 0xFF),
        static_cast<uint8_t>(fid & 0xFF),
    };
    return selectFile(m5::nfc::apdu::SelectBy::FileId, occ, res, file_id, sizeof(file_id));
}

bool FileSystem::selectFileIdAuto(const uint16_t fid, const m5::nfc::apdu::SelectOccurrence occ)
{
    // Response handling varies depending on PICC, so fallback is required
    return selectByFileId(fid, m5::nfc::apdu::SelectResponse::FCI, occ) ||
           selectByFileId(fid, m5::nfc::apdu::SelectResponse::None, occ) ||
           selectByFileId(fid, m5::nfc::apdu::SelectResponse::FCP, occ);
}

bool FileSystem::selectByDfName(const uint8_t* aid, const uint8_t aid_len, const m5::nfc::apdu::SelectResponse res,
                                const m5::nfc::apdu::SelectOccurrence occ)
{
    return selectFile(m5::nfc::apdu::SelectBy::DfName, occ, res, aid, aid_len);
}

bool FileSystem::selectDfNameAuto(const uint8_t* aid, const uint8_t aid_len, const m5::nfc::apdu::SelectOccurrence occ)
{
    // Response handling varies depending on PICC, so fallback is required
    return selectByDfName(aid, aid_len, m5::nfc::apdu::SelectResponse::FCI, occ) ||
           selectByDfName(aid, aid_len, m5::nfc::apdu::SelectResponse::None, occ) ||
           selectByDfName(aid, aid_len, m5::nfc::apdu::SelectResponse::FCP, occ);
}

bool FileSystem::selectByPath(const uint8_t* path, const uint8_t path_len, const bool from_mf,
                              const m5::nfc::apdu::SelectResponse res, const m5::nfc::apdu::SelectOccurrence occ)
{
    const auto by = from_mf ? m5::nfc::apdu::SelectBy::PathFromMf : m5::nfc::apdu::SelectBy::PathFromCurrentDf;
    return selectFile(by, occ, res, path, path_len);
}

bool FileSystem::selectParent(const m5::nfc::apdu::SelectResponse res, const m5::nfc::apdu::SelectOccurrence occ)
{
    const uint8_t p1 = m5::stl::to_underlying(m5::nfc::apdu::SelectBy::ParentDf) | m5::stl::to_underlying(occ);
    const uint8_t p2 = m5::stl::to_underlying(res);

    std::vector<uint8_t> cmd = need_select_file_le(p2)
                                   ? make_apdu_case2(0x00, m5::stl::to_underlying(INS::SELECT_FILE), p1, p2, 256)
                                   : make_apdu_case1(0x00, m5::stl::to_underlying(INS::SELECT_FILE), p1, p2);

    uint8_t rx[256]{};
    uint16_t rx_len = sizeof(rx);
    if (!_isoDEP.transceiveAPDU(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        M5_LIB_LOGE("Failed SELECT parent");
        return false;
    }

    if (need_select_file_le(p2)) {
        auto tlvs = parse_tlv(rx, rx_len - 2);
        dump_tlv(tlvs);
    }

    if (!is_response_OK(rx + rx_len - 2)) {
        M5_LIB_LOGE("Response error SW:%02X:%02X", rx[rx_len - 2], rx[rx_len - 1]);
        // M5_DUMPE(cmd.data(), cmd.size());
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
        M5_LIB_LOGE("Response error SW:%02X:%02X", rx[rx_len - 2], rx[rx_len - 1]);
        // M5_DUMPE(cmd.data(), cmd.size());
        return false;
    }
    return true;
}

bool FileSystem::readBinary(std::vector<uint8_t>& out, const uint16_t offset,
                            const uint16_t le /* 1..256 recommended */)
{
    out.clear();

    if (le == 0 || le > 256) {
        M5_LIB_LOGE("invalid le %u", le);
        return false;
    }

    const uint8_t p1 = static_cast<uint8_t>((offset >> 8) & 0xFF);
    const uint8_t p2 = static_cast<uint8_t>(offset & 0xFF);
    // const bool sfi   = (p1 & 0x80) != 0;
    //  M5_LIB_LOGE("READ BINARY off:%u p1:%02X p2:%02X le:%u sfi:%u", offset, p1, p2, le, sfi ? 1 : 0);

    auto cmd = make_apdu_case2(0x00, m5::stl::to_underlying(INS::READ_BINARY), p1, p2, le);
    // m5::utility::log::dump(cmd.data(), cmd.size(), false);

    std::vector<uint8_t> rx;
    rx.resize(le + 2 + 16);

    uint16_t rx_len = clamp_u16_size(rx.size());
    if (!_isoDEP.transceiveAPDU(rx.data(), rx_len, cmd.data(), static_cast<uint16_t>(cmd.size())) || rx_len < 2) {
        M5_LIB_LOGE("READ BINARY failed (transport) %u", rx_len);
        return false;
    }

    if (!is_response_OK(rx.data() + rx_len - 2)) {
        M5_LIB_LOGE("Response error SW:%02X:%02X", rx[rx_len - 2], rx[rx_len - 1]);
        // M5_DUMPE(cmd.data(), cmd.size());
        return false;
    }
    out.assign(rx.begin(), rx.begin() + (rx_len - 2));
    return true;
}

bool FileSystem::updateBinary(const uint16_t offset, const uint8_t* data, const uint16_t data_len)
{
    if (!data || data_len == 0) {
        return false;
    }

    const uint8_t p1 = static_cast<uint8_t>((offset >> 8) & 0xFF);
    const uint8_t p2 = static_cast<uint8_t>(offset & 0xFF);
    // const bool sfi   = (p1 & 0x80) != 0;
    //  M5_LIB_LOGE("UPDATE BINARY off:%u p1:%02X p2:%02X len:%u sfi:%u", offset, p1, p2, data_len, sfi ? 1 : 0);

    auto cmd = make_apdu_case3(0x00, m5::stl::to_underlying(INS::UPDATE_BINARY), p1, p2, data, data_len);
    // m5::utility::log::dump(cmd.data(), cmd.size(), false);

    uint8_t rx[2]{};
    uint16_t rx_len = sizeof(rx);
    if (!_isoDEP.transceiveAPDU(rx, rx_len, cmd.data(), static_cast<uint16_t>(cmd.size())) || rx_len < 2) {
        M5_LIB_LOGE("UPDATE BINARY failed (transport) %u", rx_len);
        return false;
    }
    if (!is_response_OK(rx + rx_len - 2)) {
        M5_LIB_LOGE("Response error SW:%02X:%02X", rx[rx_len - 2], rx[rx_len - 1]);
        // M5_DUMPE(cmd.data(), cmd.size());
        return false;
    }
    return true;
}

}  // namespace nfc
}  // namespace m5
