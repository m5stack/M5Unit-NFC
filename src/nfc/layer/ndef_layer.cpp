/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file ndef_layer.cpp
  @brief Common layer for NDEF related
*/
#include "ndef_layer.hpp"
#include "nfc/ndef/ndef.hpp"
#include "nfc/ndef/ndef_tlv.hpp"
#include "nfc/ndef/ndef_record.hpp"
#include <M5Utility.hpp>
#include <algorithm>
#include <numeric>

using namespace m5::nfc;
using namespace m5::nfc::ndef;

namespace m5 {
namespace nfc {
namespace ndef {

// Check CC/AB
bool NDEFLayer::isValidFormat(bool& valid, const m5::nfc::NFCForumTag ftag)
{
    valid = false;

    switch (ftag) {
        case NFCForumTag::Type2: {
            type2::CapabilityContainer cc{};
            if (readCapabilityContainer(cc)) {
                valid = cc.valid();
                return true;
            }
        } break;

        case NFCForumTag::Type3: {
            type3::AttributeBlock ab{};
            if (readAttributeBlock(ab)) {
                valid = ab.valid();
                return true;
            }
        } break;
        case NFCForumTag::Type5: {
            type5::CapabilityContainer cc{};
            if (readCapabilityContainer(cc)) {
                valid = cc.valid();
                return true;
            }
        } break;
        case NFCForumTag::Type1:
        case NFCForumTag::Type4:
        default:
            break;
    }
    return false;
}

bool NDEFLayer::readCapabilityContainer(m5::nfc::ndef::type2::CapabilityContainer& cc)
{
    using type2::CapabilityContainer;

    cc = CapabilityContainer{};

    const uint16_t block_size = _interface.unit_size_read();

    uint8_t rx[block_size]{};
    uint16_t rx_len = block_size;
    uint8_t ccb     = (block_size == 4) ? TYPE2_CC_BLOCK : 0 /* 0-3 page*/;
    if (!_interface.read(rx, rx_len, ccb) || (rx_len != block_size)) {
        return false;
    }
    memcpy(cc.block, rx + ((block_size == 4) ? 0 : 12), sizeof(cc.block));

    M5_LIB_LOGE("CC2:%02X %u.%u %u %02X/%02X", cc.block[0], cc.major_version(), cc.minor_version(), cc.ndef_size(),
                cc.read_access(), cc.write_access());

    return true;
}

bool NDEFLayer::readAttributeBlock(m5::nfc::ndef::type3::AttributeBlock& ab)
{
    using type3::AttributeBlock;

    ab = AttributeBlock{};

    uint16_t block = _interface.first_user_block();
    if (block == 0xFFFF) {
        return false;
    }

    uint16_t rx_len = sizeof(ab.block);
    if (!_interface.read(ab.block, rx_len, block) || rx_len != sizeof(ab.block) ||
        ab.check_sum() != ab.calculate_check_sum()) {
        M5_LIB_LOGE("Failed to read AB actual:%u sum:%04X/%04X", rx_len, ab.check_sum(), ab.calculate_check_sum());
        return false;
    }
    M5_LIB_LOGV("AB:%02X %u/%u/%u %02X/%02X %u %04X/%04X", ab.version(), ab.max_block_to_read(),
                ab.max_block_to_write(), ab.blocks_for_ndef_storage(), ab.write_flag(), ab.access_flag(),
                ab.current_ndef_message_length(), ab.check_sum(), ab.calculate_check_sum());
    return true;
}

bool NDEFLayer::readCapabilityContainer(m5::nfc::ndef::type5::CapabilityContainer& cc)
{
    using type5::CapabilityContainer;

    cc = CapabilityContainer{};

    auto cc_block = _interface.first_user_block();  // May be block 0
    if (cc_block == 0xFFFF) {
        return false;
    }
    uint16_t cc_block_size = _interface.unit_size_read();
    if (!cc_block_size) {
        return false;
    }
    while (cc_block_size < 8) {  // Support 8 byte CC
        cc_block_size <<= 1;
    }

    // Read CC
    uint8_t rx[cc_block_size]{};
    uint16_t rx_len = sizeof(rx);
    if (!_interface.read(rx, rx_len, cc_block) || rx_len != cc_block_size) {
        return false;
    }
    memcpy(cc.block, rx, std::min<uint16_t>(rx_len, sizeof(cc.block)));

    M5_LIB_LOGV("CC5:%02X %u.%u %u %02X/%02X %02X", cc.block[0], cc.major_version(), cc.minor_version(), cc.ndef_size(),
                cc.read_access(), cc.write_access(), cc.addtional_feature());

    return true;
}

bool NDEFLayer::read(const m5::nfc::NFCForumTag ftag, std::vector<m5::nfc::ndef::TLV>& tlvs,
                     const m5::nfc::ndef::TagBits tagBits)
{
    tlvs.clear();

    switch (ftag) {
        case NFCForumTag::Type2:
            return read_type2(tlvs, tagBits);
        case NFCForumTag::Type3: {
            TLV tlv{};
            if (read_type3(tlv)) {
                tlvs.emplace_back(tlv);
                return true;
            }
        } break;
        case NFCForumTag::Type5:
            return read_type5(tlvs, tagBits);
        case NFCForumTag::Type1:
        case NFCForumTag::Type4:
        default:
            break;
    }
    return false;
}

bool NDEFLayer::write(const m5::nfc::NFCForumTag ftag, const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep)
{
    if (!tlvs.empty()) {
        switch (ftag) {
            case NFCForumTag::Type2:
                return write_type2(tlvs, keep);
            case NFCForumTag::Type3:
                return write_type3(tlvs.front());
            case NFCForumTag::Type5:
                return write_type5(tlvs, keep);
            case NFCForumTag::Type1:
            case NFCForumTag::Type4:
            default:
                break;
        }
    }
    return false;
}

//
bool NDEFLayer::read_type2(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::TagBits tagBits)
{
    tlvs.clear();
    type2::CapabilityContainer cc{};
    if (!readCapabilityContainer(cc) || !cc.valid()) {
        M5_LIB_LOGE("Failed to read CC or invalid CC %02X:%02X:%02X;%02X",  //
                    cc.block[0], cc.block[1], cc.block[2], cc.block[3]);
        return false;
    }

    bool ret{};
    uint8_t* buf{};
    uint16_t block      = _interface.first_user_block();
    uint16_t last_block = _interface.last_user_block();
    if (block == 0xFFFF || last_block == 0xFFFF) {
        return false;
    }

    const uint16_t buf_size = _interface.user_area_size();

    buf = static_cast<uint8_t*>(malloc(buf_size));
    if (!buf) {
        M5_LIB_LOGE("Failed to allocate memory %u", buf_size);
        return false;
    }

    // Read TLV
    uint16_t actual{buf_size};
    if (!_interface.read(buf, actual, block) || actual == 0) {
        M5_LIB_LOGE("Failed to read %u %u", block, actual);
        goto skip;
    }

    {
        uint32_t offset{}, idx{};
        TLV tlv{};
        do {
            auto decoded = tlv.decode(buf + offset, actual > offset ? actual - offset : 0);
            // Even if decoding fails, return the results up to that point and treat it as a success
            if (!decoded) {
                M5_LIB_LOGE("Failed to decode [%3u]:%02X", idx, tlv.tag());
                break;
            }
            offset += decoded;
            ++idx;
            M5_LIB_LOGD("Decoded:%u %02X", decoded, tlv.tag());

            if (contains_tag(tagBits, tlv.tag())) {
                tlvs.push_back(tlv);
            }

        } while (!tlv.isTerminatorTLV() && !tlv.isNullTLV());
        ret = true;
    }

skip:
    free(buf);
    return ret;
}

bool NDEFLayer::read_type3(m5::nfc::ndef::TLV& tlv)
{
    using type3::AttributeBlock;
    tlv = TLV{};

    // Check AB
    AttributeBlock ab{};
    if (!readAttributeBlock(ab) || !ab.valid()) {
        M5_LIB_LOGE("Failed to read AB or invalid AB %02X:%02X:%02X;%02X",  //
                    ab.block[0], ab.block[1], ab.block[2], ab.block[3]);
        return false;
    }

    TLV tmp{Tag::Message};
    bool ret{};
    uint16_t block      = _interface.first_user_block();
    uint16_t last_block = _interface.last_user_block();
    if (block == 0xFFFF || last_block == 0xFFFF) {
        M5_LIB_LOGE("ERROR");
        return false;
    }

    // Read NDEF Records
    uint16_t buf_size = ((ab.current_ndef_message_length() + 15) >> 4) << 4;
    uint8_t* buf{};

    if (buf_size) {
        buf = static_cast<uint8_t*>(malloc(buf_size));

        if (!buf) {
            M5_LIB_LOGE("Failed to allocate memory %u", buf_size);
            return false;
        }
        uint16_t actual = buf_size;
        if (!_interface.read(buf, actual, block + 1) || actual != buf_size) {
            M5_LIB_LOGE("Failed to read %u/%u", actual, buf_size);
            goto skip;
        }

        {
            uint16_t decoded{};
            uint16_t idx{};
            while (decoded < ab.current_ndef_message_length()) {
                Record r{};
                auto len = r.decode(buf + decoded, actual - decoded);
                if (!len) {
                    M5_LIB_LOGE("Failed to decode %u", idx);
                    goto skip;
                }
                tmp.push_back(r);
                decoded += len;
                ++idx;
            }
        }
        tlv = tmp;
    }
    ret = true;

skip:
    free(buf);
    return ret;
}

bool NDEFLayer::read_type5(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::TagBits tagBits)
{
    tlvs.clear();
    type5::CapabilityContainer cc{};
    if (!readCapabilityContainer(cc) || !cc.valid()) {
        M5_LIB_LOGE("Failed to read CC or invalid CC %02X:%02X:%02X;%02X",  //
                    cc.block[0], cc.block[1], cc.block[2], cc.block[3]);
        return false;
    }

    TLV tmp{Tag::Message};
    bool ret{};

    uint16_t block            = _interface.first_user_block();
    const uint16_t last_block = _interface.last_user_block();
    if (block == 0xFFFF || last_block == 0xFFFF) {
        return false;
    }

    // Read CC + TLV
    const uint16_t buf_size = _interface.user_area_size();
    uint8_t* buf            = static_cast<uint8_t*>(malloc(buf_size));
    if (!buf) {
        M5_LIB_LOGE("Failed to allocate memory %u", buf_size);
        return false;
    }

    if (buf) {
        uint16_t actual = buf_size;
        if (!_interface.read(buf, actual, block) || actual != buf_size) {
            M5_LIB_LOGE("Failed to read %u %u/%u", block, actual, buf_size);
            goto skip;
        }

        {
            uint32_t offset = cc.size();
            uint32_t idx{};
            TLV tlv{};
            do {
                auto decoded = tlv.decode(buf + offset, actual > offset ? actual - offset : 0);
                // Even if decoding fails, return the results up to that point and treat it as a success
                if (!decoded) {
                    M5_LIB_LOGW("Failed to decode [%3u]:%02X", idx, tlv.tag());
                    ret = true;
                    break;
                }
                offset += decoded;
                ++idx;
                M5_LIB_LOGV("Decoded:%u %02X", decoded, tlv.tag());

                if (contains_tag(tagBits, tlv.tag())) {
                    tlvs.push_back(tlv);
                }

            } while (!tlv.isTerminatorTLV() && !tlv.isNullTLV());
            ret = true;
        }
    }

skip:
    free(buf);
    return ret;
}

bool NDEFLayer::write_type2(const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep)
{
    bool ret{};
    const uint32_t user_size = _interface.user_area_size();

    if (tlvs.empty()) {
        return false;
    }

    std::vector<TLV> tmp{};
    if (keep) {
        // Maintain TLVs that must not be removed
        if (!read_type2(tmp, tagBitsAll)) {
            return false;
        }
        tmp = merge_tlv(tmp, tlvs);
    } else {
        // Overwirte
        tmp = tlvs;
    }

    // Calculate encoded size
    uint32_t encoded_size =
        std::accumulate(tmp.begin(), tmp.end(), 0U, [](uint32_t acc, const TLV& m) { return acc + m.required(); });

    M5_LIB_LOGD("Encoded size:%u", encoded_size);
    if (encoded_size > user_size) {
        M5_LIB_LOGE("Not enough area %u/%u", encoded_size, user_size);
        return false;
    }

    // Encode
    uint8_t* buf = static_cast<uint8_t*>(malloc(encoded_size));
    if (!buf) {
        M5_LIB_LOGE("Failed to allocate memory %u", encoded_size);
        return false;
    }

    uint32_t offset{};
    uint32_t idx{};
    for (auto&& m : tmp) {
        const auto esz = m.encode(buf + offset, encoded_size - offset);
        M5_LIB_LOGD("   [%3u] Tag:%02X %u %u", idx, m.tag(), esz, m.required());
        if (!esz) {
            M5_LIB_LOGE("encode failed %u %02X", idx, m.tag());
            goto skip;
        }
        offset += esz;
        ++idx;
    }
    if (offset > encoded_size) {
        M5_LIB_LOGE("Internal error %u/%u", offset, encoded_size);
        goto skip;
    }

    // Write
    // M5_LIB_LOGE(">>>>ndef write %u %u", _interface.first_user_block(), encoded_size);
    ret = _interface.write(_interface.first_user_block(), buf, encoded_size);

skip:
    free(buf);
    return ret;
}

bool NDEFLayer::write_type3(const m5::nfc::ndef::TLV& tlv)
{
    using type3::AttributeBlock;

    AttributeBlock ab{};
    bool ret{};

    if (!tlv.isMessageTLV()) {
        return false;
    }

    // Read AB
    if (!readAttributeBlock(ab)) {
        return false;
    }

    uint16_t first_block = _interface.first_user_block();
    uint16_t last_block  = _interface.last_user_block();
    if (first_block == 0xFFFF || last_block == 0xFFFF) {
        return false;
    }

    uint16_t user_size   = _interface.user_area_size();
    uint32_t record_size = std::accumulate(tlv.records().begin(), tlv.records().end(), 0U,
                                           [](uint32_t acc, const Record& r) { return acc + r.required(); });
    if (record_size + 16 > user_size) {
        M5_LIB_LOGE("Not enough area %u/%u", record_size + 16, user_size);
        return false;
    }

    // Encode
    uint8_t* buf = static_cast<uint8_t*>(malloc(record_size));
    if (!buf) {
        M5_LIB_LOGE("Failed to allocate memory %u", record_size);
        return false;
    }

    uint32_t idx{};
    uint32_t encoded{};
    for (auto&& r : tlv.records()) {
        auto len = r.encode(buf + encoded, record_size - encoded);
        if (!len) {
            M5_LIB_LOGE("Failed to encode %u", idx);
            goto skip;
        }
        encoded += len;
        ++idx;
    }

    // Write
    {
        if (!ab.valid()) {
            ab.version(AttributeBlock::DEFAULT_VERSION);
            ab.max_block_to_read(_interface.maximum_read_blocks());
            ab.max_block_to_write(_interface.maximum_write_blocks());
            ab.blocks_for_ndef_storage(last_block - first_block + 1 - 1 /* AB */);
            ab.access_flag(AttributeBlock::AccessFlag::ReadWrite);
        }
        ab.write_flag(AttributeBlock::WriteFlag::InProgress);  // protect
        ab.current_ndef_message_length(record_size);
        ab.update_check_sum();

        // 1) Write AB (In progress)
        if (!_interface.write(first_block, ab.block, sizeof(ab.block))) {
            goto skip;
        }
        // 2) Write records
        if (!_interface.write(first_block + 1, buf, record_size)) {
            goto skip;
        }
        // 3) Write AB again (Done)
        ab.write_flag(AttributeBlock::WriteFlag::Done);  // done
        ab.update_check_sum();
        if (!_interface.write(first_block, ab.block, sizeof(ab.block))) {
            goto skip;
        }
        ret = true;
    }

skip:
    free(buf);
    return ret;
}

bool NDEFLayer::write_type5(const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep)
{
    bool ret{};
    const uint32_t user_size = _interface.user_area_size();

    M5_LIB_LOGE(">>>>>>>>>>>>>>>>>>>>>> ");

    if (tlvs.empty()) {
        return false;
    }

    std::vector<TLV> tmp{};
    if (keep) {
        bool valid{};
        if (!isValidFormat(valid, NFCForumTag::Type5)) {
            return false;
        }
        if (valid) {
            // Read all TLV and merge
            if (!read_type5(tmp, tagBitsAll)) {
                return false;
            }
            tmp = merge_tlv(tmp, tlvs);
        } else {
            // Overwrite if CC is invalid
            tmp = tlvs;
        }
    } else {
        tmp = tlvs;  // Overwrite
    }

    // Read CC
    type5::CapabilityContainer cc{};
    if (!readCapabilityContainer(cc)) {
        return false;
    }

    // Calculate encoded size
    uint32_t encoded_size =
        std::accumulate(tmp.begin(), tmp.end(), 0U, [](uint32_t acc, const TLV& m) { return acc + m.required(); });

    M5_LIB_LOGD("Encoded size:%u", encoded_size);
    uint32_t buf_size = encoded_size + (encoded_size > CC4_MAX_NDEF_LENGTH ? 8 : 4);
    if (buf_size > _interface.user_area_size()) {
        M5_LIB_LOGE("Not enough area %u/%u", encoded_size, _interface.user_area_size());
        return false;
    }

    // Make CC
    if (!cc.valid()) {
        cc.block[0] = (encoded_size > CC4_MAX_NDEF_LENGTH) ? MAGIC_NO_CC8 : MAGIC_NO_CC4;
        cc.major_version(NDEF_MAJOR_VERSION);
        cc.minor_version(NDEF_MINOR_VERSION);
        cc.ndef_size(user_size);
        cc.read_access(ACCESS_FREE);
        cc.write_access(ACCESS_FREE);
        cc.addtional_feature(0);
    }

    // Encode
    uint8_t* buf = static_cast<uint8_t*>(malloc(buf_size));
    if (!buf) {
        M5_LIB_LOGE("Failed to allocate memory %u", buf_size);
        return false;
    }
    memcpy(buf, cc.block, cc.size());

    uint8_t* tlv_buf = buf + cc.size();
    uint32_t offset{};
    uint32_t idx{};
    for (auto&& m : tmp) {
        const auto esz = m.encode(tlv_buf + offset, encoded_size - offset);
        M5_LIB_LOGD("   [%3u] Tag:%02X %u %u", idx, m.tag(), esz, m.required());
        if (!esz) {
            M5_LIB_LOGE("encode failed %u %02X", idx, m.tag());
            goto skip;
        }
        offset += esz;
        ++idx;
    }
    if (offset > encoded_size) {
        M5_LIB_LOGE("Internal error %u/%u", offset, encoded_size);
        goto skip;
    }

    // Write
    ret = _interface.write(_interface.first_user_block(), buf, buf_size);

skip:
    free(buf);
    return ret;
}

/*
  Remove only the NULL, Message, and Terminator TLVs, then add new TLVs
  (Lock, Memory and Proprietary fields are retained)
 */
std::vector<m5::nfc::ndef::TLV> NDEFLayer::merge_tlv(std::vector<m5::nfc::ndef::TLV>& old_tlvs,
                                                     const std::vector<m5::nfc::ndef::TLV>& tlvs)
{
    // Remove Null,Message,and Terminator (Keep Lock,Memory,Proprietary)
    auto it = std::remove_if(old_tlvs.begin(), old_tlvs.end(), [](const TLV& m) {  //
        return m.tag() == Tag::Null || m.tag() == Tag::Message || m.tag() == Tag::Terminator;
    });
    old_tlvs.erase(it, old_tlvs.end());

    // Insert argument before Proprietary TLV
    it = std::find_if(old_tlvs.begin(), old_tlvs.end(), [](const TLV& m) { return m.tag() == Tag::Proprietary; });
    old_tlvs.insert(it, tlvs.begin(), tlvs.end());

    // Append terminator
    if (old_tlvs.empty() || old_tlvs.back().tag() != Tag::Terminator) {
        old_tlvs.push_back(TLV(Tag::Terminator));
    }
    return old_tlvs;
}

}  // namespace ndef
}  // namespace nfc
}  // namespace m5
