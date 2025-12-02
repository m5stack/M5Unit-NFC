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
#include "nfc/a/nfca.hpp"
#include "nfc/b/nfcb.hpp"
#include "nfc/f/nfcf.hpp"
#include "nfc/v/nfcv.hpp"
#include "nfc/ndef/ndef.hpp"
#include "nfc/ndef/ndef_tlv.hpp"
#include "nfc/ndef/ndef_record.hpp"
#include <M5Utility.hpp>
#include <algorithm>
#include <numeric>

using namespace m5::nfc::a;
using namespace m5::nfc::b;
using namespace m5::nfc::f;
using namespace m5::nfc::v;
using namespace m5::nfc::ndef;

namespace m5 {
namespace nfc {
namespace ndef {

bool NDEFLayer::isValidFormat(bool& valid)
{
    valid = false;

    uint8_t rbuf[16]{};
    uint16_t rlen{16};
    auto block = _interface.firstUserBlock();
    if (block == 0xFFFF) {
        return false;
    }

    if (!_interface.read(rbuf, rlen, block)) {
        M5_LIB_LOGE("Failed to read %u", block);
        return false;
    }
    valid = is_valid_tag(rbuf[0]);
    return true;
}

bool NDEFLayer::read(const m5::nfc::NFCForumTag ftag, std::vector<m5::nfc::ndef::TLV>& tlvs,
                     const m5::nfc::ndef::TagBits tagBits)
{
    tlvs.clear();

    switch (ftag) {
        case NFCForumTag::Type1:
        case NFCForumTag::Type2:
        case NFCForumTag::Type5:
            return read_with_tlv(tlvs, tagBits);
        case NFCForumTag::Type3:
        case NFCForumTag::Type4: {
            tlvs.clear();
            TLV tlv{};
            if (read_without_tlv(tlv)) {
                tlvs.emplace_back(tlv);
                return true;
            }
        } break;
        default:
            break;
    }
    return false;
}

bool NDEFLayer::write(const m5::nfc::NFCForumTag ftag, const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep)
{
    if (!tlvs.empty()) {
        switch (ftag) {
            case NFCForumTag::Type1:
            case NFCForumTag::Type2:
            case NFCForumTag::Type5:
                return write_with_tlv(tlvs, keep);
            case NFCForumTag::Type3:
            case NFCForumTag::Type4:
                return write_without_tlv(tlvs.front());
            default:
                break;
        }
    }
    return false;
}

//
bool NDEFLayer::read_with_tlv(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::TagBits tagBits)
{
    bool ret{};
    uint8_t* buf{};
    uint16_t block      = _interface.firstUserBlock();
    uint16_t last_block = _interface.lastUserBlock();
    if (block == 0xFFFF || last_block == 0xFFFF) {
        return false;
    }

    uint16_t buf_size = (last_block - block + 1) * _interface.userBlockUnitSize();
    ;
    buf = static_cast<uint8_t*>(malloc(buf_size));
    if (!buf) {
        M5_LIB_LOGE("Failed to allocate memory %u", buf_size);
        return false;
    }
    uint16_t actual{buf_size};
    if (!_interface.read(buf, actual, block) || actual == 0) {
        M5_LIB_LOGE("Failed to read %u", actual);
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

bool NDEFLayer::write_with_tlv(const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep)
{
    bool ret{};
    const uint32_t user_bytes =
        (_interface.lastUserBlock() - _interface.firstUserBlock() + 1) * _interface.userBlockUnitSize();

    if (tlvs.empty()) {
        return false;
    }

    std::vector<TLV> tmp{};

    /*
      Since there is an NTAG containing information such as LockControl starting
      from the beginning of the user area, skip it and write
     */
    if (keep && read_with_tlv(tmp, tagBitsAll)) {
        // Remove Null,NDEF,and Terminator (Keep Lock,Memory,Proprietary)
        auto it = std::remove_if(tmp.begin(), tmp.end(), [](const TLV& m) {  //
            return m.tag() == Tag::Null || m.tag() == Tag::Message || m.tag() == Tag::Terminator;
        });
        tmp.erase(it, tmp.end());

        // Insert argument before Proprietary TLV
        it = std::find_if(tmp.begin(), tmp.end(), [](const TLV& m) { return m.tag() == Tag::Proprietary; });
        tmp.insert(it, tlvs.begin(), tlvs.end());

        // Append terminator
        if (tmp.empty() || tmp.back().tag() != Tag::Terminator) {
            tmp.push_back(TLV(Tag::Terminator));
        }
    } else {
        // Overwirte if the TLV is not maintained, or if there is a corrupted NDEF
        tmp = tlvs;
    }

    // Calculate encoded size
    uint32_t encoded_size =
        std::accumulate(tmp.begin(), tmp.end(), 0U, [](uint32_t acc, const TLV& m) { return acc + m.required(); });

    M5_LIB_LOGD("Encoded size:%u", encoded_size);

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
    if (offset != encoded_size) {
        M5_LIB_LOGE("Internal error %u/%u", offset, encoded_size);
        goto skip;
    }
    if (encoded_size > user_bytes) {
        M5_LIB_LOGE("Not enough user area %u/%u", encoded_size, user_bytes);
        goto skip;
    }

    // Write
    // M5_LIB_LOGE(">>>>ndef write %u %u", _interface.firstUserBlock(), encoded_size);
    ret = _interface.write(_interface.firstUserBlock(), buf, encoded_size);

skip:
    free(buf);
    return ret;
}

bool NDEFLayer::read_without_tlv(m5::nfc::ndef::TLV& tlv)
{
    tlv = TLV{};

    TLV tmp{Tag::Message};
    bool ret{};
    uint16_t block      = _interface.firstUserBlock();
    uint16_t last_block = _interface.lastUserBlock();
    if (block == 0xFFFF || last_block == 0xFFFF) {
        M5_LIB_LOGE("ERROR");
        return false;
    }

    // Attribute block
    AttributeBlock ab{};
    uint16_t actual{16};
    if (!_interface.read(ab.block, actual, block) || actual != 16 || ab.check_sum() != ab.calculate_check_sum()) {
        M5_LIB_LOGE("Failed to read AB actual:%u sum:%04X/%04X", actual, ab.check_sum(), ab.calculate_check_sum());
        return false;
    }

    M5_LIB_LOGE("AB:%02X %u/%u/%u %02X/%02X %u %04X/%04X", ab.version(), ab.max_block_to_read(),
                ab.max_block_to_write(), ab.blocks_for_ndef_storage(), ab.write_flag(), ab.access_flag(),
                ab.current_ndef_message_length(), ab.check_sum(), ab.calculate_check_sum());

    if (!ab.valid()) {
        return false;
    }

    // NDEF Records
    uint16_t buf_size = ((ab.current_ndef_message_length() + 15) >> 4) << 4;
    uint8_t* buf{};

    if (buf_size) {
        buf = static_cast<uint8_t*>(malloc(buf_size));

        if (!buf) {
            M5_LIB_LOGE("Failed to allocate memory %u", buf_size);
            return false;
        }
        actual = buf_size;
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

bool NDEFLayer::write_without_tlv(const m5::nfc::ndef::TLV& tlv)
{
    bool ret{};

    if (!tlv.isMessageTLV()) {
        return false;
    }

    uint16_t first_block = _interface.firstUserBlock();
    uint16_t last_block  = _interface.lastUserBlock();
    if (first_block == 0xFFFF || last_block == 0xFFFF) {
        return false;
    }

    uint16_t user_area_size = (last_block - first_block + 1) * _interface.userBlockUnitSize();
    uint32_t record_size    = std::accumulate(tlv.records().begin(), tlv.records().end(), 0U,
                                              [](uint32_t acc, const Record& r) { return acc + r.required(); });
    if (record_size + 16 > user_area_size) {
        M5_LIB_LOGE("Not enough user area %u/%u", record_size + 16, user_area_size);
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
        AttributeBlock ab{};
        ab.max_block_to_read(_interface.maximumReadBlocks());
        ab.max_block_to_write(_interface.maximumWriteBlocks());
        ab.blocks_for_ndef_storage(last_block - first_block + 1 - 1 /* AB */);
        ab.write_flag(AttributeBlock::WriteFlag::InProgress);  // protect
        ab.access_flag(AttributeBlock::AccessFlag::ReadWrite);
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

#if 0
bool NDEFLayer::readTLVSize(uint32_t& size, const TagBits tagBits)
{
    size = 0;

    uint8_t* buf{};
    uint16_t block      = _interface.firstUserBlock();
    uint16_t last_block = _interface.lastUserBlock();
    if (block == 0xFFFF || last_block == 0xFFFF) {
        return false;
    }

    bool ret{false};
    uint16_t buf_size = (last_block - block + 1) * _interface.userBlockUnitSize();
    buf               = static_cast<uint8_t*>(malloc(buf_size));
    if (!buf) {
        M5_LIB_LOGE("Failed to allocate memory");
        return false;
    }
    uint16_t actual{buf_size};
    if (!_interface.read(buf, actual, block) || actual == 0) {
        M5_LIB_LOGE("Failed to read %u", actual);
        goto skip;
    }

    {
        ret = calculate_ndef_size(size, buf, buf + actual, tagBits);
        if (ret) {
            M5_LIB_LOGE("NDEF SIZE:%u", size);
        }
    }
skip:
    free(buf);
    return ret;
}

bool calculate_ndef_size(uint32_t& size, const uint8_t* p, const uint8_t* end, const TagBits tagBits)
{
    size = 0;
    uint32_t required{};

    while (p < end) {
        uint32_t msize{};
        Tag t = static_cast<Tag>(*p);

        M5_LIB_LOGD(" Tag[%02X] %u", t, contains_tag(tagBits, t));

        if (!is_valid_tag(*p)) {
            break;
        }

        // Terminator?
        if (is_terminator_tag(*p++)) {
            ++required;
            break;
        }

        if (p >= end) {
            M5_LIB_LOGE("No room for length field");
            return false;
        }
        ++msize;

        // Any message
        uint16_t payload_len = *p++;
        if (payload_len == 0xFF) {  // 3 bytes format
            if (end - p < 2) {
                M5_LIB_LOGE("No room for extended length field");
                return false;
            }
            payload_len = ((uint16_t)*p++) << 8;
            payload_len |= ((uint16_t)*p++);
        }

        if (end - p < payload_len) {
            M5_LIB_LOGE("Payload length overrun: %u > %u", payload_len, end - p);
            return false;
        }

        p += payload_len;
        msize += payload_len;
        M5_LIB_LOGD("  PL:%u", payload_len);
        required += contains_tag(tagBits, t) ? msize : 0;
    }
    size = required;
    return true;
}
#endif

}  // namespace ndef
}  // namespace nfc
}  // namespace m5
