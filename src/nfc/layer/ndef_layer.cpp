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

bool NDEFLayer::read(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::TagBits tagBits)
{
    tlvs.clear();

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
    }

skip:
    free(buf);
    return true;
}

bool NDEFLayer::write(const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep)
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
    if (keep && read(tmp)) {
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
