/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file ndef_tlv.cpp
  @brief NDEF TLV
*/
#include "ndef_tlv.hpp"
#include <M5Utility.hpp>
#include <numeric>
#include <cinttypes>

namespace {
uint32_t calculate_record_size(const std::vector<m5::nfc::ndef::Record>& v)
{
    return std::accumulate(v.cbegin(), v.cend(), 0U,
                           [](uint32_t acc, const m5::nfc::ndef::Record& r) { return acc + r.required(); });
}

}  // namespace

namespace m5 {
namespace nfc {
namespace ndef {

const TLV TLV::Terminator(Tag::Terminator);

uint32_t TLV::required() const
{
    uint32_t payload_len = (_tag == Tag::Message) ? calculate_record_size(_records) : _payload.size();
    return 1 /* tag */ + ((_tag == Tag::Terminator) ? 0 : ((payload_len >= 0xFF ? 3 : 1) + payload_len));
}

bool TLV::push_back(const Record& r)
{
    if (_tag != Tag::Message) {
        return false;
    }

    if (required() + r.required() > 0xFFFE) {
        return false;
    }
    auto s = _records.size();
    _records.push_back(r);
    if (s == _records.size()) {
        return false;
    }

    if (_records.size() == 1) {
        auto& attr = _records[0].attribute();
        attr.messageBegin(true);
        attr.messageEnd(true);
    } else {
        auto& prev_attr = _records[_records.size() - 2].attribute();
        prev_attr.messageEnd(false);
        auto& attr = _records.back().attribute();
        attr.messageEnd(true);
    }
    return true;
}

void TLV::pop_back()
{
    if (_tag != Tag::Message || _records.empty()) {
        return;
    }

    _records.pop_back();

    const auto n = _records.size();
    if (n == 0) {
        /* Nop */
    } else if (n == 1) {
        // single record → MB=1, ME=1
        auto& attr = _records[0].attribute();
        attr.messageBegin(true);
        attr.messageEnd(true);
    } else {
        // 2 or more records → last ME=1
        auto& attr = _records.back().attribute();
        attr.messageEnd(true);
    }
}

uint32_t TLV::encode(uint8_t* buf, const uint32_t blen) const
{
    if (!buf || !blen) {
        return 0;
    }

    uint32_t count{};
    uint32_t payload_len = (_tag == Tag::Message) ? calculate_record_size(_records) : _payload.size();
    if (payload_len > 0xFFFE) {
        return 0;
    }

    // Tag and payload length
    if (count + 1 > blen) {
        return 0;
    }
    buf[count++] = m5::stl::to_underlying(_tag);  // Tag
    if (isTerminatorTLV()) {
        return count;  // 0xFE only
    }
    // Length (1 byte or 3 bytes)
    if (payload_len >= 0XFF) {
        if (count + 3 > blen) {
            return 0;
        }
        buf[count++] = 0xFF;  // tag for 3 bytes format
        buf[count++] = (payload_len >> 8) & 0xFF;
        buf[count++] = payload_len & 0xFF;
    } else {
        if (count + 1 > blen) {
            return 0;
        }
        buf[count++] = payload_len;  // 0x00 - 0xFE
    }

    if (_tag == Tag::Message) {  // Message
        for (auto&& r : _records) {
            if (count >= blen) {
                return 0;
            }
            const uint32_t remain = blen - count;
            const uint32_t rec    = r.encode(&buf[count], remain);
            if (!rec || count + rec > blen) {
                return 0;
            }
            count += rec;
        }
    } else {  // Others
        if (count + payload_len > blen) {
            return 0;
        }
        std::memcpy(&buf[count], _payload.data(), payload_len);
        count += payload_len;
    }
    return count;
}

uint32_t TLV::decode(const uint8_t* buf, const uint32_t len)
{
    clear();

    uint32_t decoded{};
    uint16_t payload_len{};
    const auto top = buf;

    if (!buf || !len) {
        return 0;
    }

    // Tag
    uint8_t t = *buf++;
    _tag      = static_cast<Tag>(t);

    if (is_terminator_tag(t)) {
        return 1;
    }

    if (len < 3) {
        return 0;
    }

    if (!is_valid_tag(t)) {
        M5_LIB_LOGE("Invalid tag %02X", t);
        return 0;
    }

    // Payload length
    uint8_t pl = *buf++;
    if (pl == 0xFF) {  // 3 bytes format?
        if (len < 5) {
            return 0;
        }
        payload_len = ((uint16_t)*buf << 8);
        ++buf;
        payload_len |= *buf;
        ++buf;
    } else {
        payload_len = pl;
    }
    decoded = buf - top;

    if (payload_len == 0) {
        return decoded;
    }

    // Message
    if (_tag == Tag::Message) {
        const uint8_t* payload_end = top + decoded + payload_len;
        while (buf < payload_end) {
            Record r{};
            uint32_t rlen = len - (buf - top);
            auto rec      = r.decode(buf, rlen);
            if (!rec) {
                M5_LIB_LOGE("Record decode error");
                return 0;
            }
            decoded += rec;

            if (_records.empty()) {
                if (!r.attribute().messageBegin()) {
                    M5_LIB_LOGE("First record is not MB");
                    return 0;
                }
            } else {
                if (r.attribute().messageBegin()) {
                    M5_LIB_LOGE("Invalid MB");
                    return 0;
                }
            }

            _records.push_back(r);

            buf += rec;

            // ME detected, subsequent data will be ignored
            if (r.attribute().messageEnd()) {
                break;
            }
        }
        if (!_records.empty() && !_records.back().attribute().messageEnd()) {
            M5_LIB_LOGE("Last record is not ME");
            return false;
        }
        // Verify
        return required() == decoded ? decoded : 0;
    }

    // Other
    if (payload_len > len - (buf - top)) {
        return 0;
    }
    _payload.insert(_payload.end(), buf, buf + payload_len);
    buf += payload_len;
    return buf - top;
}

uint32_t TLV::decode_t3t(const uint8_t* buf, const uint32_t len)
{
    clear();

    uint32_t decoded{};
    uint16_t payload_len{};
    const auto top = buf;

    if (!buf || !len || len < 16) {
        return 0;
    }

    // Attribute block (16 byte)
    AttributeBlock ab{};
    memcpy(ab.block, buf, 16);

    M5_LIB_LOGE("AB:%02X %u/%u/%u %02X/%02X %u %04X/%04X", ab.version(), ab.max_block_to_read(),
                ab.max_block_to_write(), ab.blocks_for_ndef_storage(), ab.write_flag(), ab.access_flag(),
                ab.current_ndef_message_length(), ab.check_sum(), ab.calculate_check_sum());

    //    _tag = Tag::Message;
    return false;
}

void TLV::clear()
{
    _tag = Tag::Null;
    _records.clear();
    _payload.clear();
}

void TLV::dump()
{
    uint32_t payload_len = (_tag == Tag::Message) ? calculate_record_size(_records) : _payload.size();
    printf("== NDEF Mesage Tag:%02X Payload:%" PRIu32 "\n", m5::stl::to_underlying(_tag),
           payload_len);  // PRIu32 for compile on NanoC6

    if (_tag == Tag::Message) {
        for (auto&& r : _records) {
            r.dump();
        }
        return;
    }

    if (_payload.empty()) {
        return;
    }

    puts(
        "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
        "-----------------------------------------------");

    auto p        = _payload.data();
    uint32_t plen = _payload.size();
    if (p) {
        char line[128] = "";
        uint32_t idx{};
        while (idx < plen) {
            uint32_t left{};
            for (int_fast8_t i = 0; idx < plen && i < 16; ++i, ++idx) {
                left += snprintf(line + left, 4, "%02X ", *p++);
            }
            puts(line);
        }
    }
}

}  // namespace ndef
}  // namespace nfc
}  // namespace m5
