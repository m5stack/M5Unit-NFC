/*
 * SPDX-FileCopyrightText: 2024 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file ndef_message.cpp
  @brief NDEF message
*/
#include "ndef_message.hpp"
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

const Message Message::Terminator(Tag::Terminator);

uint32_t Message::required(const bool include_terminator) const
{
    uint32_t payload_len = (_tag == Tag::NDEFMessage) ? calculate_record_size(_records) : _payload.size();
    return 1 /* tag */ + (payload_len >= 0xFF ? 3 : 1) + payload_len + (include_terminator ? 1 : 0);
}

bool Message::push_back(const Record& r)
{
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

uint32_t Message::encode(uint8_t* buf, const uint32_t blen, const bool include_terminator) const
{
    uint32_t count{};

    uint32_t payload_len = (_tag == Tag::NDEFMessage) ? calculate_record_size(_records) : _payload.size();
    if (payload_len > 0xFFFE) {
        return 0;
    }

    // Tag and payload length
    buf[count++] = m5::stl::to_underlying(_tag);  // Tag
    if (isTerminator()) {
        return 1;  // 0xFE only
    }
    // Length (1 byte or 3 bytes)
    if (payload_len >= 0XFF) {
        buf[count++] = 0xFF;  // tag for 3 bytes format
        buf[count++] = (payload_len >> 8) & 0xFF;
        buf[count++] = payload_len & 0xFF;
    } else {
        buf[count++] = payload_len;  // 0x00 - 0xFE
    }

    if (_tag == Tag::NDEFMessage) {  // NDEFMessage
        for (auto&& r : _records) {
            auto rec = r.encode(&buf[count], blen - count);
            if (!rec) {
                return 0;
            }
            count += rec;
        }
    } else {  // Others

        if (blen - count < payload_len) {
            return 0;
        }
        std::memcpy(&buf[count], _payload.data(), blen - count);
        count += blen - count;
    }

    if (include_terminator) {
        buf[count++] = 0xFE;
    }
    return count;
}

uint32_t Message::decode(const uint8_t* buf, const uint32_t len)
{
    if (len < 3) {
        return 0;
    }

    clear();

    uint32_t decoded{};
    uint16_t payload_len{};
    const auto top = buf;

    if (len < 3) {
        return 0;
    }

    // Tag
    uint8_t t = *buf++;
    _tag      = static_cast<Tag>(t);

    if (is_terminator_tag(t)) {
        return 1;
    }

    if (!is_valid_tag(t)) {
        M5_LIB_LOGE("Invalid tag");
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

    // NDEFMessage
    if (_tag == Tag::NDEFMessage) {
        while (buf - top < len) {
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
        return required(false) == decoded ? decoded : 0;
    }

    // Other
    if (payload_len > len - (buf - top)) {
        return 0;
    }
    _payload.insert(_payload.end(), buf, buf + payload_len);
    buf += payload_len;
    return buf - top;
}

void Message::clear()
{
    _tag = Tag::Null;
    _records.clear();
    _payload.clear();
}

void Message::dump()
{
    uint32_t payload_len = (_tag == Tag::NDEFMessage) ? calculate_record_size(_records) : _payload.size();
    printf("== NDEF Mesage Tag:%02X Payload:%" PRIu32 "\n", m5::stl::to_underlying(_tag),
           payload_len);  // PRIu32 for compile on NanoC6

    if (_tag == Tag::NDEFMessage) {
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
