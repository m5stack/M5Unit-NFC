/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file ndef_record.cpp
  @brief NDEF record
*/
#include "ndef_record.hpp"
#include "ndef_message.hpp"
#include <M5Utility.hpp>
#include <algorithm>
#include <cstring>

namespace {

const char* find_first_mismatch(const char* s1, const char* s2)
{
    if (!s1 || !s2) {
        return nullptr;
    }
    while (*s1 && *s2) {
        if (*s1 != *s2) {
            return s1;
        }
        ++s1;
        ++s2;
    }
    if (*s1 != *s2) {
        return s1;
    }
    return nullptr;
}

}  // namespace

namespace m5 {
namespace nfc {
namespace ndef {

uint32_t Record::required() const
{
    return 1 +                                // Attribute
           1 +                                // Type length
           (_payload.size() < 256 ? 1 : 4) +  // Payload length
           (_attr.idLength() ? 1 : 0) +       // ID length
           _type.size() +                     // Type
           _id.size() +                       // ID
           _payload.size();                   // Payload

    // (_id.empty() ? 0 : 1) +            // ID length
}

bool Record::setTextPayload(const char* str, const char* lang)
{
    if (tnf() == TNF::Wellknown) {
        _type = "T";  // Text
        _payload.clear();
        set_text_payload(str, lang);
        return true;
    }
    M5_LIB_LOGE("Record is not Wellknown");
    return false;
}

bool Record::setURIPayload(const char* uri, URIProtocol protocol)
{
    if (tnf() == TNF::Wellknown) {
        _type = "U";  // URI
        _payload.clear();
        set_uri_payload(uri, protocol);
        return true;
    }
    M5_LIB_LOGE("Record is not Wellknown");
    return false;
}

uint32_t Record::encode(uint8_t* buf, const uint32_t mlen) const
{
    uint32_t count{};
    uint8_t tlen = _type.length();

    if (!buf || mlen < 3 || !tlen || _payload.empty()) {
        return 0;
    }

    // Attribute, type length
    buf[count++] = _attr.value;
    buf[count++] = tlen;

    // Payload length
    if (_attr.shortRecord()) {  // 1 byte
        if (_payload.size() >= 256) {
            M5_LIB_LOGE("Illegal payload size %zu", _payload.size());
            return 0;
        }
        buf[count++] = _payload.size();
    } else {  // 4 bytes
        if (mlen < 6) {
            return 0;
        }
        uint32_t plen = _payload.size();
        buf[count++]  = (plen >> 24) & 0xFF;
        buf[count++]  = (plen >> 16) & 0xFF;
        buf[count++]  = (plen >> 8) & 0xFF;
        buf[count++]  = (plen >> 0) & 0xFF;
    }

    // ID length (Not exists if id length is 0)
    if (_attr.idLength()) {
        if (count >= mlen) {
            return 0;
        }
        buf[count++] = _id.size();
    }

    // Type
    if (count + tlen > mlen) {
        return 0;
    }
    auto tp = _type.data();
    if (tp) {
        std::memcpy(&buf[count], tp, tlen);
        count += tlen;
    }

    // ID ((Not exists if id length is 0)
    if (_attr.idLength()) {
        if (count + _id.size() > mlen) {
            return 0;
        }
        std::memcpy(&buf[count], _id.data(), _id.size());
        count += _id.size();
    }
    // Payload
    if (count + _payload.size() > mlen) {
        return 0;
    }
    std::memcpy(&buf[count], _payload.data(), _payload.size());
    count += _payload.size();

    return count;
}

uint32_t Record::decode(const uint8_t* buf, const uint32_t len)
{
    uint8_t type_len{};
    uint8_t id_len{};
    uint32_t payload_len{};
    const auto top = buf;

    clear();

    if (!buf || !len) {
        return 0;
    }
    if (len < 3) {
        return 0;
    }

    _attr.value = *buf++;
    type_len    = *buf++;
    if (_attr.shortRecord()) {
        payload_len = *buf++;
    } else {
        if (len < 6) {
            return 0;
        }
        payload_len |= ((uint32_t)*buf) << 24;
        ++buf;
        payload_len |= ((uint32_t)*buf) << 16;
        ++buf;
        payload_len |= ((uint32_t)*buf) << 8;
        ++buf;
        payload_len |= ((uint32_t)*buf);
        ++buf;
    }

    if (_attr.idLength()) {
        if (buf + 1 - top > len) {
            return 0;
        }
        id_len = *buf++;
    }

    if (type_len) {
        if (buf + type_len - top > len) {
            return 0;
        }
        _type = std::string(buf, buf + type_len);
        buf += type_len;
    }

    if (id_len) {
        if (buf + id_len - top > len) {
            return 0;
        }
        _id = std::vector<uint8_t>(buf, buf + id_len);
        buf += id_len;
    }

    if (payload_len) {
        if (buf + payload_len - top > len) {
            return 0;
        }
        _payload = std::vector<uint8_t>(buf, buf + payload_len);
        buf += payload_len;
    }

    auto decoded = buf - top;
    // verify
    return (required() == decoded) ? decoded : 0;
}

std::string Record::payloadAsString() const
{
    const char* cptr    = (const char*)_payload.data();
    const uint8_t* uptr = _payload.data();
    uint32_t len        = _payload.size();

    if (!uptr || !len) {
        return std::string();
    }

    switch (tnf()) {
        case TNF::Wellknown:
            if (_type == "T") {  // Text
                auto offset = (*uptr & 0x3F) + 1;
                cptr += offset;
                len -= offset;
            } else if (_type == "U") {  // URI
                char tmp[512]{};
                URIProtocol up = static_cast<URIProtocol>(*uptr);
                std::string s(cptr + 1, cptr + _payload.size());
                len      = snprintf(tmp, sizeof(tmp), "%s%s", get_uri_idc_string(up), s.c_str());
                tmp[len] = '\0';
                cptr     = tmp;
            }
            break;
        default:
            return std::string(type());
    }
    return std::string(cptr, cptr + len);
}

void Record::set_text_payload(const char* str, const char* lang)
{
    auto lang_len = strlen(lang);

    if (!str || !lang || lang_len >= 64) {
        M5_LIB_LOGE("Invalid arguments");
        return;
    }

    uint8_t status = 0x00 | lang_len;  // [7] 0:UTF-8 1:UTF-16, [6] RFU, [5..0] Length of the IANA langage code

    _payload.push_back(status);
    const uint8_t* lp = (const uint8_t*)lang;
    _payload.insert(_payload.end(), lp, lp + lang_len);
    const uint8_t* sp = (const uint8_t*)str;
    _payload.insert(_payload.end(), sp, sp + strlen(str));

    _attr.shortRecord(_payload.size() < 256);
}

void Record::set_uri_payload(const char* uri, URIProtocol protocol)
{
    auto len = strlen(uri);

    auto diff = find_first_mismatch(uri, get_uri_idc_string(protocol));
    _payload.push_back(m5::stl::to_underlying(protocol));
    if (diff) {
        len = strlen(diff);
        _payload.insert(_payload.end(), diff, diff + len);
    }

    _attr.shortRecord(_payload.size() < 256);
}

void Record::clear()
{
    _attr.value &= ~0x07;
    _type.clear();
    _payload.clear();
    _id.clear();
}

void Record::dump() const
{
    auto tlen = _type.length();

    puts("|MB|ME|CF|SR|IL|TNF|");
    printf("|%02u|%02u|%02u|%02u|%02u|%03u|\n", _attr.messageBegin(), _attr.messageEnd(), _attr.chunk(),
           _attr.shortRecord(), _attr.idLength(), m5::stl::to_underlying(_attr.tnf()));
    printf("|   Type length %3zu|\n", tlen);
    printf("|Payload length %3zu|\n", _payload.size());
    if (!_id.empty()) {
        printf("|     ID length %3zu|\n", _id.size());
    }
    puts(
        "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
        "-----------------------------------------------");

    auto p = _type.data();
    if (p) {
        char line[128] = "";
        uint32_t idx{};
        while (idx < tlen) {
            uint32_t left{};
            for (int_fast8_t i = 0; idx < tlen && i < 16; ++i, ++idx) {
                left += snprintf(line + left, 4, "%02X ", *p++);
            }
            puts(line);
        }
    }

    if (!_id.empty()) {
        auto p         = _id.data();
        char line[128] = "";
        uint32_t idx{};
        while (idx < _id.size()) {
            uint32_t left{};
            for (int_fast8_t i = 0; idx < _id.size() && i < 16; ++i, ++idx) {
                left += snprintf(line + left, 4, "%02X ", *p++);
            }
            puts(line);
        }
    }

    if (!_payload.empty()) {
        auto p         = _payload.data();
        char line[128] = "";
        uint32_t idx{};
        while (idx < _payload.size()) {
            uint32_t left{};
            for (int_fast8_t i = 0; idx < _payload.size() && i < 16; ++i, ++idx) {
                left += snprintf(line + left, 4, "%02X ", *p++);
            }
            puts(line);
        }
    }
}

}  // namespace ndef
}  // namespace nfc
}  // namespace m5
