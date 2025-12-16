/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file apdu.cpp
  @brief Application Protocol Data Unit (ISO/IEC 7816-4)
*/
#include "apdu.hpp"
#include <M5Utility.hpp>

namespace {

}

namespace m5 {
namespace nfc {
namespace apdu {

std::vector<uint8_t> make_apdu_command(const uint8_t cla, const INS ins, const uint8_t param1, const uint8_t param2,
                                       const uint8_t* data, const uint16_t data_len, const uint16_t rx_len)
{
    if (data_len != 0 && data == nullptr) {
        return {};
    }

    const uint8_t lc_len = (data_len == 0) ? 0 : ((data_len > 255) ? 3 : 1);
    const uint8_t le_len = (rx_len == 0) ? 0 : ((rx_len > 256) ? 3 : 1);

    std::vector<uint8_t> cmd{};
    cmd.resize(4 + lc_len + data_len + le_len);

    uint32_t offset{};

    // ---- Header
    cmd[offset++] = cla;
    cmd[offset++] = m5::stl::to_underlying(ins);
    cmd[offset++] = param1;
    cmd[offset++] = param2;

    // ---- Body
    // Lc
    if (lc_len == 3) {
        cmd[offset++] = 0x00;
        cmd[offset++] = static_cast<uint8_t>((data_len >> 8) & 0xFF);
        cmd[offset++] = static_cast<uint8_t>(data_len & 0xFF);
    } else if (lc_len == 1) {
        cmd[offset++] = static_cast<uint8_t>(data_len & 0xFF);
    }
    // Data
    if (data_len) {
        std::memcpy(cmd.data() + offset, data, data_len);
        offset += data_len;
    }
    // Le
    if (le_len == 3) {
        cmd[offset++] = 0x00;
        cmd[offset++] = static_cast<uint8_t>((rx_len >> 8) & 0xFF);
        cmd[offset++] = static_cast<uint8_t>(rx_len & 0xFF);
    } else if (le_len == 1) {
        cmd[offset++] = static_cast<uint8_t>(rx_len & 0xFF);  // 0x100 -> 0x00 means 256 bytes
    }

    return cmd;
}

std::vector<TLV> parse_tlv(const uint8_t* ptr, const uint32_t len)
{
    std::vector<TLV> out{};
    if (!ptr || len == 0) {
        return out;
    }

    uint32_t off{};

    while (off < len) {
        TLV tlv{};

        // T
        if (off >= len) break;

        uint32_t tag{};
        uint8_t tag_len{};

        uint8_t b = ptr[off];
        tag       = b;
        tag_len   = 1;

        // Extended tag (0x1F)
        if ((b & 0x1F) == 0x1F) {
            // up to 3 bytes total
            while (tag_len < 3) {
                if (off + tag_len >= len) {
                    return {};  // malformed
                }
                uint8_t tb = ptr[off + tag_len];
                tag        = (tag << 8) | tb;
                tag_len++;

                // last tag byte?
                if ((tb & 0x80) == 0) {
                    break;
                }
            }
            // still continuation -> unsupported
            if ((tag & 0x80) != 0 && tag_len == 3) {
                return {};
            }
        }

        off += tag_len;

        // L
        if (off >= len) {
            return {};
        }

        uint32_t vlen{};
        uint8_t len_len{};

        uint8_t lb = ptr[off];
        if ((lb & 0x80) == 0) {
            // short form
            vlen    = lb;
            len_len = 1;
        } else {
            // long form
            uint8_t cnt = lb & 0x7F;
            if (cnt == 0 || cnt > 2) {
                // indefinite or too large not supported
                return {};
            }
            if (off + 1 + cnt > len) {
                return {};
            }
            vlen = 0;
            for (uint8_t i = 0; i < cnt; ++i) {
                vlen = (vlen << 8) | ptr[off + 1 + i];
            }
            len_len = 1 + cnt;
        }

        off += len_len;

        // V
        if (off + vlen > len) {
            return {};
        }

        tlv.tag     = tag;
        tlv.tag_len = tag_len;
        tlv.len     = vlen;
        tlv.v       = ptr + off;

        out.emplace_back(tlv);
        off += vlen;
    }

    return out;
}

void dump_tlv(const std::vector<TLV>& tlvs, const uint8_t depth)
{
    if (depth == 0) {
        printf("==== TLV %zu ====\n", tlvs.size());
    }
    for (auto&& t : tlvs) {
        printf("%*s", depth * 2, "");
        printf("TLV:%2X %u %p\n", t.tag, t.len, t.v);
        if (t.is_constructed()) {
            dump_tlv(parse_tlv(t.v, t.len), depth + 1);
        }
    }
}

}  // namespace apdu
}  // namespace nfc
}  // namespace m5
