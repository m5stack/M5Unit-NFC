/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfcv.hpp
  @brief NFC-V definitions
*/
#include "nfcv.hpp"
#include "nfc/manufacturer_id.hpp"
#include <M5Utility.hpp>

using namespace m5::nfc;
using namespace m5::nfc::v;

namespace {

constexpr char name_unknown[]         = "Unknown";
constexpr char name_nxp_icode_sli[]   = "ICODE SLI";
constexpr char name_nxp_icode_slix[]  = "ICODE SLIX";
constexpr char name_nxp_icode_slix2[] = "ICODE SLIX2";
constexpr char name_nxp[]             = "NXP(Unclassified)";
constexpr char name_tagit_2048[]      = "Tag-it 2048";
constexpr char name_tagit_hf_i[]      = "Tag-it HF-I";
constexpr char name_tagit_hf_i_plus[] = "Tag-it HF-I Plus";
constexpr char name_tagit_hf_i_pro[]  = "Tag-it HF-I Pro";
constexpr char name_ti[]              = "TI(Unclassified)";
constexpr char name_st_lri[]          = "ST LRI";
constexpr char name_st_st25v[]        = "ST25V";
constexpr char name_st_st25dv[]       = "ST25DV";
constexpr char name_st[]              = "ST(Unclassified)";
constexpr char name_fram[]            = "FRAM";
constexpr char name_fujitsu[]         = "Fujitsu(Unclassified)";
constexpr char name_unclassified[]    = "Unclassified";

constexpr const char* name_table[] = {
    name_unknown,
    // NXP
    name_nxp_icode_sli,
    name_nxp_icode_slix,
    name_nxp_icode_slix2,
    name_nxp,
    // TI
    name_tagit_2048,
    name_tagit_hf_i,
    name_tagit_hf_i_plus,
    name_tagit_hf_i_pro,
    name_ti,
    // ST
    name_st_lri,
    name_st_st25v,
    name_st_st25dv,
    name_st,
    // Others
    name_fram,
    name_fujitsu,
    //
    name_unclassified,
};

constexpr uint8_t FLAG_TWO_SUBCARRIERS{0x01};
constexpr uint8_t FLAG_HIGH_DATARATE{0x02};
constexpr uint8_t SOF_1OF4{0x21};
constexpr uint8_t EOF_COMMON{0x04};
constexpr uint8_t SOF_1OF256{0x81};
constexpr uint8_t DAT_00_1OF4{0x02};
constexpr uint8_t DAT_01_1OF4{0x08};
constexpr uint8_t DAT_10_1OF4{0x20};
constexpr uint8_t DAT_11_1OF4{0x80};
constexpr uint8_t DAT_SLOT0_1OF256{0x02};
constexpr uint8_t DAT_SLOT1_1OF256{0x08};
constexpr uint8_t DAT_SLOT2_1OF256{0x20};
constexpr uint8_t DAT_SLOT3_1OF256{0x80};

using encode_function = void (*)(std::vector<uint8_t>&, const uint8_t);

void encode_byte_1of4(std::vector<uint8_t>& out, const uint8_t data)
{
    uint8_t tmp = data;
    for (int i = 0; i < 4; ++i) {
        uint8_t twoBits = static_cast<uint8_t>(tmp & 0x03u);
        uint8_t sym{};
        switch (twoBits) {
            case 0:
                sym = DAT_00_1OF4;
                break;
            case 1:
                sym = DAT_01_1OF4;
                break;
            case 2:
                sym = DAT_10_1OF4;
                break;
            case 3:
                sym = DAT_11_1OF4;
                break;
            default:
                break;
        }
        out.push_back(sym);
        tmp >>= 2;
    }
}

void encode_byte_1of256(std::vector<uint8_t>& out, const uint8_t data)
{
    uint8_t tmp = data;
    for (int i = 0; i < 64; ++i) {
        uint8_t sym{};
        switch (tmp) {
            case 0:
                sym = DAT_SLOT0_1OF256;
                break;
            case 1:
                sym = DAT_SLOT1_1OF256;
                break;
            case 2:
                sym = DAT_SLOT2_1OF256;
                break;
            case 3:
                sym = DAT_SLOT3_1OF256;
                break;
            default:
                break;
        }
        out.push_back(sym);
        tmp -= 4;
    }
}

}  // namespace

namespace m5 {
namespace nfc {
namespace v {

Type identify_type(const PICC& picc)
{
    const uint8_t mf = picc.manufacturerCode();
    const uint8_t ic = picc.icIdentifier();
    const uint8_t ir = picc.icReference();

    // mf -> See also https://en.wikipedia.org/wiki/ISO/IEC_15693
    if (mf == 0xFF || ic == 0xFF) {
        return Type::Unknown;
    }

    // M5_LIB_LOGE("mf:%02X ic:%02X ir:%02X", mf, ic, ir);

    // NXP
    if (mf == m5::stl::to_underlying(m5::nfc::ManufacturerId::NXP)) {
        if (ic == 0x01) {
            uint8_t type_indicator_bits = (picc.uid[3] >> 3) & 0x03;
            switch (type_indicator_bits) {
                case 0:
                    return Type::NXP_ICODE_SLI;
                case 2:
                    return Type::NXP_ICODE_SLIX;
                case 1:
                    return Type::NXP_ICODE_SLIX_2;
                default:
                    break;
            }
        }
        return Type::Unclassified;
    }

    // TI
    if (mf == m5::stl::to_underlying(m5::nfc::ManufacturerId::TexasInstruments)) {
        if (ic == 0x80) {
            return Type::TI_TAGIT_2048;
        }
        if (ic == 0x00 || ic == 0x01 || ic == 0x81) {
            return Type::TI_TAGIT_HF_I_Plus;
        }
        if (ic == 0xC0 || ic == 0xC1) {
            return Type::TI_TAGIT_HF_I;
        }
        if (ic == 0xC4 || ic == 0xC5) {
            return Type::TI_TAGIT_HF_I_Pro;
        }
        return Type::TI;
    }

    // STMicroelectronics
    if (mf == m5::stl::to_underlying(m5::nfc::ManufacturerId::STMicroelectronics)) {
        switch (ir) {
            case 0x23:
                return Type::ST_ST25V;
            case 0x24:
                // [fallthrough]
            case 0x26:
                return Type::ST_ST25DV;  // ST25DV 04K/16K/64K
            case 0x02:
                return Type::ST_LRI;  // LRI2K
        }
        return Type::ST;
    }

    // Fujitsu
    if (mf == m5::stl::to_underlying(m5::nfc::ManufacturerId::Fujitsu)) {
        return Type::Fujitsu;
    }

    return Type::Unclassified;
}

uint32_t encode_VCD(std::vector<uint8_t>& out, const ModulationMode mode, const uint8_t* buffer, const uint32_t length,
                    const bool high_rate, const bool add_crc)
{
    out.clear();

    if (!buffer && !length) {
        out.push_back(EOF_COMMON);
        return 1;
    }
    if (!buffer || !length) {
        return 0;
    }

    std::vector<uint8_t> frame{};
    frame.assign(buffer, buffer + length);

    // Adjust flags
    if (high_rate) {
        frame[0] = static_cast<uint8_t>(frame[0] | FLAG_HIGH_DATARATE);
        frame[0] = static_cast<uint8_t>(frame[0] & ~FLAG_TWO_SUBCARRIERS);
    }

    // Append CRC
    if (add_crc) {
        m5::utility::CRC16 crc16(0xFFFF, 0x1021, true, true, 0xFFFF);  // ISO15693 CRC
        const uint16_t crc = crc16.range(frame.data(), frame.size());
        frame.push_back(crc & 0xFF);
        frame.push_back(((crc >> 8) & 0xFF));
    }

    // Calculate SOF/EOF/subbit
    uint8_t sof{};
    uint8_t eof{EOF_COMMON};
    uint32_t out_bytes{};

    const uint32_t frameLen = static_cast<uint16_t>(frame.size());
    encode_function encode_byte{};

    if (mode == ModulationMode::OneOf4) {
        sof         = SOF_1OF4;
        out_bytes   = 1u + frameLen * 4u + 1u;
        encode_byte = encode_byte_1of4;
    } else {
        sof         = SOF_1OF256;
        out_bytes   = 1u + frameLen * 64u + 1u;
        encode_byte = encode_byte_1of256;
    }

    // Make data
    out.reserve(out_bytes);
    // SOF
    out.push_back(sof);
    // payload and CRC (if exeist)
    for (uint32_t i = 0; i < frameLen; ++i) {
        encode_byte(out, frame[i]);
    }
    // EOF
    out.push_back(eof);

    return out.size();
}

bool decode_VICC(std::vector<uint8_t>& out, const uint8_t* buffer, const uint32_t length, const uint32_t ignore_bits)
{
    if (!buffer || !length) {
        return false;
    }

    // Check SOF
    if ((buffer[0] & 0x1F) != 0x17) {
        M5_LIB_LOGE("Framing error %02X", buffer[0]);
        return false;
    }

    // Calculate size
    const uint32_t manBits        = static_cast<uint32_t>(length) * 8;
    const uint32_t maxPayloadBits = (manBits > 5) ? ((manBits - 5) / 2) : 0;
    const uint32_t outBufLen      = (maxPayloadBits + 7) / 8;
    if (!outBufLen) {
        M5_LIB_LOGE("Output length is zero %u/%u", manBits, maxPayloadBits);
        return false;
    }
    out.assign(outBufLen, 0);

    // Decode
    uint16_t mp{5};  // position of Manchester bit (SOF 5bit consumed)
    uint16_t bp{0};  // position of payload bit

    for (; mp < (manBits - 2); mp += 2) {
        bool isEOF{};

        // Get man
        uint8_t man{};
        man = (buffer[mp / 8] >> (mp % 8)) & 0x01;
        man |= ((buffer[(mp + 1) / 8] >> ((mp + 1) % 8)) & 0x01) << 1;

        // man == 1 (01) -> payload bit 0
        if (man == 1) {
            ++bp;
        }
        // man == 2 (10) -> payload bit 1
        if (man == 2) {
            const uint16_t byte_pos = bp / 8;
            const uint8_t bit_pos   = bp % 8;
            if (byte_pos < out.size()) {
                out[byte_pos] = static_cast<uint8_t>(out[byte_pos] | static_cast<uint8_t>(1U << bit_pos));
            }
            ++bp;
        }

        // Check the EOF pattern for each byte boundary
        if ((bp % 8) == 0) {
            const uint16_t byte_pos = static_cast<uint16_t>(mp / 8);
            if (byte_pos + 1 < length) {
                if (((buffer[byte_pos] & 0xe0) == 0xa0) && (buffer[byte_pos + 1] == 0x03)) {
                    isEOF = true;
                }
            }
        }

        // Collision if man is 0 or 3
        if ((man == 0 || man == 3) && !isEOF) {
            if (bp >= ignore_bits) {
                M5_LIB_LOGE("Exceeded collision ignore bits %u", ignore_bits);
                return false;
            } else {
                ++bp;
            }
        }

        // Break if overflow, EOF
        if (bp >= static_cast<uint16_t>(out.size() * 8) || isEOF) {
            break;
        }
    }

    const uint16_t out_bytes_used = static_cast<uint16_t>(bp / 8u);

    // Reduce output buffer
    if (out_bytes_used <= out.size()) {
        out.resize(out_bytes_used);
    }

    // The bit boundary is not a multiple of 8
    if ((bp % 8u) != 0u) {
        M5_LIB_LOGE("Bit boundary error");
        return false;
    }

    // The output length must be at least 2 bytes (including CRC)
    if (out_bytes_used <= 2u) {
        M5_LIB_LOGE("Output too small %u", out_bytes_used);
        return false;
    }

    // Check CRC
    m5::utility::CRC16 crc16(0xFFFF, 0x1021, true, true, 0xFFFF);  // ISO15693 CRC
    const uint16_t crc   = crc16.range(out.data(), out_bytes_used - 2u);
    const uint16_t crcRx = ((uint16_t)out[out_bytes_used - 1] << 8) | out[out_bytes_used - 2u];
    if (crc != crcRx) {
        M5_LIB_LOGE("CRC error %04X/%04X", crc, crcRx);
        return false;
    }
    return true;
}

//
std::string PICC::uidAsString() const
{
    char buf[2 * 8 + 1]{};
    uint8_t left{};
    for (uint8_t i = 0; i < 8; ++i) {
        left += snprintf(buf + left, 3, "%02X", this->uid[i]);
    }
    return std::string(buf);
}

std::string PICC::typeAsString() const
{
    auto idx = m5::stl::to_underlying(this->type);
    return std::string((idx <= m5::stl::size(name_table)) ? name_table[idx] : name_unknown);
}

}  // namespace v
}  // namespace nfc
}  // namespace m5
