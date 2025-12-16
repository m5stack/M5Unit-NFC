/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file apdu.hpp
  @brief Application Protocol Data Unit (ISO/IEC 7816-4)
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_APDU_APDU_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_APDU_APDU_HPP
#include <cstdint>
#include <string>
#include <vector>

namespace m5 {
namespace nfc {
/*!
  @namespace apdu
  @brief For APDU
*/
namespace apdu {

///@name APDU responses
///@{
//!  @brief Command successfully executed (OK)
constexpr uint16_t RESPONSE_OK{0x9000};
//! Command successfully executed; xx bytes of data are available and can be requested using GET RESPON
constexpr uint16_t SUCCESSFULLY_1{0x6100};
//! Command successfully executed; xx bytes of data are available and can be requested using GET RESPON
constexpr uint16_t SUCCESSFULLY_2{0x9F00};

constexpr uint8_t RESPONSE_BYTES_STILL_AVAILABLE{0x61};  //!< Response bytes still available
constexpr uint8_t WRONG_LENGTH_LE{0x6C};                 //!< Wrong length Le
///@}

//! @brief Is response successfully?
inline bool is_response_OK(const uint16_t sw12)
{
    return sw12 == RESPONSE_OK || ((sw12 & 0xFF00) == SUCCESSFULLY_1) || ((sw12 & 0xFF00) == SUCCESSFULLY_2);
}

//! @brief Is response successfully?
inline bool is_response_OK(const uint8_t sw[2])
{
    return is_response_OK((uint16_t)((sw[0] << 8) | sw[1]));
}
//! @brief Is response successfully?
inline bool is_response_OK(const uint8_t sw1, const uint8_t sw2)
{
    return is_response_OK((uint16_t)((sw1 << 8) | sw2));
}

/*!
  @enum INS
  @brief APDU instruction code
 */
enum class INS : uint8_t {
    // ISO/IEC 7816-4
    SELECT_FILE = 0xA4,

    READ_BINARY   = 0xB0,
    WRITE_BINARY  = 0xD0,
    UPDATE_BINARY = 0xD6,
    ERASE_BINARY  = 0x0E,

    READ_RECORD    = 0xB2,
    WRITE_RECORD   = 0xD2,
    APPEND_RECORD  = 0xE2,
    UPDATE_RECORRD = 0xDC,

    GET_RESPONSE = 0xC0,
    GET_DATA     = 0xCA,
    PUT_DATA     = 0xDA,

    VERIFY = 0x20,

    INTERNAL_AUTHENTICATE = 0x88,
    EXTERNAL_AUTHENTICATE = 0x82,

    GET_CHALLEMGE = 0x84,

    // Not ISO/IEC 7816-4
    LOCK_DF           = 0x50,
    UNLOCK_DF         = 0x52,
    UNLOCK_KEY        = 0x54,
    CHANGE_KEY        = 0x32,
    ERASE_ALL_RECORDS = 0x06,
    GET_VERSION       = 0x60,
};

///@}

inline bool need_select_file_le(const uint8_t param2)
{
    return (param2 & 0x0C) != 0x0C;
}

struct TLV {
    uint32_t tag{};      //!< T (Tag)
    uint32_t len{};      //!< L (length)
    const uint8_t* v{};  //!< V
    uint8_t tag_len{};   //!< Tag length

    inline bool is_constructed() const
    {
        return (tag & 0x20) != 0;
    }
    inline bool is_primitive() const
    {
        return is_constructed();
    }
};

std::vector<TLV> parse_tlv(const uint8_t* ptr, const uint32_t len);
void dump_tlv(const std::vector<TLV>& tlvs, const uint8_t depth = 0);

/*!
  @brief Make APDU command
  @param cla CLA
  @param ins INS
  @param param1 PARAM1
  @param param2 PARAM2
  @param data Payload data
  @param data_len Payload data length
  @param rx_len Expected bytes to receive
  @return Constructed command data
 */
std::vector<uint8_t> make_apdu_command(const uint8_t cla, const INS ins, const uint8_t param1 = 0x00,
                                       const uint8_t param2 = 0x00, const uint8_t* data = nullptr,
                                       const uint16_t data_len = 0, const uint16_t rx_len = 0);

//!  @brief Make APDU case1 command [CLA | INS | P1 | P2]
inline std::vector<uint8_t> make_apdu_case1(const uint8_t cla, const INS ins, const uint8_t p1, const uint8_t p2)
{
    return make_apdu_command(cla, ins, p1, p2, nullptr, 0, 0);
}

//!  @brief Make APDU case2 command [CLA | INS | P1 | P2 | Le]
inline std::vector<uint8_t> make_apdu_case2(const uint8_t cla, const INS ins, const uint8_t p1, const uint8_t p2,
                                            const uint16_t le)
{
    return make_apdu_command(cla, ins, p1, p2, nullptr, 0, le);
}

//!  @brief Make APDU case3 command [CLA | INS | P1 | P2 | Lc | C-Data]
inline std::vector<uint8_t> make_apdu_case3(const uint8_t cla, const INS ins, const uint8_t p1, const uint8_t p2,
                                            const uint8_t* data, const uint16_t data_len)
{
    return make_apdu_command(cla, ins, p1, p2, data, data_len, 0);
}

//!  @brief Make APDU case4 command [CLA | INS | P1 | P2 | Lc | C-Data | Le]
inline std::vector<uint8_t> make_apdu_case4(const uint8_t cla, const INS ins, const uint8_t p1, const uint8_t p2,
                                            const uint8_t* data, const uint16_t data_len, const uint16_t le)
{
    return make_apdu_command(cla, ins, p1, p2, data, data_len, le);
}

}  // namespace apdu
}  // namespace nfc
}  // namespace m5
#endif
