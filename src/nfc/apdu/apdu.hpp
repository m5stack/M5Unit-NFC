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
    CREATE_FILE = 0xE0,

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

    // DESFire
    DF_CREATE_APPLICATION          = 0xCA,
    DF_DELETE_APPLICATION          = 0xDA,
    DF_SELECT_APPLICATION          = 0x5A,
    DF_GET_APPLICATION_IDS         = 0x6A,
    DF_CREATE_STD_DATA_FILE        = 0xCD,
    DF_GET_FREE_MEMORY             = 0x6E,
    DF_GET_FILE_IDS                = 0x6F,
    DF_GET_ISO_FILE_IDS            = 0x61,
    DF_GET_KEY_SETTINGS            = 0x45,
    DF_SET_CONFIGURATION           = 0x5C,
    DF_CHANGE_FILE_SETTINGS        = 0x5F,
    DF_AUTHENTICATE                = 0x0A,
    DF_AUTHENTICATE_ISO            = 0x1A,
    DF_AUTHENTICATE_AES            = 0xAA,
    DF_AUTHENTICATE_EV2            = 0x71,
    DF_FORMAT_PICC                 = 0xFC,
    DF_READ_DATA                   = 0xBD,
    DF_WRITE_DATA                  = 0x3D,
    DF_GET_FILE_SETTINGS           = 0xF5,
    DF_DELETE_TRANSACTION_MAC_FILE = 0xDF,
    DF_CREATE_TRANSACTION_MAC_FILE = 0xCE,
};
///@}

/*!
  @enum SelectBy
  @brief Select control for SELECT_FILE
  @note OR with SelectOccurrence
 */
enum class SelectBy : uint8_t {
    FileId            = 0x00,  //!< Select MF/DF/EF by file ID
    ChildDf           = 0x01,  //!< Select child DF (FID in data)
    EfUnderCurrentDf  = 0x02,  //!< Select EF under current DF (FID in data)
    ParentDf          = 0x03,  //!< Select parent DF
    DfName            = 0x04,  //!< Select by DF name (AID)
    PathFromMf        = 0x08,  //!< Select by path from MF
    PathFromCurrentDf = 0x09,  //!< Select by path from current DF
};

/*!
  @enum SelectOccurrence
  @brief Select occurrence for SELECT_FILE
  @note OR with SelectBy
 */
enum class SelectOccurrence : uint8_t {
    FirstOrOnly = 0x00,  //!< Select the first (or only) match
    Last        = 0x01,  //!<  Select the last match
    Next        = 0x02,  //!<  Select the next match
    Previous    = 0x03,  //!<  Select the previous match
};

/*!
  @enum SelectResponse
  @brief Response for SELECT_FILE
*/
enum class SelectResponse : uint8_t {
    FCI  = 0x00,  //!< FCI template
    FCP  = 0x04,  //!< FCP template
    FMD  = 0x08,  //!< FMD template
    None = 0x0C,  //!</ No response
};

constexpr uint16_t master_file_id{0x3F00};  //!< Master file ID

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
std::vector<uint8_t> make_apdu_command(const uint8_t cla, const uint8_t ins, const uint8_t param1 = 0x00,
                                       const uint8_t param2 = 0x00, const uint8_t* data = nullptr,
                                       const uint16_t data_len = 0, const uint16_t rx_len = 0);

//!  @brief Make APDU case1 command [CLA | INS | P1 | P2]
inline std::vector<uint8_t> make_apdu_case1(const uint8_t cla, const uint8_t ins, const uint8_t p1, const uint8_t p2)
{
    return make_apdu_command(cla, ins, p1, p2, nullptr, 0, 0);
}

//!  @brief Make APDU case2 command [CLA | INS | P1 | P2 | Le]
inline std::vector<uint8_t> make_apdu_case2(const uint8_t cla, const uint8_t ins, const uint8_t p1, const uint8_t p2,
                                            const uint16_t le)
{
    return make_apdu_command(cla, ins, p1, p2, nullptr, 0, le);
}

//!  @brief Make APDU case3 command [CLA | INS | P1 | P2 | Lc | C-Data]
inline std::vector<uint8_t> make_apdu_case3(const uint8_t cla, const uint8_t ins, const uint8_t p1, const uint8_t p2,
                                            const uint8_t* data, const uint16_t data_len)
{
    return make_apdu_command(cla, ins, p1, p2, data, data_len, 0);
}

//!  @brief Make APDU case4 command [CLA | INS | P1 | P2 | Lc | C-Data | Le]
inline std::vector<uint8_t> make_apdu_case4(const uint8_t cla, const uint8_t ins, const uint8_t p1, const uint8_t p2,
                                            const uint8_t* data, const uint16_t data_len, const uint16_t le)
{
    return make_apdu_command(cla, ins, p1, p2, data, data_len, le);
}

}  // namespace apdu
}  // namespace nfc
}  // namespace m5
#endif
