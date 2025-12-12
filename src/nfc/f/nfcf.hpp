/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfcf.hpp
  @brief NFC-F definitions
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_F_NFCF_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_F_NFCF_HPP

#include "nfc/nfc.hpp"
#include <cstdint>
#include <string>
#include <array>

namespace m5 {
namespace nfc {
/*!
  @namespace f
  @brief NFC-F definitions
 */
namespace f {

using IDm = std::array<uint8_t, 8>;  //!< Manufacture ID
using PMm = std::array<uint8_t, 8>;  //!< Manufacture Parameter

/*!
  @enum Type
  @brief Type of the PICC
 */
enum class Type : uint8_t {
    Unknown,         //!< Unknown type
    FeliCaStandard,  //!< Standard
    FeliCaLite,      //!< Lite
    FeliCaLiteS,     //!< Lite-S
    FeliCaPlug,      //!< Plug
    //    FeliCaLink,      //!< Link
};

//! @brief Get NFC Forum Tag Type from PICC type
inline m5::nfc::NFCForumTag get_nfc_forum_tag_type(const Type t)
{
    return (t != Type::Unknown) ? NFCForumTag::Type3 : NFCForumTag::None;
}

///@name Format bits
///@{
using Format = uint8_t;
constexpr Format format_nfcip1{0x0001};       //!< Support ISO/IEC18092
constexpr Format format_dfc{0x0002};          //!< Has DFC
constexpr Format format_private{0x0004};      //!< Has private area
constexpr Format format_ndef{0x0008};         //!< Support NDEF
constexpr Format format_shared{0x0010};       //!< Has shared area
constexpr Format format_secure{0x0020};       //!< FeliCa Secure ID
constexpr Format format_felica_plug{0x0040};  //!< FeliCa Plug
///@}

/*!
  @enum CommandCode
  @brief NFC-F Command code
 */
enum class CommandCode : uint8_t {
    Polling,
    RequestService         = 0x02,
    RequestResponse        = 0x04,
    ReadWithoutEncryption  = 0x06,
    WriteWithoutEncryption = 0x08,
    RequestSystemCode      = 0x0C,
};

/*!
  @enum ResponseCode
  @brief NFC-F Response code
*/
enum class ResponseCode : uint8_t {
    Polling                = 0x01,
    RequestService         = 0x03,
    RequestResponse        = 0x05,
    ReadWithoutEncryption  = 0x07,
    WriteWithoutEncryption = 0x09,
    RequestSystemCode      = 0x0D,
};

///@name SystemCode
///@{
constexpr uint16_t system_code_wildcard{0xFFFF};          //!< Wildcard
constexpr uint16_t system_code_ndef{0x12FC};              //!< NDEF
constexpr uint16_t system_code_felica_secure_id{0x957A};  //!< FeliCa secure ID
constexpr uint16_t system_code_shared{0xFE00};            //!< Shared area
constexpr uint16_t system_code_dfc{0x88B4};               //!< Lite, Lite-S
constexpr uint16_t system_code_felica_plug{0xFEE1};       //!< FeliCa Plug
///@}

/*!
  @enum RequestCode
  @brief Request code for Polling
 */
enum class RequestCode : uint8_t {
    None,                      //!< No request
    SystemCode,                //!< Request system code
    CommunicationPerformance,  //!< Request communication performance
};

/*!
  @enum TimeSlot
  @brief Timeslot value for Polling
 */
enum class TimeSlot : uint8_t { Slot1, Slot2, Slot4 = 0x03, Slot8 = 0x07, Slot16 = 0x0F };

//! @brief TimeSlot to the number of the slot
inline constexpr uint8_t timeslot_to_slot(const TimeSlot ts)
{
    return (ts == TimeSlot::Slot16)  ? 16
           : (ts == TimeSlot::Slot8) ? 8
           : (ts == TimeSlot::Slot4) ? 4
           : (ts == TimeSlot::Slot2) ? 2
           : (ts == TimeSlot::Slot1) ? 1
                                     : 0;  //    Illegal
}

///@name Service attribute
///@{
// Random service
constexpr uint16_t service_random_read_write_auth{0x0008};  //!< Random,Read/write,Authentication required (S)
constexpr uint16_t service_random_read_write{0x0009};       //!< Random,Read/write,No authentication required (S, L, LS)
constexpr uint16_t service_random_read_auth{0x000A};        //!< Random,Read only,No authentication required (S)
constexpr uint16_t service_random_read{0x000B};             //!< Random,Read only,No authentication required (S,LS)
// Cyclic service
constexpr uint16_t service_cyclic_read_write_auth{0x000C};  //!< Cyclic,Read/write,Authentication required(S)
constexpr uint16_t service_cyclic_read_write{0x000D};       //!< Cyclic,Read/write,No athentication required(S)
constexpr uint16_t service_cyclic_read_auth{0x000E};        //!< Cyclic,Read only,Authentication required(S)
constexpr uint16_t service_cyclic_read{0x000F};             //!< Cyclic,Read only,No authentication required(S)
// Parse service
constexpr uint16_t service_parse_direct_auth{0x0100};
constexpr uint16_t service_parse_direct{0x0101};
constexpr uint16_t service_parse_cacheback_auth{0x0102};
constexpr uint16_t service_parse_cacheback{0x0103};
constexpr uint16_t service_parse_decrement_auth{0x0104};
constexpr uint16_t service_parse_decrement{0x0105};
constexpr uint16_t service_parse_increment_auth{0x0106};
constexpr uint16_t service_parse_increment{0x0107};
///@}

/*!
  @struct block_t
  @brief Block list element
 */
struct block_t {
    uint8_t pad{};
    uint8_t header{};   //!< size:1 access:3 order:4
    uint16_t number{};  //!< block number (using low byte if 2 byte mode)

    inline constexpr block_t() : block_t(0)
    {
    }
    // Allow implicit type conversion
    inline constexpr block_t(const uint16_t num, const uint8_t access = 0, const uint8_t order = 0)
        : header{(uint8_t)(((num > 0xFF) ? 0x00 : 0x80) | ((access & 0x07) << 4) | (order & 0x0F))}, number{num}
    {
    }
    inline constexpr bool is_2byte() const
    {
        return (header & 0x80) != 0;
    }
    inline constexpr bool is_3byte() const
    {
        return (header & 0x80) == 0;
    }
    inline constexpr uint8_t access_mode() const
    {
        return (header >> 4) & 0x07;
    }
    inline constexpr uint8_t order() const
    {
        return (header & 0x0F);
    }
    inline constexpr uint16_t block() const
    {
        return number;
    }

    inline void block(const uint16_t num)
    {
        number = num;
        header = (header & ~0x80) | (num > 0xFF ? 0x00 : 0x80);
    }
    inline void access_mode(const uint8_t a)
    {
        header = (header & ~(0x07 << 4)) | ((a & 0x07) << 4);
    }
    inline void order(const uint8_t o)
    {
        header = (header & ~0x0F) | (o & 0x0F);
    }

    inline operator uint16_t() const
    {
        return block();
    }

    uint8_t store(uint8_t buf[3]) const
    {
        uint8_t idx{};
        buf[idx++] = header;
        buf[idx++] = number & 0xFF;
        if (is_3byte()) {
            buf[idx++] = number >> 8;
        }
        return idx;
    }
};

/*!
  @namespacce lite
  @brief For FeliCa Standard
 */
namespace standard {
/*!
  @enum Mode
  @brief Mode for Standard
 */
enum class Mode : uint8_t {
    Mode0,  //!< Power was supplied to the PICC
    Mode1,  //!< Certification for PICC has been completed (Auth1)
    Mode2,  //!< After mutual authentication is complete (Auth2)
    Mode3,  //!< After registering area services or executing system partitioning

};
}  // namespace standard

/*!
  @namespacce lite
  @brief For FeliCa Lite
 */
namespace lite {
///@name

///@name Block
///@{
constexpr block_t S_PAD0{0x00};
constexpr block_t S_PAD1{0x01};
constexpr block_t S_PAD2{0x02};
constexpr block_t S_PAD3{0x03};
constexpr block_t S_PAD4{0x04};
constexpr block_t S_PAD5{0x05};
constexpr block_t S_PAD6{0x06};
constexpr block_t S_PAD7{0x07};
constexpr block_t S_PAD8{0x08};
constexpr block_t S_PAD9{0x09};
constexpr block_t S_PAD10{0x0A};
constexpr block_t S_PAD11{0x0B};
constexpr block_t S_PAD12{0X0C};
constexpr block_t S_PAD13{0x0D};
constexpr block_t REG{0x0E};
constexpr block_t RC{0x80};
constexpr block_t MAC{0x81};
constexpr block_t ID{0x082};
constexpr block_t D_ID{0x83};
constexpr block_t SER_C{0x84};
constexpr block_t SYS_C{0x85};
constexpr block_t CKV{0x86};
constexpr block_t CK{0x87};
constexpr block_t MC{0x88};
///@}

}  // namespace lite

/*!
  @namespacce lite_s
  @brief For FeliCa Lite-S
 */
namespace lite_s {

/*!
  @enum Mode
  @brief Mode for LiteS
 */
enum class Mode : uint8_t {
    Mode00,  //!< External authentication incomplete, polling response possible
    Mode01,  //!< External authentication incomplete, polling response not possible
    Mode10,  //!< External authentication complete, polling response possibl
    Mode11,  //!< External authentication complete, polling response not possible
};

///@name Block
///@{
constexpr block_t S_PAD0{0x00};   // Same as Lite
constexpr block_t S_PAD1{0x01};   // Same as Lite
constexpr block_t S_PAD2{0x02};   // Same as Lite
constexpr block_t S_PAD3{0x03};   // Same as Lite
constexpr block_t S_PAD4{0x04};   // Same as Lite
constexpr block_t S_PAD5{0x05};   // Same as Lite
constexpr block_t S_PAD6{0x06};   // Same as Lite
constexpr block_t S_PAD7{0x07};   // Same as Lite
constexpr block_t S_PAD8{0x08};   // Same as Lite
constexpr block_t S_PAD9{0x09};   // Same as Lite
constexpr block_t S_PAD10{0x0A};  // Same as Lite
constexpr block_t S_PAD11{0x0B};  // Same as Lite
constexpr block_t S_PAD12{0X0C};  // Same as Lite
constexpr block_t S_PAD13{0x0D};  // Same as Lite
constexpr block_t REG{0x0E};      // Same as Lite
constexpr block_t RC{0x80};       // Same as Lite
constexpr block_t MAC{0x81};      // Same as Lite
constexpr block_t ID{0x082};      // Same as Lite
constexpr block_t D_ID{0x83};     // Same as Lite
constexpr block_t SER_C{0x84};    // Same as Lite
constexpr block_t SYS_C{0x85};    // Same as Lite
constexpr block_t CKV{0x86};      // Same as Lite
constexpr block_t CK{0x87};       // Same as Lite
constexpr block_t MC{0x88};       // Same as Lite
constexpr block_t WCNT{0x90};
constexpr block_t MAC_A{0x91};
constexpr block_t STATE{0x92};
constexpr block_t CRC_CHECK{0xA0};
///@}

}  // namespace lite_s

//! @brief Gets the maximum block
uint16_t get_maximum_block(const Type t);
//! @brief Gets the number of user blocks
uint16_t get_number_of_user_blocks(const Type t);
//!@brief Gets the user area bytes
inline uint16_t get_user_area_size(const Type t)
{
    return 16 * get_number_of_user_blocks(t);
}
//! @brief Gets the first user area block number
uint16_t get_first_user_block(const Type t);
//! @brief Gets the last user area block number
uint16_t get_last_user_block(const Type t);
//! @brief Is block user area?
inline bool is_user_block(const Type t, const uint16_t block)
{
    return (block >= get_first_user_block(t)) && (block <= get_last_user_block(t));
}
//! @brief Maximum number of blocks that can be read simultaneously
uint8_t get_maxumum_read_blocks(const Type t);
//! @brief Maximum number of blocks that can be write simultaneously
uint8_t get_maxumum_write_blocks(const Type t);

///@name RequestService
///@{
constexpr uint16_t NODE_SYSTEM_KEY{0xFFFF};   //!< Retrieving the System Key Version
constexpr uint16_t KEY_VERIOSN_NONE{0xFFFF};  //!< No key version exists
///@}

/*!
  @struct PICC
  @brief PICC information for NFC-F
 */
struct PICC {
    IDm idm{};                   //!< Manufacture ID
    PMm pmm{};                   //!< Manufacture Parameter
    uint16_t request_data{};     //!< Any request data if exists
    RequestCode request_code{};  //!< Tyepe of the request_data
    Type type{};                 //!< PICC Type
    Format format{};             //!< Format type group bits
    uint8_t _pad{};
    uint16_t dfc_format{};  //!< DFC format (ID[8],ID[9] LE) if format include DFC

    //! @brief Valid?
    inline bool valid() const
    {
        return type != Type::Unknown;
    }

    //! @brief Total user area size
    inline uint16_t userAreaSize() const
    {
        return valid() ? get_user_area_size(type) : 0;
    }
    //! @brief Gets the first user block
    inline uint16_t firstUserBlock() const
    {
        return valid() ? get_first_user_block(type) : 0xFFFF;
    }
    //! @brief Gets the last user block
    inline uint16_t lastUserBlock() const
    {
        return valid() ? get_last_user_block(type) : 0xFFFF;
    }
    //! @brief Is user block?
    inline bool isUserBlock(const block_t block) const
    {
        return is_user_block(type, block);
    }

    //! @brief Maximum number of blocks that can be read simultaneously
    inline uint8_t maximumReadBlocks() const
    {
        return get_maxumum_read_blocks(type);
    }
    //! @brief Maximum number of blocks that can be write simultaneously
    inline uint8_t maximumWriteBlocks() const
    {
        return get_maxumum_write_blocks(type);
    }

    //! @brief Check format
    inline bool checkFormat(const Format f) const
    {
        return (format & f) != 0;
    }
    //! @brief Supports NDEF?
    inline bool supportsNDEF() const
    {
        return checkFormat(format_ndef);
    }

    //! @brief NFC ForumTag
    inline NFCForumTag nfcForumTagType() const
    {
        return get_nfc_forum_tag_type(type);
    }

    //! @brief Gets the IDm string
    std::string idmAsString() const;
    //! @brief Gets the PMm string
    std::string pmmAsString() const;
    //! @brief Gets the type string
    std::string typeAsString() const;
};

//! @brief Equal? (Only IDm,PMm)
inline bool operator==(const PICC& a, const PICC& b)
{
    return a.valid() && b.valid() && a.idm == b.idm && a.pmm == b.pmm && a.type == b.type;
}
//! @brief Not equal?
inline bool operator!=(const PICC& a, const PICC& b)
{
    return !(a == b);
}

///@name Timeout
///@{
constexpr uint32_t TIMEOUT_POLLING{3};
constexpr uint32_t TIMEOUT_POLLING_PICC{2};  // 2 ms per PICC

/*!
  @struct REG
  @brief Subtract Register Block Data
 */
union REG {
    uint8_t reg[16]{};
    struct {
        uint8_t reg_a[4];  // RegA (LE)
        uint8_t reg_b[4];  // RegB (LE)
        uint8_t reg_c[8];  // RegC (BE)
    } __attribute__((packed));

    REG()
    {
    }

    //!@brief Gets the RegA
    inline uint32_t regA() const
    {
        return ((uint32_t)reg_a[3] << 24) | ((uint32_t)reg_a[2] << 16) | ((uint32_t)reg_a[1] << 8) |
               ((uint32_t)reg_a[0]);
    }
    //!@brief Gets the RegB
    inline uint32_t regB() const
    {
        return ((uint32_t)reg_b[3] << 24) | ((uint32_t)reg_b[2] << 16) | ((uint32_t)reg_b[1] << 8) |
               ((uint32_t)reg_b[0]);
    }
    //!@brief Gets the RegC
    inline uint64_t regC() const
    {
        return ((uint64_t)reg_c[0] << 56) | ((uint64_t)reg_c[1] << 48) | ((uint64_t)reg_c[2] << 40) |
               ((uint64_t)reg_c[3] << 32) | ((uint64_t)reg_c[4] << 24) | ((uint64_t)reg_c[5] << 16) |
               ((uint64_t)reg_c[6] << 8) | ((uint64_t)reg_c[7]);
    }
    //!@brief Set the RegA
    void regA(const uint32_t v)
    {
        reg_a[0] = v & 0xFF;
        reg_a[1] = v >> 8;
        reg_a[2] = v >> 16;
        reg_a[3] = v >> 24;
    }
    //!@brief Set the RegB
    void regB(const uint32_t v)
    {
        reg_b[0] = v & 0xFF;
        reg_b[1] = v >> 8;
        reg_b[2] = v >> 16;
        reg_b[3] = v >> 24;
    }
    //!@brief Set the RegC
    void regC(const uint64_t v)
    {
        reg_c[7] = v & 0xFF;
        reg_c[6] = v >> 8;
        reg_c[5] = v >> 16;
        reg_c[4] = v >> 24;
        reg_c[3] = v >> 32;
        reg_c[2] = v >> 40;
        reg_c[1] = v >> 48;
        reg_c[0] = v >> 56;
    }

    inline operator const uint8_t*() const
    {
        return reg;
    }
    inline operator uint8_t*()
    {
        return reg;
    }
} __attribute__((packed));

/*!
  brief Is the new value writable?
  @param o Old REG value
  @param New REG value
  @return true if writable
*/
inline bool can_write_reg(const REG& o, const REG& n)
{
    return (o.regA() >= n.regA()) && (o.regB() >= n.regB());
}

///@name For MAC
///@{
/*!
  @brief Make session key
  @param[out] sk Session key (sk1 8byte + sk2 8byte)
  @param ck Card key
  @param rc Random challenge
  @return True if successful
 */
bool make_session_key(uint8_t sk[16], const uint8_t ck[16], const uint8_t rc[16]);

/*!
  @brief Generate MAC
  @param[out] mac MAC
  @param plain Plain blocks (If nullptr, do not use)
  @param plain_num Number of plain (If zero, do not use)
  @param block_data Block data
  @param block_len Length of block_data
  @param sk1 Session key 1
  @param sk2 Session key 2
  @param rc Random challenge
  @return True if successful
*/
bool generate_mac(uint8_t mac[8], const uint8_t* plain, uint32_t plain_len, const uint8_t* block_data,
                  uint32_t block_len, const uint8_t sk1[8], const uint8_t sk2[8], const uint8_t rc[16]);

///@}

}  // namespace f
}  // namespace nfc
}  // namespace m5
#endif
