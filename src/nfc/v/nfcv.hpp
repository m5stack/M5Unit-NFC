/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfcv.hpp
  @brief NFC-V definitions
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_V_NFCV_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_V_NFCV_HPP

#include "nfc/nfc.hpp"
#include <cstdint>
#include <string>
#include <cstring>
#include <vector>

namespace m5 {
namespace nfc {
/*!
  @namespace v
  @brief NFC-V definitions
 */
namespace v {

/*!
  @enum Type
  @brief Type of the PICC
 */
enum class Type : uint8_t {
    Unknown,  //!< Unknown type

    NXP_ICODE_SLI,     //!< ICODE SLI
    NXP_ICODE_SLIX,    //!< ICODE SLIX
    NXP_ICODE_SLIX_2,  //!< ICODE SLIX2
    NXP,               //!< NXP (Unclassified)

    TI_TAGIT_HF_I,       //!< Tag-it HF-I Standard
    TI_TAGIT_HF_I_Plus,  //!< Tag-it HF-I Plus
    TI_TAGIT_HF_I_Pro,   //!< Tag-it HF-I Pro
    TI,                  //!< TI (Unclassified)

    ST_LRI,     //!< ST LRI
    ST_ST25DV,  //!< ST25DV
    ST,         //!< ST (Unclassified)

    Fujitsu_FRAM,  //!< FRAM
    Fujitsu,       //!< Fujitsu (Unclassified)

    Unclassified,  //!< Unclassified
};

///@name Request flags
///@{
const uint8_t option_flag{0x40};
const uint8_t address_flag{0x20};
const uint8_t select_flag{0x10};
const uint8_t inventory_flag{0x04};
const uint8_t data_rate_flag{0x02};
const uint8_t subcarrior_flag{0x01};
const uint8_t nb_slots_flag{0x20};  // if inventory_flag is 1
const uint8_t AFI_flag{0x10};       // // if inventory_flag is 1
///@}

/*!
  @enum VCDMode
  @breif VCD encode flag
 */
enum class ModulationMode : uint8_t {
    OneOf4,    //!< 1 out of 4 pulse-position modulation
    OneOf256,  //!< 1 out of 256 pulse-position modulation
};

/*!
  @brief Identify the type from  Manufacturer Code, IC Identifier, IC Reference
  @return Type
  @warning Not all tags can be identified
  @warning If identification is impossible, Unclassified is returned
 */
Type identify_type(const uint8_t mf, const uint8_t ic, const uint8_t ir, const uint8_t uid4);

//! @brief Get NFC Forum Tag Type from PICC type
inline m5::nfc::NFCForumTag get_nfc_forum_tag_type(const Type t)
{
    return (t != Type::Unknown) ? NFCForumTag::Type5 : NFCForumTag::None;
}

/*!
  @struct PICC
  @brief PICC for NFC-V
 */
struct PICC {
    uint8_t uid[8]{};      //!< UID (MSB-first)
    Type type{};           //!< Type
    uint8_t dsfID{};       //!< Data Storage Format Identifier
    uint8_t afi{};         //!< Application Family Identifier
    uint8_t icRef{};       //!< IC Reference
    uint8_t block_size{};  //!< Byte size of 1 block
    uint8_t _pad{};        //
    uint16_t blocks{};     //!< Number of blocks

    inline bool valid() const
    {
        return (uid[0] == 0xE0) && blocks && block_size;
    }
    inline uint8_t manufacturerCode() const
    {
        return valid() ? uid[1] : 0xFF;
    }
    inline uint8_t icIdentifier() const
    {
        return valid() ? uid[2] : 0x00;
    }
    inline uint8_t icReference() const
    {
        return valid() ? icRef : 0xFF;
    }

    //
    inline uint16_t totalSize() const
    {
        return blocks * block_size;
    }
    //! @brief Total user area size
    inline uint16_t userAreaSize() const
    {
        return totalSize();  // Same as totalSize
    }
    //! @brief NFC ForumTag
    inline NFCForumTag nfcForumTagType() const
    {
        return get_nfc_forum_tag_type(type);
    }

    //! @brief Gets the first user block
    inline uint16_t firstUserBlock() const
    {
        return valid() ? 0 : 0xFFFF;
    }
    //! @brief Gets the last user block
    inline uint16_t lastUserBlock() const
    {
        return valid() ? (blocks - 1) : 0xFFFF;
    }

    //! @brief Gets the uid string
    std::string uidAsString() const;
    //! @brief Gets the type string
    std::string typeAsString() const;
};

//! @brief Equal?
inline bool operator==(const PICC& a, const PICC& b)
{
    return std::memcmp(a.uid, b.uid, 8) == 0;
}
//! @brief Not equal?
inline bool operator!=(const PICC& a, const PICC& b)
{
    return !(a == b);
}

/*!
  @enum Command
  @brief ISO/IEC 15693 Command
 */
enum class Command : uint8_t {
    Inventory           = 0x01,  //!< IVENTORY
    StayQuiet           = 0x02,  //!< STAY QUIET
    Select              = 0x25,  //!< SELECT
    ResetToReady        = 0x26,  //!< RESET TO READY
    GetSystemInformaion = 0x2B,  //!< GET SYSTEM INFORMATION
    ReadSingleBlock     = 0x20,  //!< READ SINGLE BLOCK
    WriteSingleBlock    = 0x21,  //!< WRITE SINGLE BLOCK
};

///@name Timeout
///@{
constexpr uint32_t TIMEOUT_INVENTORY{16};
constexpr uint32_t TIMEOUT_STAY_QUIET{16};
constexpr uint32_t TIMEOUT_SELECT{16};
constexpr uint32_t TIMEOUT_RESET_TO_READY{16};
constexpr uint32_t TIMEOUT_GET_SYSTEM_INFORMATION{20};
constexpr uint32_t TIMEOUT_READ_SINGLE_BLOCK{20};
constexpr uint32_t TIMEOUT_WRITE_SINGLE_BLOCK{30};
///@}

/*!
  @brief Encode to VCD frame
  @param out Output buffer
  @param mode ModulationMode
  @param buffer Input buffer (allow nullptr )
  @param length Input buffer length (allow 0)
  @param high_rate High data rate if true
  @param add_crc Append CRC16 if true
  @return True if successful
  @note Make EOF only if buffer is nullptr and length is 0
 */
uint32_t encode_VCD(std::vector<uint8_t>& out, const ModulationMode mode, const uint8_t* buffer, const uint32_t length,
                    const bool high_rate = true, const bool add_crc = true);

/*!
  @brief Decode from VICC frame
  @param out Output buffer
  @param buffer Input buffer
  @param length Input buffer length
  @return True if successful
 */
bool decode_VICC(std::vector<uint8_t>& out, const uint8_t* buffer, const uint32_t length,
                 const uint32_t ignore_bits = 16);

}  // namespace v
}  // namespace nfc
}  // namespace m5
#endif
