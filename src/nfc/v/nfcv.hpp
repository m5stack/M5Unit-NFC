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
  @brief Encode to VCD frame
  @param out Output buffer
  @param mode ModulationMode
  @param buffer Input buffer
  @param length Input buffer length
  @param high_rate High data rate if true
  @param add_crc Append CRC16 if true
  @return True if successful
 */
bool encode_VCD(std::vector<uint8_t>& out, const ModulationMode mode, const uint8_t* buffer, const uint32_t length,
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

/*!
  @enum Type
  @brief Type of the PICC
 */
enum class Type : uint8_t {
    Unknown,  //!< Unknown type
};

/*!
  @struct PICC
  @brief PICC for NFC-V
 */
struct PICC {
    uint8_t uid[8]{};      //!< UID (MSB-first)
    uint8_t dsfID{};       //!< Data Storage Format Identifier
    uint8_t afi{};         //!< Application Family Identifier
    uint8_t icRef{};       //!< IC Reference
    uint8_t block_size{};  //!< Byte size of 1 block
    uint16_t blocks{};     //!< Number of blocks

    inline bool valid() const
    {
        return (uid[0] == 0xE0) && blocks && block_size;
    }
    inline uint8_t manufacturerCode() const
    {
        return valid() ? uid[1] : 0xFF;
    }
    inline uint16_t totalSize() const
    {
        return blocks * block_size;
    }

    //! @brief Gets the uid string
    std::string uidAsString() const;
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
constexpr uint32_t TIMEOUT_WRITE_SINGLE_BLOCK{50};
///@}

}  // namespace v
}  // namespace nfc
}  // namespace m5
#endif
