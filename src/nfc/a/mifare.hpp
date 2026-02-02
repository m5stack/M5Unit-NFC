/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file mifare.hpp
  @brief MIFARE definitions
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_A_MIFARE_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_A_MIFARE_HPP

#include <cstdint>
#include <array>

namespace m5 {
namespace nfc {
namespace a {
/*!
  @namespace mifare
  @brief For MIFARE
 */
namespace mifare {

///@name Historical bytes for identiy type
///@{
constexpr std::array<uint8_t, 7> historical_bytes_mifare_plus_s    = {0xC1, 0x05, 0x2F, 0x2F, 0x00, 0x35, 0xC7};
constexpr std::array<uint8_t, 7> historical_bytes_mifare_plus_x_ev = {0xC1, 0x05, 0x2F, 0x2F, 0x01, 0xBC, 0xD6};
constexpr std::array<uint8_t, 7> historical_bytes_mifare_plus_se0  = {0xC1, 0x05, 0x21, 0x30, 0x00, 0xF6, 0xD1};
constexpr std::array<uint8_t, 7> historical_bytes_mifare_plus_se1  = {0xC1, 0x05, 0x21, 0x30, 0x10, 0xF6, 0xD1};
constexpr std::array<uint8_t, 7> historical_bytes_mifare_plus_se2  = {0xC1, 0x05, 0x21, 0x30, 0x00, 0x77, 0xC1};
///@}

/*!
  @namespace classic
  @brief For MIFARE classic
 */
namespace classic {

constexpr uint16_t MIFARE_CLASSIC_MAX_TX_LEN{32};
constexpr uint16_t MIFARE_CLASSIC_MAX_RX_LEN{32};
constexpr uint16_t MIFARE_CLASSIC_MAX_TX_WITH_CRC{MIFARE_CLASSIC_MAX_TX_LEN + 2};
constexpr uint16_t MIFARE_CLASSIC_MAX_RX_WITH_CRC{MIFARE_CLASSIC_MAX_RX_LEN + 2};
constexpr uint16_t MIFARE_CLASSIC_MAX_BITSTREAM_LEN{(9 * MIFARE_CLASSIC_MAX_TX_WITH_CRC + 7) / 8};

/*!
  @typedef Key
  @brief MIFARE classic Key
*/
using Key = std::array<uint8_t, 6>;

//! @brief Default key for MIFARE classic
constexpr Key DEFAULT_KEY{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

///@name Access bit
///@{
constexpr uint8_t READ_WRITE_BLOCK{0x00};              //!<  Read and write block
constexpr uint8_t VALUE_BLOCK_NON_RECHARGEABLE{0x01};  //!<  Value block (debit only)
constexpr uint8_t VALUE_BLOCK_RECHARGEABLE{0x06};      //!< Value block (rechargeable)
///@}

/*!
  @brief Can this permission be used as a value block?
  @return True if can
 */
inline constexpr bool can_value_block_permission(const uint8_t permission)
{
    return (permission == 0x00) ||  // transport configuration
           (permission == 0x01) ||  // value block (Only read and decrement)
           (permission == 0x06);    // value block (Full operation)
}

/*!
  @brief Is this block a sector trailer?
  @return True if sector trailer
 */
inline constexpr bool is_sector_trailer_block(const uint16_t block)
{
    return (block < 128) ? (block & 0x03) == 0x03 : ((block - 128) & 0x0F) == 0x0F;
}

/*!
  @brief Obtains the block address of the sector to which it belongs from the block address
  @return The sector trailer block address of the block belongs
 */
inline constexpr uint16_t get_sector_trailer_block(const uint16_t block)
{
    return (block < 128) ? (block | 0x03) : (block | 0x0F);
}

/*!
  @brief Obtains the sector to which the block belongs from the block address
  @return Sector no
 */
inline constexpr uint16_t get_sector(const uint16_t block)
{
    return (block < 128) ? (block >> 2) : 32 + ((block - 128) >> 4);
}

/*!
  @brief Get the offset in the permissions of this block
  @return Offset (0-3)
 */
inline constexpr uint8_t get_permission_offset(const uint16_t block)
{
    return ((block < 128) ? (block & 0x03) : ((block - 128) & 0x0F) / 5) & 0x03;
}

/*!
  @brief Obtains the block address of the sector trailer from sector
  @param sector Sector no
  @return The sector trailer block address of the sector
 */
inline constexpr uint16_t get_sector_trailer_block_from_sector(const uint16_t sector)
{
    return ((sector < 32) ? sector * ((sector < 32) ? 4U : 16U) : 128U + (sector - 32) * ((sector < 32) ? 4U : 16U)) +
           ((sector < 32) ? 4U : 16U) - 1;
}

/*!
  @brief Decode the value of value block
  @param[out] value Value
  @param[out] addr Block address
  @param buf Data of block(16 bytes)
  @return True if successful
 */
bool decode_value_block(int32_t& value, uint8_t& addr, const uint8_t buf[16]);
/*!
  @brief Encode the value of value block
  @param[out] buf Output buffer at least 16 bytes
  @param value Value
  @param addr Block address
  @return Encoded buffer
 */
const uint8_t* encode_value_block(uint8_t buf[16], const int32_t value, const uint8_t addr);

/*!
  @brief Encode accesss bits from permissions
  @param abits[3] Output buffer at leaset 3 bytes
  @param p0 permissions for block 0
  @param p1 permissions for block 1
  @param p2 permissions for block 2
  @param p3 permissions for sector tarailer
  @return True if successful
  @warning Return values should always be checked
  @warning Writing incorrect access bits may make the sector inaccessible!
*/
bool encode_access_bits(uint8_t abits[3], const uint8_t p0, const uint8_t p1, const uint8_t p2, const uint8_t p3);
/*!
  @brief Encode accesss bits from permissions
  @param abits[3] Output buffer at leaset 3 bytes
  @param permissions[4] Array of the permissions. [0];block0 ... [3]:sector trailer
  @return True if successful
  @warning Return values should always be checked
  @warning Writing incorrect access bits may make the sector inaccessible!
*/
inline bool encode_access_bits(uint8_t abits[3], const uint8_t permissions[4])
{
    return encode_access_bits(abits, permissions[0], permissions[1], permissions[2], permissions[3]);
}
/*!
  @brief Decode access bits to permissons
  @param permissions[4] Output buffer at leaset 4 bytes
  @param ab0 1st byte of the access bits
  @param ab1 2nd byte of the access bits
  @param ab2 3rd byte of the access bits
  @return True if successful
  @note permissions[0] block 0
  @note permissions[1] block 1
  @note permissions[2] block 2
  @note permissions[3] sector trailer
  @warning Return values should always be checked
*/
bool decode_access_bits(uint8_t permissions[4], const uint8_t ab0, const uint8_t ab1, const uint8_t ab2);
/*!
  @brief Decode access bits to permissons
  @param permissions[4] Output buffer at leaset 4 bytes
  @param abits[3] Array of the accees bits
  @return True if successful
  @warning Return values should always be checked
*/
inline bool decode_access_bits(uint8_t permissions[4], const uint8_t abits[3])
{
    return decode_access_bits(permissions, abits[0], abits[1], abits[2]);
}

}  // namespace classic

/*!
  @namespace desfire
  @brief For MIFARE DESFire
 */
namespace desfire {

constexpr uint32_t DESFIRE_NDEF_APP_ID{0x000001};           //!< DESFire NDEF application AID
constexpr uint8_t DESFIRE_CC_FILE_NO{0x01};                 //!< AN11004 default CC file number
constexpr uint8_t DESFIRE_NDEF_FILE_NO{0x02};               //!< AN11004 default NDEF file number
constexpr uint8_t DESFIRE_NDEF_AID[] = {0x00, 0x00, 0x01};  //!< DESFire NDEF AID (3 bytes)

constexpr uint8_t DESFIRE_LIGHT_DF_NAME[] = {  //!< DESFire Light default DF Name
    0xA0, 0x00, 0x00, 0x03, 0x96, 0x56, 0x43, 0x41, 0x03, 0xF0, 0x15, 0x40, 0x00, 0x00, 0x00, 0x0B};
constexpr uint16_t DESFIRE_LIGHT_DF_FID{0xDF01};        //!< DESFire Light default DF FID
constexpr uint8_t DESFIRE_LIGHT_CC_FILE_NO{0x00};       //!< DESFire Light CC file number
constexpr uint8_t DESFIRE_LIGHT_NDEF_FILE_NO{0x04};     //!< DESFire Light NDEF file number
constexpr uint16_t DESFIRE_LIGHT_CC_FILE_ID{0xEF00};    //!< DESFire Light CC file ID
constexpr uint16_t DESFIRE_LIGHT_NDEF_FILE_ID{0xEF04};  //!< DESFire Light NDEF file ID
constexpr uint16_t DESFIRE_LIGHT_NDEF_FILE_SIZE{256};   //!< DESFire Light NDEF file size (bytes)

constexpr uint8_t DESFIRE_DEFAULT_KEY[16]{};  //!  DESFire default key

///@name Access rights
///@{
constexpr int8_t access_denied{-1};
constexpr int8_t access_free{-2};
/*!
  @brief Obtain read permissions from access rights
  @param access_rights Access rights
  @retval >= 0 Key number to use
  @reval == access_denied Access denied
  @retval == access_free Access free
*/
inline int8_t required_read_key_no_from_access_rights(const uint16_t access_rights)
{
    const uint8_t read_key = (access_rights >> 12) & 0x0F;
    const uint8_t rw_key   = (access_rights >> 4) & 0x0F;
    if (read_key == 0x0E) {
        return access_free;
    }
    if (read_key != 0x0F) {
        return read_key;
    }
    if (rw_key == 0x0E) {
        return access_free;
    }
    if (rw_key != 0x0F) {
        return rw_key;
    }
    return access_denied;
}
/*!
  @brief Obtain rite permissions from access rights
  @param access_rights Access rights
  @retval >= 0 Key number to use
  @reval == access_denied Access denied
  @retval == access_free Access free
*/
inline int8_t required_write_key_no_from_access_rights(const uint16_t access_rights)
{
    const uint8_t write_key = (access_rights >> 8) & 0x0F;  // Write
    const uint8_t rw_key    = (access_rights >> 4) & 0x0F;  // Read/Write
    if (write_key == 0x0E) {
        return access_free;
    }
    if (write_key != 0x0F) {
        return write_key;
    }
    if (rw_key == 0x0E) {
        return access_free;
    }
    if (rw_key != 0x0F) {
        return rw_key;
    }
    return access_denied;
}
///@}

}  // namespace desfire

/*!
  @namespace plus
  @brief For MIFARE Plus
 */
namespace plus {

/*!
  @typedef AESKey
  @brief MIFARE Plus SL2/3 Key (AES)
*/
using AESKey = std::array<uint8_t, 16>;
//! @brief Default key for MIFARE Plus
constexpr AESKey DEFAULT_KEY{};  // All 0x00
//! @brief Default AES sector key (as classic DEFAULT_KEY)
constexpr AESKey DEFAULT_FF_KEY = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

}  // namespace plus

}  // namespace mifare
}  // namespace a
}  // namespace nfc
}  // namespace m5
#endif
