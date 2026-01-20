/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file mifare.hpp
  @brief MIFARE definitions
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_NFCA_MIFARE_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_NFCA_MIFARE_HPP

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
constexpr std::array<uint8_t, 7> historical_bytes_mifare_plus_s   = {0xC1, 0x05, 0x2F, 0x2F, 0x00, 0x35, 0xC7};
constexpr std::array<uint8_t, 7> historical_bytes_mifare_plus_x   = {0xC1, 0x05, 0x2F, 0x2F, 0x01, 0xBC, 0xD6};
constexpr std::array<uint8_t, 7> historical_bytes_mifare_plus_se0 = {0xC1, 0x05, 0x21, 0x30, 0x00, 0xF6, 0xD1};
constexpr std::array<uint8_t, 7> historical_bytes_mifare_plus_se1 = {0xC1, 0x05, 0x21, 0x30, 0x10, 0xF6, 0xD1};
constexpr std::array<uint8_t, 7> historical_bytes_mifare_plus_se2 = {0xC1, 0x05, 0x21, 0x30,
                                                                     0x00, 0x77, 0xC1};  // Unofficial?
///@}

/*!
  @namespace classic
  @brief For MIFARE classic
 */
namespace classic {
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
constexpr AESKey DEFAULT_KEY{}; // All 0x00


/*!
  @struct Keys
  @brief MIFARE Plus key set for SL upgrade and authentication
 */
struct Keys {
    static constexpr size_t MAX_SECTORS{40};  //!< @brief Maximum number of sectors for MIFARE Plus 4K
    //! @brief Default AES key (all 0x00)
    static constexpr std::array<uint8_t, 16> DEFAULT_AES_KEY{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    //! @brief Default CRYPTO1 key (all 0xFF)
    static constexpr std::array<uint8_t, 6> DEFAULT_CLASSIC_KEY{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    std::array<uint8_t, 16> card_config_key{};                           //!< Card Configuration Key
    std::array<uint8_t, 16> card_master_key{};                           //!< Card Master Key
    std::array<uint8_t, 16> l3_switch_key{};                             //!< Level 3 Switch Key
    std::array<std::array<uint8_t, 16>, MAX_SECTORS> aes_sector_keys{};  //!< AES sector keys
    std::array<std::array<uint8_t, 6>, MAX_SECTORS> classic_key_a{};     //!< Crypto1 Key A per sector
    std::array<std::array<uint8_t, 6>, MAX_SECTORS> classic_key_b{};     //!< Crypto1 Key B per sector

    //! @brief Construct with default keys (AES=0x00, CRYPTO1=0xFF)
    Keys() noexcept
    {
        card_config_key = DEFAULT_AES_KEY;
        card_master_key = DEFAULT_AES_KEY;
        l3_switch_key   = DEFAULT_AES_KEY;
        for (auto& key : aes_sector_keys) {
            key = DEFAULT_AES_KEY;
        }
        for (auto& key : classic_key_a) {
            key = DEFAULT_CLASSIC_KEY;
        }
        for (auto& key : classic_key_b) {
            key = DEFAULT_CLASSIC_KEY;
        }
    }
};
}  // namespace plus

}  // namespace mifare
}  // namespace a
}  // namespace nfc
}  // namespace m5
#endif
