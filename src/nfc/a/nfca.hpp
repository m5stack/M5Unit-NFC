/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfca.hpp
  @brief NFC-A definitions
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_NFCA_NFCA_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_NFCA_NFCA_HPP

#include "mifare.hpp"
#include <cstring>

namespace m5 {
namespace nfc {
/*!
  @namespace a
  @brief NFC-A definitions
 */
namespace a {

/*!
  @enum Type
  @brief Type of the PICC device
 */
enum class Type : uint8_t {
    Unknown,              //!< Unknown type
    MIFARE_Classic,       //!< Also known as MIFARE Standard mini
    MIFARE_Classic_1K,    //!< Also known as MIFARE Standard 1K
    MIFARE_Classic_2K,    //!< Also known as MIFARE Standard 2K
    MIFARE_Classic_4K,    //!< Also known as MIFARE Standard 4K
    MIFARE_UltraLight,    //!< MIFARE Ultralight
    MIFARE_UltraLightC,   //!< MIFARE UltralightC
    MIFARE_Plus_2K,       //!< MIFARE Plus 2K
    MIFARE_Plus_4K,       //!< MIFARE Plus 4K
    MIFARE_DESFire_2K,    //!< MIFARE DESFire 2K
    MIFARE_DESFire_4K,    //!< MIFARE DESFire 4K
    MIFARE_DESFire_8K,    //!< MIFARE DESFire 8K
    NTAG_203,             //!< NATG 203
    NTAG_210u,            //!< NTAG 210μ
    NTAG_210,             //!< NTAG 210
    NTAG_212,             //!< NTAG 212
    NTAG_213,             //!< NTAG 213
    NTAG_215,             //!< NTAG 215
    NTAG_216,             //!< NTAG 216
    ISO_14443_4,          //!< PICC compliant with ISO/IEC 14443-4
    ISO_18092,            //!< PICC compliant with ISO/IEC 18092 (NFC)
    NotCompleted = 0xFF,  //!< SAK indicates UID is not complete
};

//! @brief Is type MIFARE Classic?
inline bool is_classic(const Type t)
{
    return t >= Type::MIFARE_Classic && t <= Type::MIFARE_Classic_4K;
}

//! @brief Is type MIFARE?
inline bool is_mifare(const Type t)
{
    return t >= Type::MIFARE_Classic && t <= Type::MIFARE_DESFire_8K;
}

//! @brief Is type NTAG?
inline bool is_ntag(const Type t)
{
    return t >= Type::NTAG_203 && t <= Type::NTAG_216;
}

//! @brief Does the specified type function as NFC?
inline bool supports_NFC(const Type t)
{
    return t == Type::MIFARE_UltraLight || t == Type::MIFARE_UltraLightC ||  // Light/C
           is_ntag(t);
}

//! @brief Has FAST_READ command?
inline bool has_fast_read(const Type t)
{
    return t >= Type::NTAG_210 && t <= Type::NTAG_216;
}

/*!
  @brief Get type from SAK
  @param sak SAK
  @return Type
  @warning Some types cannot be determined by SAK alone
 */
Type get_type(const uint8_t sak);

//! @brief SAK uncompleted?
inline bool has_sak_dependent_bit(const uint8_t sak)
{
    return (sak & 0x04);
}
//! @brief SAK completed? (Complies with ISO/IEC 14443-4)
inline bool is_sak_completed_14443_4(const uint8_t sak)
{
    return ((sak & 0x24) == 0x20);
}
//! @brief SAK completed? (Does not comply with ISO/IEC 14443-4)
inline bool is_sak_completed(const uint8_t sak)
{
    return ((sak & 0x24) == 0x00);
}

//! @brief Get the number of the blocks
uint16_t get_number_of_blocks(const Type t);
//! @brief Get the number of the sectors
uint8_t get_number_of_sectors(const Type t);
//! @brief Get the first user area block
uint8_t get_first_user_block(const Type t);
//! @brief Get the last user area block
uint8_t get_last_user_block(const Type t);
//! @brief Gets the number of the user blocks
uint8_t get_user_block_size(const Type t);
//! @brief  Is block user area?
bool is_user_block(const Type t, const uint8_t block);

//! @brief Calculate bcc8
uint8_t calculate_bcc8(const uint8_t* data, const uint32_t len);

/*!
  @struct UID
  @brief The UID of the PICC
 */
struct UID {
    //! @brief PICC type
    Type type{};
    //! @brief  UID size 4, 7 or 10.
    uint8_t size{};
    //! @brief  The SAK (Select acknowledge) returned from the PICC after successful selection
    uint8_t sak{};
    //! @brief uid data (Valid up to the value of size)
    uint8_t uid[10]{};
    //! @brief The number of the blocks or pages
    uint16_t blocks{};

    //! @brief Valid?
    inline bool valid() const
    {
        return size && (type != Type::Unknown) && blocks;
    }
    //! @brief Is MIFARE?
    inline bool isMifare() const
    {
        return valid() && is_mifare(type);
    }
    //! @brief Is MIFARE classic?
    inline bool isMifareClassic() const
    {
        return valid() && is_classic(type);
    }
    //! @brief Is NTAG?
    inline bool isNTAG() const
    {
        return valid() && is_ntag(type);
    }

    //! @brief Supports NFC tag?
    inline bool supportsNFC() const
    {
        return valid() && supports_NFC(type);
    }
    //! @brief Can use FAST_READ command?
    inline bool canFastRead() const
    {
        return valid() && has_fast_read(type);
    }
    //! @brief clear
    void clear()
    {
        size = sak = blocks = 0;
        type                = Type::Unknown;
        std::memset(uid, 0x00, sizeof(uid));
    }
    //! @brief Retrieve the last 4 bytes
    void tail4(uint8_t buf[4]) const
    {
        if (buf) {
            memcpy(buf, uid + size - 4, 4);
        }
    }
    //! @breif Gets the uid string for debug
    std::string uidAsString() const;
    //! @breif Gets the type string for debug
    std::string typeAsString() const;
};

//! @brief Equal?
inline bool operator==(const UID& a, const UID& b)
{
    return (a.size == b.size) && (a.sak == b.sak) && (a.type == b.type) && (a.blocks == b.blocks) &&
           std::memcmp(a.uid, b.uid, 10) == 0;
}
//! @brief Not equal?
inline bool operator!=(const UID& a, const UID& b)
{
    return !(a == b);
}

/*!
  @struct ATQA
  @brief Answer To Request, Type A
 */
struct ATQA {
    // single:4 double:7 triple:10 error:0
    inline uint8_t uidLength() const
    {
        uint8_t ulen = ((value[0] >> 6) & 0x03);
        return (ulen != 0x03) ? 3 + ulen * 3 + 1 : 0;
    };
    // Anti-collision bit frame
    inline uint8_t bitFrame() const
    {
        return value[0] & 0x1F;
    }
    inline void clear()
    {
        value[0] = value[1] = 0;
    }

    uint8_t value[2]{};  // Litte endian 16bit
};

/*!
  @enum Command
  @brief ISO-14443-3/4,MIFARE,NTAG commands
 */
enum class Command : uint8_t {
    // ISO/IEC 14443-3
    REQA          = 0x26,  //!< Reequest
    WUPA          = 0x52,  //!< Wake-up
    HLTA          = 0x50,  //!< Halt
    SELECT_CL1    = 0x93,  //!< Anticollison/Select CL1
    SELECT_CL2    = 0x95,  //!< Anticollison/Select CL2
    SELECT_CL3    = 0x97,  //!< Anticollison/Select CL3
    SELCT_CL1_OPT = 0x92,  //!< Select cascade level 1 and swich bit rate to fc/64 after receive SAK
    SELCT_CL2_OPT = 0x94,  //!< Select cascade level 2 and swich bit rate to fc/64 after receive SAK
    SELCT_CL3_OPT = 0x96,  //!< Select cascade level 2 and swich bit rate to fc/64 after receive SAK
    // ISO/IEC 14443-4
    RATS = 0x0E,  //!< Request for Answer to Select
    // MIFARE
    AUTH_WITH_KEY_A = 0x60,  //!< MIFARE Classic. Authentication with Key A
    AUTH_WITH_KEY_B = 0x61,  //!< MIFARE Classic. Authentication with Key B
    AUTHENTICATE_1  = 0x1A,  //!< MIFARE UltraLight/C. Authentication 1st
    AUTHENTICATE_2  = 0xAF,  //!< MIFARE UltraLight/C. Authentication 2nd
    READ            = 0x30,  //!< MIFARE. read
    WRITE           = 0xA0,  //!< MIFARE. write
    DECREMENT       = 0xC0,  //!< MIFARE Classic. decrement value block
    INCREMENT       = 0xC1,  //!< MIFARE Classic. increment value block
    RESTORE         = 0xC2,  //!< MIFARE Classic. reads the contents of a value block into the internal Transfer Buffer
    TRANSFER        = 0xB0,  //!< MIFARE Classic. writes the contents of the internal Transfer Buffer to a block
    PERSONALIZE_UID_USAGE = 0x40,  //!< MIFARE Classic Personalize UID Usage
    SET_MOD_TYPE          = 0x43,  //!< MIFARE Classic SET_MOD_TYPE
    WRITE_UL              = 0xA2,  //!< MIFARE UltraLight/C and NTAG write
    // NTAG
    GET_VERSION = 0x60,  //!< NTAG 21x. Gets the version information
    FAST_READ   = 0x3A,  //!< NTAG 21x excluding 210u. Read multiple pages
    READ_CNT    = 0x39,  //!< NTAG 213/5/6. Read counter value
    PWD_AUTH    = 0x1B,  //!< NTAG 21x excluding 210u. Authentication for protected area
    READ_SIG    = 0x3C,  //!< NTAG 21x Read NXP ECC signature
    WRITE_SIG   = 0xA9,  //!< NTAG 210u Write custom signature
    LOCK_SIG    = 0xAC,  //!< NTAG 210u Lock/Unlock signature
};

///@name Timeout
///@{
constexpr uint32_t TIMEOUT_REQ_WUP{4};
constexpr uint32_t TIMEOUT_SELECT{4};
constexpr uint32_t TIMEOUT_ANTICOLL{8};
constexpr uint32_t TIMEOUT_HALT{2};
constexpr uint32_t TIMEOUT_GET_VERSION{5};
constexpr uint32_t TIMEOUT_3DES{10};
constexpr uint32_t TIMEOUT_AUTH1{2};
constexpr uint32_t TIMEOUT_AUTH2{10};
constexpr uint32_t TIMEOUT_READ{4};
constexpr uint32_t TIMEOUT_WRITE1{5};
constexpr uint32_t TIMEOUT_WRITE2{10};
constexpr uint32_t TIMEOUT_OP{5};  // Inc/Dec/Restore...
///@}

}  // namespace a
}  // namespace nfc
}  // namespace m5

#endif
