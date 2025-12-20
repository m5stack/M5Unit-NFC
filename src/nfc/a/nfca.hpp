/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfca.hpp
  @brief NFC-A definitions
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_A_NFCA_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_A_NFCA_HPP

#include "nfc/nfc.hpp"
#include "mifare.hpp"
#include <cstdint>
#include <string>
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
  @brief Type of the PICC
 */
enum class Type : uint8_t {
    Unknown,  //!< Unknown type

    MIFARE_Classic_Mini,  //!< Also known as MIFARE Standard mini
    MIFARE_Classic_1K,    //!< Also known as MIFARE Standard 1K
    MIFARE_Classic_2K,    //!< Also known as MIFARE Standard 2K
    MIFARE_Classic_4K,    //!< Also known as MIFARE Standard 4K

    MIFARE_Ultralight,        //!< MIFARE Ultralight
    MIFARE_Ultralight_EV1_1,  //!< MIFARE Ultralight EV1 MF0UL11
    MIFARE_Ultralight_EV1_2,  //!< MIFARE Ultralight EV1 MF0UL21
    MIFARE_Ultralight_Nano,   //!< MIFARE Ultralight Nano
    MIFARE_UltralightC,       //!< MIFARE UltralightC

    NTAG_203,   //!< NATG 203
    NTAG_210u,  //!< NTAG 210μ
    NTAG_210,   //!< NTAG 210
    NTAG_212,   //!< NTAG 212
    NTAG_213,   //!< NTAG 213
    NTAG_215,   //!< NTAG 215
    NTAG_216,   //!< NTAG 216

    ST25TA_2K,   //!< ST25TA02K
    ST25TA_16K,  //!< ST25TA16K
    ST25TA_64K,  //!< ST25TA64K

    ISO_14443_4,  //!< PICC compliant with ISO/IEC 14443-4

    MIFARE_Plus_2K,  //!< MIFARE Plus 2K
    MIFARE_Plus_4K,  //!< MIFARE Plus 4K
    MIFARE_Plus_SE,  //!< MIFARE Plus SE 1K

    MIFARE_DESFire_2K,     //!< MIFARE DESFire 2K
    MIFARE_DESFire_4K,     //!< MIFARE DESFire 4K
    MIFARE_DESFire_8K,     //!< MIFARE DESFire 8K
    MIFARE_DESFire_Light,  //!< MIFARE DESFire Light

    NTAG_4XX,  //!< NTAG 4XX

    ISO_18092,  //!< PICC compliant with ISO/IEC 18092

    NotCompleted = 0xFF,  //!< SAK indicates UID is not complete
};

enum class SubTypePlus : uint8_t {
    None,
    EV1,
    EV2,
    S,
    X,
};

enum SubTypeDESFire : uint8_t {
    None,
    EV1,
    EV2,
    EV3,
};

//! @brief Get NFC Forum Tag Type from PICC type
m5::nfc::NFCForumTag get_nfc_forum_tag_type(const Type t);

//! @brief Is type MIFARE Classic?
inline bool is_mifare_classic(const Type t)
{
    return t >= Type::MIFARE_Classic_Mini && t <= Type::MIFARE_Classic_4K;
}

//! @brief Is type MIFARE Ultralight series?
inline bool is_mifare_ultralight(const Type t)
{
    return t >= Type::MIFARE_Ultralight && t <= Type::MIFARE_UltralightC;
}

//! @brief Is type NTAG?
inline bool is_ntag(const Type t)
{
    return t >= Type::NTAG_203 && t <= Type::NTAG_216;
}

//! @brief Is type MIFARE Plus?
inline bool is_mifare_plus(const Type t)
{
    return t >= Type::MIFARE_Plus_2K && t <= Type::MIFARE_Plus_SE;
}

//! @brief Is type MIFARE DESFire?
inline bool is_mifare_desfire(const Type t)
{
    return t >= Type::MIFARE_DESFire_2K && t <= Type::MIFARE_DESFire_Light;
}

//! @brief Is type MIFARE?
inline bool is_mifare(const Type t)
{
    return is_mifare_classic(t) || is_mifare_ultralight(t) || is_mifare_plus(t) || is_mifare_desfire(t);
}

//! @brief Is ISO 14443-4?
inline bool is_iso14443_4(const Type t)
{
    return is_mifare_plus(t) || is_mifare_desfire(t) || (t == Type::ISO_14443_4);
}

//! @brief Is ISO 14443-3?
inline bool is_iso14443_3(const Type t)
{
    return !is_iso14443_4(t);
}

//! @brief Does the specified type function as NFC?
inline bool supports_NFC(const Type t)
{
    return (t >= Type::MIFARE_Ultralight && t <= Type::MIFARE_UltralightC) || is_ntag(t);
}

//! @brief Has FAST_READ command?
inline bool has_fast_read(const Type t)
{
    return t >= Type::NTAG_210 && t <= Type::NTAG_216;
}

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

/*!
  @brief Inferring the type from SAK
  @return Type
  @warning This is a preliminary diagnosis, a more accurate diagnosis is required
 */
Type sak_to_type(const uint8_t sak);
//!  @brief Inferring the type from GetVersion L3
Type version3_to_type(const uint8_t info[8]);
//!  @brief Inferring the type from GetVersion L4
Type version4_to_type(uint8_t& sub, const uint8_t info[8]);
//! @brief Historical bytes to type on SAK 0x18
Type historical_bytes_to_type_sak18(uint8_t& sub, const uint8_t* bytes, const uint8_t len);
//! @brief Historical bytes to type on SAK 0x08
Type historical_bytes_to_type_sak08(uint8_t& sub, const uint8_t* bytes, const uint8_t len);
//! @brief Historical bytes to type on SAK 0x20
Type historical_bytes_to_type_sak20(uint8_t& sub, const uint8_t* bytes, const uint8_t len, const uint16_t atqa);

//! @brief Gets the number of blocks
uint16_t get_number_of_blocks(const Type t);
//! @brief Gets the number of user blocks
uint16_t get_number_of_user_blocks(const Type t);
//!@brief Gets the user area bytes
uint16_t get_user_area_size(const Type t);
/*!
  @brief Get the unit size of 1 block / 1 page
  @retval != 0 Unit size
  @retval == 0 Does not have a unit size
*/
uint16_t get_unit_size(const Type t);
//! @brief Gets the number of sectors
uint16_t get_number_of_sectors(const Type t);
//! @brief Gets the first user area block
uint16_t get_first_user_block(const Type t);
//! @brief Gets the last user area block
uint16_t get_last_user_block(const Type t);
//! @brief Is block user area?
bool is_user_block(const Type t, const uint16_t block);

//! @brief Calculate bcc8
uint8_t calculate_bcc8(const uint8_t* data, const uint32_t len);

/*!
  @struct ATS
  @brief Answer to request
 */
struct ATS {
    union {
        uint8_t header[5]{};
        struct {
            uint8_t tl;   // length
            uint8_t t0;   // format
            uint8_t ta1;  // interface DS/DR
            uint8_t tb1;  // interface FWI/SFGI
            uint8_t tc1;  // code protocol options
        };
    };
    std::array<uint8_t, 32> historical{};
    uint8_t historical_len{};
#if 0
    //
    uint8_t fsci{};        // (T0 under 4bit)
    uint16_t fsd{};        // Frame Size Device
    uint16_t fsc{};        // Frame Size Card
    uint8_t supportedD{};  // bitRate combo  (106/212/424/848)
    bool supportsCID{};
    bool supportsNAD{};
#endif

    Type identify() const;
};

/*!
  @struct PICC
  @brief PICC for NFC-A
 */
struct PICC {
    uint8_t _pad{};
    Type type{};        //!< PICC type
    uint8_t sak{};      //!< The SAK (Select acknowledge) returned from the PICC after successful selection
    uint8_t size{};     //!<  UID size 4, 7 or 10.
    uint8_t uid[10]{};  //!< uid (Valid up to the value of size)
    uint16_t atqa{};    //!< ATQA
    uint16_t blocks{};  //!< Number of the blocks or pages
    ATS ats{};          //!< RATS for ISO 14443-4
    union {
        uint8_t sub_type{};               //!< uint8_t access
        SubTypePlus sub_type_plus;        //!< For Plus
        SubTypeDESFire sub_type_desfire;  //!< For DESFire
    };  //!< SubType for Plus/DESFire;
    union {
        uint8_t security_level{};  //!< Security level for Plus
    };  //!< Optional information

    //! @brief Valid?
    inline bool valid() const
    {
        return (size == 4 || size == 7 || size == 10) && (type != Type::Unknown) && (isISO14443_4() || blocks);
    }
    //! @brief Retrieve the last 4 bytes of UID
    void tail4(uint8_t buf[4]) const
    {
        if (buf) {
            memcpy(buf, uid + size - 4, 4);
        }
    }
    std::string uidAsString() const;   //!< @brief Gets the uid string
    std::string typeAsString() const;  //!< @brief Gets the type string

    /*!
      @brief Emulation settings
      @param t Type
      @param uid UID
      @param uid_len UID length (4,7,10)
      @return True if successful
     */
    bool emulate(const Type t, const uint8_t* uid, const uint8_t uid_len);

    ///@name Type
    ///@{
    //! @brief Is MIFARE?
    inline bool isMifare() const
    {
        return is_mifare(type);
    }
    //! @brief Is MIFARE classic?
    inline bool isMifareClassic() const
    {
        return is_mifare_classic(type);
    }
    //! @brief Is MIFARE Ultralight series?
    inline bool isMifareUltralight() const
    {
        return is_mifare_ultralight(type);
    }
    //! @brief Is MIFARE Plus?
    inline bool isMifarePlus() const
    {
        return is_mifare_plus(type);
    }
    //! @brief Is MIFARE DESFire?
    inline bool isMifareDESFire() const
    {
        return is_mifare_desfire(type);
    }
    //! @brief Is NTAG?
    inline bool isNTAG() const
    {
        return is_ntag(type);
    }
    inline bool isISO14443_4() const
    {
        return is_iso14443_4(type);
    }
    ///@}

    ///@name Information
    ///@{
    //! @brief Total size
    inline uint16_t totalSize() const
    {
        return valid() ? get_number_of_blocks(type) * get_unit_size(type) : 0;
    }
    //! @brief Total user area size
    inline uint16_t userAreaSize() const
    {
        return valid() ? get_user_area_size(type) : 0;
    }
    //! @brief Read/Write unit size
    inline uint16_t unitSize() const
    {
        return valid() ? get_unit_size(type) : 0;
    }

    //! @brief Gets the first user block/page address
    inline uint16_t firstUserBlock() const
    {
        return valid() ? get_first_user_block(type) : 0xFFFF;
    }
    inline uint16_t lastUserBlock() const
    {
        return valid() ? get_last_user_block(type) : 0xFFFF;
    }
    //! @brief Is user block?
    inline bool isUserBlock(const uint8_t block) const
    {
        return valid() ? is_user_block(type, block) : false;
    }

    //! @brief NFC ForumTag
    inline NFCForumTag nfcForumTagType() const
    {
        return get_nfc_forum_tag_type(type);
    }
    ///@}

    ///@name Capability
    ///@{
    //! @brief Supports NFC?
    inline bool supportsNFC() const
    {
        return valid() && supports_NFC(type);
    }
    //! @brief Can use FAST_READ command?
    inline bool canFastRead() const
    {
        return valid() && has_fast_read(type);
    }
    ///@}
};

//! @brief Equal?
inline bool operator==(const PICC& a, const PICC& b)
{
    return (a.size == b.size) && (a.sak == b.sak) && (a.type == b.type) && (a.blocks == b.blocks) &&
           std::memcmp(a.uid, b.uid, 10) == 0;
}
//! @brief Not equal?
inline bool operator!=(const PICC& a, const PICC& b)
{
    return !(a == b);
}

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
    SELCT_CL1_OPT = 0x92,  //!< Select CL1 and swich bit rate to fc/64 after receive SAK
    SELCT_CL2_OPT = 0x94,  //!< Select CL2 and swich bit rate to fc/64 after receive SAK
    SELCT_CL3_OPT = 0x96,  //!< Select CL3 and swich bit rate to fc/64 after receive SAK
    READ          = 0x30,  //!< Read
    // ISO/IEC 14443-4
    RATS     = 0xE0,  //!< Request for Answer to Select
    DESELECT = 0xC2,  //!< DESELECT
    // MIFARE
    AUTH_WITH_KEY_A = 0x60,  //!< MIFARE Classic. Authentication with Key A
    AUTH_WITH_KEY_B = 0x61,  //!< MIFARE Classic. Authentication with Key B
    AUTHENTICATE_1  = 0x1A,  //!< MIFARE UltralightC. Authentication 1st
    AUTHENTICATE_2  = 0xAF,  //!< MIFARE UltralightC. Authentication 2nd
    WRITE_BLOCK     = 0xA0,  //!< MIFARE Classic. write
    WRITE_PAGE      = 0xA2,  //!< MIFARE Ultralight/C and NTAG write
    DECREMENT       = 0xC0,  //!< MIFARE Classic. decrement value block
    INCREMENT       = 0xC1,  //!< MIFARE Classic. increment value block
    RESTORE         = 0xC2,  //!< MIFARE Classic. reads the contents of a value block into the internal Transfer Buffer
    TRANSFER        = 0xB0,  //!< MIFARE Classic. writes the contents of the internal Transfer Buffer to a block
    PERSONALIZE_UID_USAGE = 0x40,  //!< MIFARE Classic Personalize UID Usage
    SET_MOD_TYPE          = 0x43,  //!< MIFARE Classic SET_MOD_TYPE
    // NTAG
    GET_VERSION = 0x60,  //!< NTAG 21x/UL EV1,Nano Gets the version information
    FAST_READ   = 0x3A,  //!< NTAG 21x. excluding 210u. Read multiple pages
    READ_CNT    = 0x39,  //!< NTAG 213/5/6. Read counter value
    PWD_AUTH    = 0x1B,  //!< NTAG 21x excluding 210u. Authentication for protected area
    READ_SIG    = 0x3C,  //!< NTAG 21x Read NXP ECC signature
    WRITE_SIG   = 0xA9,  //!< NTAG 210u Write custom signature
    LOCK_SIG    = 0xAC,  //!< NTAG 210u Lock/Unlock signature

};

///@name Timeout
///@{
constexpr uint32_t TIMEOUT_REQ_WUP{4};   // 4
constexpr uint32_t TIMEOUT_SELECT{4};    // 4
constexpr uint32_t TIMEOUT_ANTICOLL{8};  // 8
constexpr uint32_t TIMEOUT_HALT{2};
constexpr uint32_t TIMEOUT_GET_VERSION{5};  // 5
constexpr uint32_t TIMEOUT_3DES{10};
constexpr uint32_t TIMEOUT_AUTH1{2};
constexpr uint32_t TIMEOUT_AUTH2{10};
constexpr uint32_t TIMEOUT_READ{4};
constexpr uint32_t TIMEOUT_FAST_READ{2};
constexpr uint32_t TIMEOUT_FAST_READ_4PAGE{4};    // 3.7
constexpr uint32_t TIMEOUT_FAST_READ_12PAGE{4};   // 3.7
constexpr uint32_t TIMEOUT_FAST_READ_32PAGE{12};  // 11.8
constexpr uint32_t TIMEOUT_WRITE1{5};
constexpr uint32_t TIMEOUT_WRITE2{10};
constexpr uint32_t TIMEOUT_VALUE_BLOCK{5};  // Value block operation
constexpr uint32_t TIMEOUT_RATS{5};
constexpr uint32_t TIMEOUT_DESELECT{5};

///@}

///@name 4bit ACK
///@{
constexpr uint8_t ACK_NIBBLE{0x0A};
///@}

}  // namespace a
}  // namespace nfc
}  // namespace m5

#endif
