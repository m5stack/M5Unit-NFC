/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file ndef.hpp
  @brief NDEF related
*/
#ifndef M5_UNIT_UNIFIED_NFC_NDEF_NDEF_HPP
#define M5_UNIT_UNIFIED_NFC_NDEF_NDEF_HPP

#include <cstdint>
#include <vector>
#include <m5_utility/stl/extension.hpp>

namespace m5 {
namespace nfc {
/*!
  @namespace ndef
  @brief For NDEF
 */
namespace ndef {

///@name CapabilityContainer
///@{
constexpr uint8_t NDEF_MAJOR_VERSION{1};     //!< Support major version
constexpr uint8_t NDEF_MINOR_VERSION{0};     //!< Support minor version
constexpr uint8_t MAGIC_NO_CC4{0xE1};        //!< 4 byte CC
constexpr uint8_t MAGIC_NO_CC8{0xE2};        //!< 8 byte CC (Type5)
constexpr uint8_t ACCESS_FREE{0x00};         //!< Access condition (Free access)
constexpr uint8_t ACCESS_PROPRIETARY{0x02};  //!< Access condition (proprietary)

constexpr uint8_t TYPE2_CC_BLOCK{3};           //!< Block for CC type2
constexpr uint16_t CC4_MAX_NDEF_LENGTH{2040};  //!< Maximum ndef length for 4 byte CC
///@}

/*!
  @enum Tag
  @brief TLV(Tag,Length,Value) tag for type2/5
 */
enum class Tag : uint8_t {
    Null,                //!< NULL TLV
    LockControl,         //!< Lock control
    MemoryControl,       //!< Memory control
    Message,             //!< Message
    Proprietary = 0xFD,  //!< Proprietary
    Terminator           //!< Terminator
};

/*!
  @typedef TagBits
  @brief TLV(Tag,Length,Value) tag bit group for type2/5
*/
using TagBits = uint8_t;

//! @brief Tag to TagBit
constexpr inline TagBits tag_to_tagbit(const Tag t)
{
    return (t == Tag::Null)            ? (1u << 0)
           : (t == Tag::LockControl)   ? (1u << 1)
           : (t == Tag::MemoryControl) ? (1u << 2)
           : (t == Tag::Message)       ? (1u << 3)
           : (t == Tag::Proprietary)   ? (1u << 4)
           : (t == Tag::Terminator)    ? (1u << 5)
                                       : 0u;
}

///@cond
template <typename... Ts>
struct are_all_tag : std::true_type { /**/
};
template <typename T, typename... Ts>
struct are_all_tag<T, Ts...> : std::integral_constant<bool, std::is_same<Tag, T>::value && are_all_tag<Ts...>::value> {
};

constexpr TagBits make_tag_bits_impl(TagBits acc)
{
    return acc;
}

template <typename... Rest>
constexpr TagBits make_tag_bits_impl(TagBits acc, Tag head, Rest... rest)
{
    return make_tag_bits_impl(acc | tag_to_tagbit(head), rest...);
}
///@endcond

/*!
  @brief Make TagBit from tag
  @param tags Tag(s)
  @return TagBit
 */
template <typename... T>
constexpr TagBits make_tag_bits(T... tags)
{
    static_assert(sizeof...(tags) > 0, "At least one Tag is required");
    static_assert(are_all_tag<T...>::value, "Arguments must be Tag");
    return make_tag_bits_impl(0u, tags...);
}

//! @brief Check whether TagBits contains given Tag
inline constexpr bool contains_tag(const TagBits tb, const Tag t)
{
    return (tb & tag_to_tagbit(t)) != 0;
}

//! @brief All tags
constexpr TagBits tagBitsAll =
    make_tag_bits(m5::nfc::ndef::Tag::LockControl, m5::nfc::ndef::Tag::MemoryControl, m5::nfc::ndef::Tag::Message,
                  m5::nfc::ndef::Tag::Proprietary, m5::nfc::ndef::Tag::Terminator);
//! @brief Message only
constexpr TagBits tagBitsMessage = make_tag_bits(m5::nfc::ndef::Tag::Message);

//! @brief Is valid tag?
inline bool is_valid_tag(const uint8_t t)
{
    return t <= m5::stl::to_underlying(Tag::Message) || t == m5::stl::to_underlying(Tag::Proprietary) ||
           t == m5::stl::to_underlying(Tag::Terminator);
}

//! @brief Is terminator?
inline bool is_terminator_tag(const uint8_t t)
{
    return t == m5::stl::to_underlying(Tag::Terminator);
}

/*!
  @enum URIProtocol
  @brief URI Identifier Code
 */
enum class URIProtocol : uint8_t {
    NA,           //!< N/A
    HTTP_WWW,     //!< http://www.
    HTTPS_WWW,    //!< https://www.
    HTTP,         //!< http://
    HTTPS,        //!< https://
    TEL,          //!< tel:
    MAILTO,       //!< mailto:
    FTP_AA,       //!< ftp://anonymous:anonymous@
    FTP_FTP,      //!< ftp://ftp.
    FTPS,         //!< ftps://
    SFTP,         //!< sftp://
    SMB,          //!< smb://
    NFS,          //!< nfs://
    FTP,          //!< ftp://
    DEV,          //!< dav://
    NEWS,         //!< news:
    TELNET,       //!< telnet://
    IMAP,         //!< imap:
    RSTP,         //!< rtsp://
    URN,          //!< urn:
    POP,          //!< pop:
    SIP,          //!< sip:
    SIPS,         //!< sips:
    TFTP,         //!< tftp:
    BTSPP,        //!< btspp://
    BTL2CAP,      //!< btl2cap://
    BTGOEP,       //!< btgoep://
    TCPOBEX,      //!< tcpobex://
    IRDAOBEX,     //!< irdaobex://
    FILE,         //!< file://
    URN_EPC_ID,   //!< urn:epc:id:
    URN_EPC_TAG,  //!< urn:epc:tag:
    URN_EPC_PAT,  //!< urn:epc:pat:
    URN_EPC_RAW,  //!< urn:epc:raw:
    URN_EPC,      //!< urn:epc:
    NFC,          //!< urn:nfc:
};

//! @brief Get string of the URI IDC
const char* get_uri_idc_string(const URIProtocol protocol);

/*!
  @namespace type2
  @brief For NDEF Type2
 */
namespace type2 {
/*!
  @struct CapabilityContainer
  @brief Capability container for Type2
 */
struct CapabilityContainer {
    uint8_t block[4]{};

    inline bool valid() const
    {
        return (block[0] == MAGIC_NO_CC4) && (major_version() >= NDEF_MAJOR_VERSION) &&
               ((int16_t)minor_version() >= NDEF_MINOR_VERSION) && ndef_size();
    }
    inline bool can_read() const
    {
        return read_access() == ACCESS_FREE;
    }
    inline bool can_write() const
    {
        return write_access() == ACCESS_FREE;
    }

    // Getter
    inline uint8_t major_version() const
    {
        return (block[1] >> 4) & 0x0F;
    }
    inline uint8_t minor_version() const
    {
        return block[1] & 0x0F;
    }
    inline uint16_t ndef_size() const
    {
        return (uint16_t)block[2] << 3;
    }
    inline uint8_t read_access() const
    {
        return (block[3] >> 4) & 0x0F;
    }
    inline uint8_t write_access() const
    {
        return block[3] & 0x0F;
    }
    // Setter
    inline void major_version(const uint8_t v)
    {
        block[1] = (block[1] & 0x0F) | ((v & 0x0F) << 4);
    }
    inline void minor_version(const uint8_t v)
    {
        block[1] = (block[1] & 0xF0) | (v & 0x0F);
    }
    inline void ndef_size(const uint16_t sz)
    {
        block[2] = (sz > 2040) ? 0 : (sz >> 3);
    }
    inline void read_access(const uint8_t a)
    {
        block[3] = (block[3] & 0x0F) | ((a & 0x03) << 4);
    }
    inline void write_access(const uint8_t a)
    {
        block[3] = (block[3] & 0xF0) | (a & 0x03);
    }
};
}  // namespace type2

/*!
  @namespace type3
  @brief For NDEF Type3
 */
namespace type3 {
/*!
  @struct AttributeBlock
  @brief For Type 3 tag (T3T)
 */
struct AttributeBlock {
    uint8_t block[16]{};

    static constexpr uint8_t DEFAULT_VERSION{0x10};

    /*!
      @enum WriteFlag
      @brief Flag for fault tolerance
     */
    enum class WriteFlag : uint8_t {
        Done,               //!< Done
        InProgress = 0x0F,  //!< Write in progress
    };

    /*!
      @enum AccessFlag
      @brief Permission to read and write
    */
    enum class AccessFlag : uint8_t {
        ReadOnly,   //!< Allow read only
        ReadWrite,  //!< Allow read and write
    };
    AttributeBlock() : block{DEFAULT_VERSION}
    {
    }

    // Getter
    inline uint8_t version() const
    {
        return block[0];
    }
    inline uint8_t max_block_to_read() const
    {
        return block[1];
    }
    inline uint8_t max_block_to_write() const
    {
        return block[2];
    }
    inline uint16_t blocks_for_ndef_storage() const
    {
        return ((uint16_t)block[3] << 8) | block[4];
    }
    inline WriteFlag write_flag() const
    {
        return (block[9] == 0) ? WriteFlag::Done : WriteFlag::InProgress;
    }
    inline AccessFlag access_flag() const
    {
        return (AccessFlag)block[10];
    }
    inline uint32_t current_ndef_message_length() const
    {
        return ((uint32_t)block[11] << 16) | ((uint32_t)block[12] << 8) | block[13];
    }
    inline uint16_t check_sum() const
    {
        return ((uint16_t)block[14] << 8) | block[15];
    }

    // Setter
    inline void version(const uint8_t ver)
    {
        block[0] = ver;
    }
    inline void max_block_to_read(const uint8_t b)
    {
        block[1] = b;
    }
    inline void max_block_to_write(const uint8_t b)
    {
        block[2] = b;
    }
    inline void blocks_for_ndef_storage(const uint16_t s)
    {
        block[3] = s >> 8;
        block[4] = s & 0xFF;
    }
    inline void write_flag(const WriteFlag f)
    {
        block[9] = m5::stl::to_underlying(f);
    }
    inline void access_flag(const AccessFlag f)
    {
        block[10] = m5::stl::to_underlying(f);
    }
    inline void current_ndef_message_length(const uint32_t len)
    {
        block[11] = len >> 16;
        block[12] = len >> 8;
        block[13] = len & 0xFF;
    }

    //
    bool valid() const;
    uint16_t calculate_check_sum() const;
    uint16_t update_check_sum();
};

}  // namespace type3

/*!
  @namespace type4
  @brief For NDEF Type4
 */
namespace type4 {

constexpr uint16_t CC_FILE_ID{0xE103};                                      //!< CC file id
constexpr uint8_t NDEF_AID[] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};  //!< AID for NDEF
constexpr uint16_t NDEF_APP_FID{0xE110};                                    //!< ISO DF FID for NDEF app
constexpr uint16_t NDEF_FILE_ID{0xE104};                                    //!< ISO EF FID for NDEF file

/*!
  @enum FileControlTag
  @brief File control for File Control TLV for type4
 */
enum class FileControlTag : uint8_t {
    Message     = 0x04,  //!< Message
    Proprietary = 0x05,  //!< Proprietary
    //    Extended    = 0x06,  //!< Extended NDEF (Over 32KB) Type 4 Tag Specification v2.0 or later
};

/*!
  @typedef FileControTagBlits
  @brief File control TLV tag bit group for type4
*/
using FileControlTagBits = uint8_t;

//! @brief Tag to TagBit
constexpr inline FileControlTagBits fc_to_fcbit(const FileControlTag t)
{
    return (t == FileControlTag::Message) ? (1u << 0) : ((t == FileControlTag::Proprietary) ? (1u << 1) : 0u);
}

///@cond
template <typename... Ts>
struct are_all_fc : std::true_type { /**/
};
template <typename T, typename... Ts>
struct are_all_fc<T, Ts...>
    : std::integral_constant<bool, std::is_same<FileControlTag, T>::value && are_all_fc<Ts...>::value> { /**/
};

constexpr FileControlTagBits make_fc_bits_impl(FileControlTagBits acc)
{
    return acc;
}

template <typename... Rest>
constexpr FileControlTagBits make_fc_bits_impl(FileControlTagBits acc, FileControlTag head, Rest... rest)
{
    return make_fc_bits_impl(acc | fc_to_fcbit(head), rest...);
}
///@endcond

/*!
  @brief Make FileControlBit from FileControlTag
  @param fcs FileControl(s)
  @return FcBit
 */
template <typename... T>
constexpr FileControlTagBits make_fc_bits(T... fcs)
{
    static_assert(sizeof...(fcs) > 0, "At least one Fc is required");
    static_assert(are_all_fc<T...>::value, "Arguments must be Fc");
    return make_fc_bits_impl(0u, fcs...);
}

//! @brief Check whether FileControlTagBits contains given FileControl
inline constexpr bool contains_file_control_tag(const FileControlTagBits tb, const FileControlTag t)
{
    return (tb & fc_to_fcbit(t)) != 0;
}

//! @brief All fcs
constexpr FileControlTagBits fcBitsAll = make_fc_bits(FileControlTag::Message, FileControlTag::Proprietary);
//! @brief Message only
constexpr FileControlTagBits fcBitsMessage = make_fc_bits(FileControlTag::Message);

/*!
  @struct FileControlTLV
  @brief File control TLV
*/
struct FileControlTLV {
    uint8_t tag{};              //!< File control tag
    uint8_t len{};              //!< Length
    uint16_t ndef_file_id{};    //!< NDEF file ID
    uint16_t ndef_file_size{};  //!< NDEF file size
    uint8_t read_access{};      //!< Read access
    uint8_t write_access{};     //!< Write access

    inline FileControlTag fctag() const
    {
        return static_cast<FileControlTag>(this->tag);
    }
};

/*!
  @struct CapabilityContainer
  @brief Capability container for Type4
 */
struct CapabilityContainer {
    uint16_t cclen{};           //!< CC length
    uint8_t mapping_version{};  //!< Mapping version
    uint16_t mle{};             //!< Maximum Le
    uint16_t mlc{};             //!< Maximum Lc
    std::vector<FileControlTLV> fctlvs{};

    inline uint8_t major_version() const
    {
        return (mapping_version >> 4) & 0x0F;
    }
    inline uint8_t minor_version() const
    {
        return mapping_version & 0x0F;
    }
    inline bool valid() const
    {
        return cclen > 7 && !this->fctlvs.empty();
    }

    inline FileControlTLV fctlv(const uint8_t index) const
    {
        return index < this->fctlvs.size() ? this->fctlvs[index] : FileControlTLV{};
    }
    FileControlTLV fctlv(const FileControlTag fc = FileControlTag::Message) const;

    bool parse(const uint8_t* buf, const uint16_t len);
};

}  // namespace type4

/*!
  @namespace type5
  @brief For NDEF Type5
 */
namespace type5 {
/*!
  @struct CapabilityContainer
  @brief Capability container for Type5
 */
struct CapabilityContainer {
    uint8_t block[8]{};

    inline bool valid() const
    {
        return ((block[0] == MAGIC_NO_CC4) || (block[0] == MAGIC_NO_CC8)) && (major_version() >= NDEF_MAJOR_VERSION) &&
               ((int16_t)minor_version() >= NDEF_MINOR_VERSION) && ndef_size();
    }
    inline bool can_read() const
    {
        return read_access() == ACCESS_FREE;
    }
    inline bool can_write() const
    {
        return write_access() == ACCESS_FREE;
    }
    inline uint8_t size() const
    {
        return (block[0] == MAGIC_NO_CC4) ? 4 : ((block[0] == MAGIC_NO_CC8) ? 8 : 0);
    }
    // Getter
    inline uint8_t major_version() const
    {
        return (block[1] >> 6) & 0x03;
    }
    inline uint8_t minor_version() const
    {
        return (block[1] >> 4) & 0x03;
    }
    inline uint16_t ndef_size() const
    {
        return (block[0] == MAGIC_NO_CC4)   ? (((uint16_t)block[2]) << 3)
               : (block[0] == MAGIC_NO_CC8) ? (((uint16_t)block[6] << 8) | block[7])
                                            : 0;
    }
    inline uint8_t read_access() const
    {
        return (block[1] >> 2) & 0x03;
    }
    inline uint8_t write_access() const
    {
        return block[1] & 0x03;
    }
    inline uint8_t additional_feature() const
    {
        return block[3];
    }
    // Setter
    inline void major_version(const uint8_t v)
    {
        block[1] = (block[1] & 0x3F) | ((v & 0x03) << 6);
    }
    inline void minor_version(const uint8_t v)
    {
        block[1] = (block[1] & 0xCF) | ((v & 0x03) << 4);
    }
    inline void ndef_size(const uint16_t sz)
    {
        if (block[0] == MAGIC_NO_CC4 && sz <= 2040) {
            block[2] = (sz >> 3);
        } else if (block[0] == MAGIC_NO_CC8) {
            block[6] = (sz >> 8);
            block[7] = sz & 0xFF;
        }
    }
    inline void read_access(const uint8_t a)
    {
        block[1] = (block[1] & 0xF3) | ((a & 0x03) << 2);
    }
    inline void write_access(const uint8_t a)
    {
        block[1] = (block[1] & 0xFC) | (a & 0x03);
    }
    inline void additional_feature(const uint8_t af)
    {
        block[3] = af;
    }
};
}  // namespace type5

}  // namespace ndef
}  // namespace nfc
}  // namespace m5

#endif
