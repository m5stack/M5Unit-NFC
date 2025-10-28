/*
 * SPDX-FileCopyrightText: 2024 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file ndef.hpp
  @brief NDEF related
*/
#ifndef M5_UNIT_RFID_RFID_NFC_NDEF_HPP
#define M5_UNIT_RFID_RFID_NFC_NDEF_HPP

#include <cstdint>
#include <m5_utility/stl/extension.hpp>

namespace m5 {
namespace nfc {
/*!
  @namespace ndef
  @brief For NDEF
 */
namespace ndef {

/*!
  @enum Tag
  @brief TLV(Tag,Length,Value) tag for NDEF Message
 */
enum class Tag : uint8_t {
    Null,                //!< NULL TLV
    LockControl,         //!< Lock control
    MemoryControl,       //!< Memory control
    NDEFMessage,         //!< NDEF container
    Proprietary = 0xFD,  //!< Proprietary
    Terminator           //!< Terminator
};

//! @brief Is valid tag?
inline bool is_valid_tag(const uint8_t t)
{
    return t <= m5::stl::to_underlying(Tag::NDEFMessage) || t == m5::stl::to_underlying(Tag::Proprietary) ||
           t == m5::stl::to_underlying(Tag::Terminator);
}

//! @brief Is terminator?
inline bool is_terminator_tag(const uint8_t t)
{
    return t == m5::stl::to_underlying(Tag::Terminator);
}

/*!
  @enum TNF
  @brief Type Name Field for NDEF Record
 */
enum class TNF : uint8_t {
    Empty,      //!< Empry
    Wellknown,  //!< NFC Forum well-known-type
    Media,      //!< Media-type as define in RFC2046
    URI,        //!< Absolute URI as define in RFC3986
    External,   //!< NFC Forum external type
    Unknown,    //!< Unknown
    Unchanged,  //!< Unchanged
    Reserved,   //!< Reserved
};

/*!
  @struct Attribute
  @brief NDEF Record attribute (1st byte)
 */
struct Attribute {
    ///@name Bit field
    ///@{
    static constexpr uint8_t MB{0x80};  //!< Message Begin
    static constexpr uint8_t ME{0x40};  //!< Message End
    static constexpr uint8_t CF{0x20};  //!< Chunked Flag
    static constexpr uint8_t SR{0x10};  //!< Short Flag
    static constexpr uint8_t IL{0x08};  //!< ID Length (If disabled (specified as 0), ID LENGTH and ID can be omitted)
    static constexpr uint8_t TNF_MASK{0x07};  //!< Type Name Format
    ///@}

    ///@name Getter
    ///@{
    inline bool messageBegin() const
    {
        return value & MB;
    }
    inline bool messageEnd() const
    {
        return value & ME;
    }
    inline bool chunk() const
    {
        return value & CF;
    }
    inline bool shortRecord() const
    {
        return value & SR;
    }
    inline bool idLength() const
    {
        return value & IL;
    }
    inline TNF tnf() const
    {
        return static_cast<TNF>(value & TNF_MASK);
    }
    ///@}

    ///@name Setter
    ///@{
    inline void messageBegin(const bool b)
    {
        value = (value & ~MB) | (b ? MB : 0);
    }
    inline void messageEnd(const bool b)
    {
        value = (value & ~ME) | (b ? ME : 0);
    }
    inline void chunk(const bool b)
    {
        value = (value & ~CF) | (b ? CF : 0);
    }
    inline void shortRecord(const bool b)
    {
        value = (value & ~SR) | (b ? SR : 0);
    }
    inline void idLength(const bool b)
    {
        value = (value & ~IL) | (b ? IL : 0);
    }
    inline void tnf(const TNF t)
    {
        value = (value & ~TNF_MASK) | (m5::stl::to_underlying(t) & TNF_MASK);
    }
    ///@}

    uint8_t value{};
};

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

}  // namespace ndef
}  // namespace nfc
}  // namespace m5

#endif
