/*
 * SPDX-FileCopyrightText: 2024 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file ndef_record.hpp
  @brief NDEF record
*/
#ifndef M5_UNIT_RFID_RFID_NFC_NDEF_RECORD_HPP
#define M5_UNIT_RFID_RFID_NFC_NDEF_RECORD_HPP

#include "ndef.hpp"
#include <vector>
#include <string>

namespace m5 {
namespace nfc {
namespace ndef {

class Message;

/*!
  @class Record
  @brief NDEF Record
  @warning CF is not supported
 */
class Record {
public:
    explicit Record(const TNF tnf = TNF::Wellknown)
    {
        _attr.tnf(tnf);
    }
    ~Record()
    {
    }

    ///@name Attribute
    ///@{
    inline Attribute& attribute()
    {
        return _attr;
    }
    inline const Attribute& attribute() const
    {
        return _attr;
    }
    inline TNF tnf() const
    {
        return _attr.tnf();
    }
    ///@}

    /*!
      @note Well-known NDEF Record Types
    | NDEF Record Type | Description             | Specification Reference                   |
    |------------------|-------------------------|-------------------------------------------|
    | Di               | Device Information      | Device Information Record Type Definition |
    | Gc               | Generic Control         | Generic Control Record Type Definition    |
    | Hc               | Handover Carrier        | Connection Handover                       |
    | Hi               | Handover Initiate       | Connection Handover                       |
    | Hm               | Handover Mediation      | Connection Handover                       |
    | Hr               | Handover Request        | Connection Handover                       |
    | Hs               | Handover Select         | Connection Handover                       |
    | Mr               | Money Transfer Response | NFC Money Transfer                        |
    | Mt               | Money Transfer Request  | NFC Money Transfer                        |
    | PHD              | Personal Health Device  | Personal Health Device Communication      |
    | Sig              | Signature               | Signature Record Type Definition          |
    | Sp               | Smart Poster            | Smart Poster Record Type Definition       |
    | T                | Text                    | Text Record Type Definition               |
    | Te               | TNEP Status             | Tag NDEF Exchange Protocol                |
    | Tp               | Service Parameter       | Tag NDEF Exchange Protocol                |
    | Ts               | Service Select          | Tag NDEF Exchange Protocol                |
    | U                | URI                     | URI Record Type Definition                |
    | V                | Verb                    | Verb Record Type Definition               |
    | WLCCAP           | WLC Capability          | Wireless Charging                         |
    | WLCCTL           | WLC Listen Control      | Wireless Charging                         |
    | WLCFOD           | WLC JiFOD               | Wireless Charging                         |
    | WLCINF           | WLC Poll Information    | Wireless Charging                         |

    If TNF is TNF::Media, type is MIME type string e.g. "text/plain" , "image/png"...
    */
    ///@name Type
    ///@{
    inline const char* type() const
    {
        return _type.c_str();
    }
    inline void setType(const char* s)
    {
        _type = s;
    }
    ///@}

    ///@name Identifier
    ///@{
    //! @brief Gets the identifier size
    inline uint32_t identifierSize() const
    {
        return _id.size();
    }
    //! @brief Gets the identifier pointer
    inline const uint8_t* identifier() const
    {
        return !_id.empty() ? _id.data() : nullptr;
    }
    /*!
      @brief Set the identifier
      @param id Pointer of the identifier
      @param len identifier length
     */
    inline void setIdentifier(const uint8_t* id, const uint32_t len)
    {
        if (_attr.tnf() != TNF::Empty && id && len) {
            _id = std::vector<uint8_t>(id, id + len);
            _attr.idLength(true);
        } else {
            _id.clear();
            _attr.idLength(false);
        }
    }
    //! @brief Clear the identifier
    inline void clearIdentifier()
    {
        setIdentifier(nullptr, 0);
    }
    ///@}

    ///@name Payload
    ///@{
    //! @brief Obtain the payload as a string
    std::string payloadAsString() const;

    //! @brief Gets the payload size
    inline uint32_t payloadSize() const
    {
        return _payload.size();
    }
    //! @brief Gets the payload pointer
    inline const uint8_t* payload() const
    {
        return !_payload.empty() ? _payload.data() : nullptr;
    }
    /*!
      @brief Set the payload data
      @param data Pointer of the data
      @param len data length
     */
    inline void setPayload(const uint8_t* data, const uint32_t len)
    {
        if (_attr.tnf() != TNF::Empty && data && len) {
            _payload = std::vector<uint8_t>(data, data + len);
            _attr.shortRecord(_payload.size() < 256);
        }
    }
    ///@}

    ///@name Payload helper for TNF::Wellknown
    ///@{
    /*!
      @brief Set text to the payload
      @param str String as UTF-8
      @param lang ISO/IANA language code. e.g. "en"
      @warning type is changed to "T"
     */
    bool setTextPayload(const char* str, const char* lang);
    /*!
      @brief Set URI to the payload
      @param uri URI full text e.g. https://www.example.com
      @param protocol URIProtocol
      @note If there is a part that can be omitted by the protocol, it is omitted and stored
      @warning type is changed to "U"
     */
    bool setURIPayload(const char* uri, URIProtocol protocol);
    ///@}

    //! @brief Size required for encoding
    uint32_t required() const;

    /*!
      @brief Encode
      @param[out] buf Buffer
      @paran blen Buffer size
      @retval > 0 Encoded length
      @retval == 0 Error
    */
    uint32_t encode(uint8_t* buf, const uint32_t blen) const;
    /*!
      @brief Decode
      @param buf Pointer of the NDEF Record
      @param blen Buffer length
      @retval > 0 Decoded length
      @retval == 0 Error
     */
    uint32_t decode(const uint8_t* buf, const uint32_t blen);

    //! @brief Clear
    void clear();

    //! @brief Dump record for debug
    void dump() const;

protected:
    bool apply_nested_message();
    void set_text_payload(const char* str, const char* lang);
    void set_uri_payload(const char* uri, URIProtocol protocol);

private:
    Attribute _attr{};
    std::string _type{};
    std::vector<uint8_t> _payload{};
    std::vector<uint8_t> _id{};

    friend bool operator==(const Record& a, const Record& b);
};

//! @brief Equal?
inline bool operator==(const Record& a, const Record& b)
{
    return a._attr.value == b._attr.value && a._type == b._type && a._payload == b._payload && a._id == b._id;
}
//! @brief Not equal?
inline bool operator!=(const Record& a, const Record& b)
{
    return !(a == b);
}

}  // namespace ndef
}  // namespace nfc
}  // namespace m5
#endif
