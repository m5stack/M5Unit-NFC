/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file ndef_message.hpp
  @brief NDEF message
*/
#ifndef M5_UNIT_NFC_NDEF_NFC_NDEF_MESSAGE_HPP
#define M5_UNIT_NFC_NDEF_NFC_NDEF_MESSAGE_HPP

#include "ndef.hpp"
#include "ndef_record.hpp"

namespace m5 {
namespace nfc {
namespace ndef {

/*!
  @class Message
  @brief NDEF message container
 */
class Message {
public:
    using container_type = std::vector<Record>;

    //!@brief Terminator instance
    static const Message Terminator;

    explicit Message(const Tag t = Tag::NDEFMessage) : _tag{t}
    {
    }
    ~Message()
    {
    }

    //! @brief Tag
    inline Tag tag() const
    {
        return _tag;
    }
    //! @brief Is termibator
    inline bool isTerminator() const
    {
        return is_terminator_tag(m5::stl::to_underlying(_tag));
    }
    //! @brief Is NDEF Messgae?
    inline bool isNDEFMessage() const
    {
        return _tag == Tag::NDEFMessage;
    }
    /*!
      @brief Get the records
      @pre Tag must be NDEFMessage
    */
    inline const container_type& records() const
    {
        return _records;
    }

    /*!
      @brief Get the payload
      @pre Tag must NOT be NDEFMessage
    */
    inline const std::vector<uint8_t>& payload() const
    {
        return _payload;
    }

    /*!
      @brief Get the payload
      @pre Tag must NOT be NDEFMessage
    */
    inline std::vector<uint8_t>& payload()
    {
        return _payload;
    }

    /*!
      @brief Size required for encoding
      @param include_terminator Include terminator in required size?
    */
    uint32_t required(const bool include_terminator = true) const;

    /*!
      @brief Push back the record
      @param r Record
      @return True if successful
      @note A copy of the Record is inserted at the end
     */
    bool push_back(const Record& r);

    /*!
      @brief Encode
      @param[out] buf Buffer
      @param blen Buffer size
      @param include_terminator Include terminator in encode?
      @retval > 0 Encoded length
      @retval == 0 Error
     */
    uint32_t encode(uint8_t* buf, const uint32_t blen, const bool include_terminator = true) const;
    /*!
      @brief Decode
      @param buf Pointer of the NDEF mesage
      @param len Buffer length
      @retval > 0 Decoded length
      @retval == 0 Error
     */
    uint32_t decode(const uint8_t* buf, const uint32_t len);

    void clear();

    void dump();

private:
    Tag _tag{};
    container_type _records{};        //  For NDEFMessage
    std::vector<uint8_t> _payload{};  // Other than NDEFMessage
};
}  // namespace ndef
}  // namespace nfc
}  // namespace m5
#endif
