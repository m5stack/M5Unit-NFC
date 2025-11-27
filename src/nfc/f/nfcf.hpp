/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfcf.hpp
  @brief NFC-F definitions
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_F_NFCF_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_F_NFCF_HPP

#include <cstdint>
#include <array>

namespace m5 {
namespace nfc {
/*!
  @namespace f
  @brief NFC-F definitions
 */
namespace f {

/*!
  @enum Type
  @brief Type of the PICC
 */
enum class Type : uint8_t {
    Unknown,  //!< Unknown type
    FeliCaStandard,
    FeliCaLiteS,
    FelicaPlugin,
};

///@name Format bits
///@{
using Format = uint8_t;
constexpr Format format_nfcip1{0x0001};
constexpr Format format_dfc{0x0002};
constexpr Format format_private{0x0004};
constexpr Format format_ndef{0x0008};
constexpr Format format_shared{0x0010};
constexpr Format format_secure{0x0020};
///@}

using IDm = std::array<uint8_t, 8>;  //!< Manufacture ID
using PMm = std::array<uint8_t, 8>;  //!< Manufacture Parameter

/*!
  @enum CommandCode
  @brief NFC-F Command code
 */
enum class CommandCode : uint8_t {
    Polling,
    RequestService  = 0x02,
    RequestResponse = 0x04,
};

/*!
  @enum ResponseCode
  @brief NFC-F Response code

*/
enum class ResponseCode : uint8_t {
    Polling        = 0x01,
    RequestService = 0x03,
};

///@name SystemCode
///@{
constexpr uint16_t system_code_wildcard{0xFFFF};  //!< Wildcard
constexpr uint16_t system_code_ndef{0x12FC};      //!< NDEF
constexpr uint16_t system_code_secure{0x957A};    //!< FeliCa secure ID
constexpr uint16_t system_code_shared{0xFE00};    //!< Shared area
constexpr uint16_t system_code_dfc{0x8884};       //!< DFC
///@}

/*!
  @enum RequestCode
  @brief Request code for Polling
 */
enum class RequestCode : uint8_t {
    None,                      //!< No request
    SystemCode,                //!< Request system code
    CommunicationPerformance,  //!< Request communication performance
};

/*!
  @enum TimeSlot
  @brief Timeslot value for Polling
 */
enum class TimeSlot : uint8_t { Slot1, Slot2, Slot4 = 0x03, Slot8 = 0x07, Slot16 = 0x0F };

//! @brief TimeSlot to the number of the slot
inline constexpr uint8_t timeslot_to_slot(const TimeSlot ts)
{
    return (ts == TimeSlot::Slot16)  ? 16
           : (ts == TimeSlot::Slot8) ? 8
           : (ts == TimeSlot::Slot4) ? 4
           : (ts == TimeSlot::Slot2) ? 2
           : (ts == TimeSlot::Slot1) ? 1
                                     : 0;  //    Illegal
}

/*!
  @strutc PICC
  @brief PICC informationg for NFC-F
 */
struct PICC {
    IDm idm{};                   //!< Manufacture ID
    PMm pmm{};                   //!< //!< Manufacture Parameter
    uint16_t request_data{};     //!< Any request data
    RequestCode request_code{};  //!< Tyepe of the request_data
    Format format{};             //!< Format type group bits

    //! @breif Gets the IDm string for debug
    std::string idmAsString() const;
    //! @breif Gets the PMm string for debug
    std::string pmmAsString() const;
};

//! @brief Equal?
inline bool operator==(const PICC& a, const PICC& b)
{
    return a.idm == b.idm && a.pmm == b.pmm;
}
//! @brief Not equal?
inline bool operator!=(const PICC& a, const PICC& b)
{
    return !(a == b);
}

///@name Timeout
///@{
constexpr uint32_t TIMEOUT_POLLING{3};
constexpr uint32_t TIMEOUT_POLLING_PICC{2};  // 2 ms per PICC

}  // namespace f
}  // namespace nfc
}  // namespace m5
#endif
