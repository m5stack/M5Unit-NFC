/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file manufacturer_id.hpp
  @brief Manufacturer ID (UID[0]) definitions for ISO/IEC 14443-3
  @note Manufacturer ID values are aligned with ISO/IEC 7816-6 manufacturer codes
  @sa https://en.wikipedia.org/wiki/ISO/IEC_15693
*/
#ifndef M5_UNIT_NFC_NFC_MANUFACTURER_ID_HPP
#define M5_UNIT_NFC_NFC_MANUFACTURER_ID_HPP

#include <cstdint>

namespace m5 {
namespace nfc {

/*!
  @enum ManufacturerId
  @brief Manufacturer ID derived from UID[0]
  @note This list is partial,extend as needed
  @warning Random UID may not reflect actual manufacturer
 */
enum class ManufacturerId : uint8_t {
    Unknown            = 0x00,  //!< Unknown/unsupported
    Motorola           = 0x01,  //!< Motorola
    STMicroelectronics = 0x02,  //!< STMicroelectronics
    Hitachi            = 0x03,  //!< Hitachi
    NXP                = 0x04,  //!< NXP Semiconductors
    Infineon           = 0x05,  //!< Infineon
    Cylink             = 0x06,  //!< Cylink
    TexasInstruments   = 0x07,  //!< Texas Instruments
    Fujitsu            = 0x08,  //!< Fujitsu
    Matsushita         = 0x09,  //!< Matsushita (Panasonic)
    NEC                = 0x0A,  //!< NEC
    Oki                = 0x0B,  //!< Oki
    Toshiba            = 0x0C,  //!< Toshiba
    Mitsubishi         = 0x0D,  //!< Mitsubishi
    Samsung            = 0x0E,  //!< Samsung
    Hynix              = 0x0F,  //!< Hynix
    LG                 = 0x10,  //!< LG Semiconductors
    EmosynEM           = 0x11,  //!< Emosyn-EM Microelectronics
    InsideTechnology   = 0x12,  //!< INSIDE Technology
    Orga               = 0x13,  //!< ORGA Kartensysteme
    Sharp              = 0x14,  //!< Sharp
    Atmel              = 0x15,  //!< Atmel
    EmMicroelectronic  = 0x16,  //!< EM Microelectronic-Marin
    Smartrac           = 0x17,  //!< SMARTRAC Technology
    Zmd                = 0x18,  //!< ZMD
    Xicor              = 0x19,  //!< XICOR
    Sony               = 0x1A,  //!< Sony
    MalaysiaMicro      = 0x1B,  //!< Malaysia Microelectronic Solutions
    Emosyn             = 0x1C,  //!< Emosyn
    Fudan              = 0x1D,  //!< Shanghai Fudan Microelectronics
    Magellan           = 0x1E,  //!< Magellan Technology
    Melexis            = 0x1F,  //!< Melexis
    RenesasTechnology  = 0x20,  //!< Renesas Technology
    Tagsys             = 0x21,  //!< TAGSYS
    Transcore          = 0x22,  //!< Transcore
    ShanghaiBelling    = 0x23,  //!< Shanghai Belling
    Masktech           = 0x24,  //!< Masktech Germany
    Innovision         = 0x25,  //!< Innovision Research and Technology
    HitachiUlsi        = 0x26,  //!< Hitachi ULSI Systems
    Yubico             = 0x27,  //!< Yubico
    Ricoh              = 0x28,  //!< Ricoh
    Ask                = 0x29,  //!< ASK
    Unicore            = 0x2A,  //!< Unicore Microsystems
    DallasMaxim        = 0x2B,  //!< Dallas Semiconductor/Maxim
    Impinj             = 0x2C,  //!< Impinj
    RightPlug          = 0x2D,  //!< RightPlug Alliance
    Broadcom           = 0x2E,  //!< Broadcom
    Mstar              = 0x2F,  //!< MStar Semiconductor
    Beedar             = 0x30,  //!< BeeDar Technology
    Rfidsec            = 0x31,  //!< RFIDsec
    Schweizer          = 0x32,  //!< Schweizer Electronic
    Amic               = 0x33,  //!< AMIC Technology
    Mikron             = 0x34,  //!< Mikron
    FraunhoferIpms     = 0x35,  //!< Fraunhofer IPMS
    IdsMicrochip       = 0x36,  //!< IDS Microchip
    Kovio              = 0x37,  //!< Kovio
    Hmt                = 0x38,  //!< HMT Microelectronic
    SiliconCraft       = 0x39,  //!< Silicon Craft
    AdvancedFilmDevice = 0x3A,  //!< Advanced Film Device
    Nitecrest          = 0x3B,  //!< Nitecrest
    Verayo             = 0x3C,  //!< Verayo
    HidGlobal          = 0x3D,  //!< HID Global
    ProductivityEng    = 0x3E,  //!< Productivity Engineering
    Austriamicrosys    = 0x3F,  //!< Austriamicrosystems (reserved)
    Gemalto            = 0x40,  //!< Gemalto
    RenesasElectronics = 0x41,  //!< Renesas Electronics
    A3logics           = 0x42,  //!< 3Alogics
    TopTroniq          = 0x43,  //!< Top TroniQ Asia
    Gentag             = 0x44,  //!< Gentag
    Invengo            = 0x45,  //!< Invengo
    GuangzhouSysur     = 0x46,  //!< Guangzhou Sysur
    Ceitec             = 0x47,  //!< CEITEC
    Quanray            = 0x48,  //!< Shanghai Quanray
    Mediatek           = 0x49,  //!< MediaTek
    Angstrem           = 0x4A,  //!< Angstrem
    Celisic            = 0x4B,  //!< Celisic Semiconductor
    Legic              = 0x4C,  //!< LEGIC
    Balluff            = 0x4D,  //!< Balluff
    Oberthur           = 0x4E,  //!< Oberthur Technologies
    Silterra           = 0x4F,  //!< Silterra
    Delta              = 0x50,  //!< DELTA
    GieseckeDevrient   = 0x51,  //!< Giesecke + Devrient
    ChinaVision        = 0x52,  //!< Shenzhen China Vision
    ShanghaiFeiju      = 0x53,  //!< Shanghai Feiju
    Intel              = 0x54,  //!< Intel
    Microsensys        = 0x55,  //!< Microsensys
    Sonix              = 0x56,  //!< Sonix
    Qualcomm           = 0x57,  //!< Qualcomm
    Realtek            = 0x58,  //!< Realtek
    Freevision         = 0x59,  //!< Freevision
    Giantec            = 0x5A,  //!< Giantec
    AngstremT          = 0x5B,  //!< Angstrem-T
    Starchip           = 0x5C,  //!< STARCHIP
    Spirtech           = 0x5D,  //!< SPIRTECH
    Gantner            = 0x5E,  //!< GANTNER Electronic
    Nordic             = 0x5F,  //!< Nordic Semiconductor
    Verisiti           = 0x60,  //!< Verisiti
    Wearlinks          = 0x61,  //!< Wearlinks
    Userstar           = 0x62,  //!< Userstar
    Pragmatic          = 0x63,  //!< Pragmatic Semiconductor
    LsiTec             = 0x64,  //!< LSI-TEC
    Tendyron           = 0x65,  //!< Tendyron
    MutoSmart          = 0x66,  //!< MUTO Smart
    OnSemiconductor    = 0x67,  //!< ON Semiconductor
    TubitakBilgem      = 0x68,  //!< TUBITAK BILGEM
    Huada              = 0x69,  //!< Huada Semiconductor
    Seveney            = 0x6A,  //!< SEVENEY
    Issm               = 0x6B,  //!< ISSM
    Wisesec            = 0x6C,  //!< Wisesec
    Holtek             = 0x7E,  //!< Holtek
    MultibyteMarker    = 0xFF,  //!< ISO/IEC 7816-6:2023
};

}  // namespace nfc
}  // namespace m5

#endif
