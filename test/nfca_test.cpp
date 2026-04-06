/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for NFC-A
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include "nfc/a/nfca.hpp"
#include <cstring>

using namespace m5::nfc;
using namespace m5::nfc::a;

TEST(NFC_A, TypeCheckers)
{
    // is_mifare_classic
    EXPECT_FALSE(is_mifare_classic(Type::Unknown));
    EXPECT_TRUE(is_mifare_classic(Type::MIFARE_Classic_Mini));
    EXPECT_TRUE(is_mifare_classic(Type::MIFARE_Classic_1K));
    EXPECT_TRUE(is_mifare_classic(Type::MIFARE_Classic_2K));
    EXPECT_TRUE(is_mifare_classic(Type::MIFARE_Classic_4K));
    EXPECT_FALSE(is_mifare_classic(Type::MIFARE_Ultralight));

    // is_mifare_ultralight
    EXPECT_FALSE(is_mifare_ultralight(Type::Unknown));
    EXPECT_TRUE(is_mifare_ultralight(Type::MIFARE_Ultralight));
    EXPECT_TRUE(is_mifare_ultralight(Type::MIFARE_Ultralight_EV1_1));
    EXPECT_TRUE(is_mifare_ultralight(Type::MIFARE_Ultralight_EV1_2));
    EXPECT_TRUE(is_mifare_ultralight(Type::MIFARE_Ultralight_Nano));
    EXPECT_TRUE(is_mifare_ultralight(Type::MIFARE_UltralightC));
    EXPECT_FALSE(is_mifare_ultralight(Type::NTAG_203));

    // is_ntag2
    EXPECT_FALSE(is_ntag2(Type::MIFARE_UltralightC));
    EXPECT_TRUE(is_ntag2(Type::NTAG_203));
    EXPECT_TRUE(is_ntag2(Type::NTAG_210u));
    EXPECT_TRUE(is_ntag2(Type::NTAG_210));
    EXPECT_TRUE(is_ntag2(Type::NTAG_212));
    EXPECT_TRUE(is_ntag2(Type::NTAG_213));
    EXPECT_TRUE(is_ntag2(Type::NTAG_215));
    EXPECT_TRUE(is_ntag2(Type::NTAG_216));
    EXPECT_FALSE(is_ntag2(Type::ST25TA_512B));

    // is_ntag4
    EXPECT_TRUE(is_ntag4(Type::NTAG_4XX));
    EXPECT_FALSE(is_ntag4(Type::NTAG_216));

    // is_mifare_plus
    EXPECT_FALSE(is_mifare_plus(Type::MIFARE_Classic_4K));
    EXPECT_TRUE(is_mifare_plus(Type::MIFARE_Plus_2K));
    EXPECT_TRUE(is_mifare_plus(Type::MIFARE_Plus_4K));
    EXPECT_TRUE(is_mifare_plus(Type::MIFARE_Plus_SE));
    EXPECT_FALSE(is_mifare_plus(Type::MIFARE_DESFire_2K));

    // is_mifare_classic_compatible (Plus SL1)
    EXPECT_TRUE(is_mifare_classic_compatible(Type::MIFARE_Plus_2K, 1));
    EXPECT_FALSE(is_mifare_classic_compatible(Type::MIFARE_Plus_2K, 2));
    EXPECT_FALSE(is_mifare_classic_compatible(Type::MIFARE_Classic_1K, 1));

    // is_mifare_desfire
    EXPECT_FALSE(is_mifare_desfire(Type::MIFARE_Plus_SE));
    EXPECT_TRUE(is_mifare_desfire(Type::MIFARE_DESFire_2K));
    EXPECT_TRUE(is_mifare_desfire(Type::MIFARE_DESFire_4K));
    EXPECT_TRUE(is_mifare_desfire(Type::MIFARE_DESFire_8K));
    EXPECT_TRUE(is_mifare_desfire(Type::MIFARE_DESFire_Light));
    EXPECT_FALSE(is_mifare_desfire(Type::NTAG_4XX));

    // is_mifare
    EXPECT_TRUE(is_mifare(Type::MIFARE_Classic_1K));
    EXPECT_TRUE(is_mifare(Type::MIFARE_Ultralight));
    EXPECT_TRUE(is_mifare(Type::MIFARE_Plus_2K));
    EXPECT_TRUE(is_mifare(Type::MIFARE_DESFire_2K));
    EXPECT_FALSE(is_mifare(Type::NTAG_213));
    EXPECT_FALSE(is_mifare(Type::ST25TA_2K));

    // is_st25ta
    EXPECT_FALSE(is_st25ta(Type::ST25TA_512B));  // Note: ST25TA_512B < ST25TA_2K
    EXPECT_TRUE(is_st25ta(Type::ST25TA_2K));
    EXPECT_TRUE(is_st25ta(Type::ST25TA_16K));
    EXPECT_TRUE(is_st25ta(Type::ST25TA_64K));
    EXPECT_FALSE(is_st25ta(Type::ISO_14443_4));

    // is_iso14443_4
    EXPECT_TRUE(is_iso14443_4(Type::MIFARE_Plus_2K));
    EXPECT_TRUE(is_iso14443_4(Type::MIFARE_DESFire_2K));
    EXPECT_TRUE(is_iso14443_4(Type::ST25TA_2K));
    EXPECT_TRUE(is_iso14443_4(Type::ISO_14443_4));
    EXPECT_FALSE(is_iso14443_4(Type::MIFARE_Classic_1K));
    EXPECT_FALSE(is_iso14443_4(Type::NTAG_213));

    // is_iso14443_3
    EXPECT_TRUE(is_iso14443_3(Type::MIFARE_Classic_1K));
    EXPECT_TRUE(is_iso14443_3(Type::NTAG_213));
    EXPECT_FALSE(is_iso14443_3(Type::MIFARE_Plus_2K));

    // supports_NFC
    EXPECT_TRUE(supports_NFC(Type::MIFARE_Ultralight));
    EXPECT_TRUE(supports_NFC(Type::NTAG_213));
    EXPECT_FALSE(supports_NFC(Type::MIFARE_Classic_1K));

    // has_fast_read
    EXPECT_FALSE(has_fast_read(Type::NTAG_203));
    EXPECT_FALSE(has_fast_read(Type::NTAG_210u));
    EXPECT_TRUE(has_fast_read(Type::NTAG_210));
    EXPECT_TRUE(has_fast_read(Type::NTAG_212));
    EXPECT_TRUE(has_fast_read(Type::NTAG_213));
    EXPECT_TRUE(has_fast_read(Type::NTAG_215));
    EXPECT_TRUE(has_fast_read(Type::NTAG_216));
}

TEST(NFC_A, SAKCheckers)
{
    // has_sak_dependent_bit
    EXPECT_TRUE(has_sak_dependent_bit(0x04));
    EXPECT_TRUE(has_sak_dependent_bit(0x24));
    EXPECT_FALSE(has_sak_dependent_bit(0x00));
    EXPECT_FALSE(has_sak_dependent_bit(0x08));

    // is_sak_completed_14443_4
    EXPECT_TRUE(is_sak_completed_14443_4(0x20));
    EXPECT_FALSE(is_sak_completed_14443_4(0x00));
    EXPECT_FALSE(is_sak_completed_14443_4(0x24));

    // is_sak_completed
    EXPECT_TRUE(is_sak_completed(0x00));
    EXPECT_TRUE(is_sak_completed(0x08));
    EXPECT_FALSE(is_sak_completed(0x04));
    EXPECT_FALSE(is_sak_completed(0x20));
}

TEST(NFC_A, ATS)
{
    ATS ats{};

    // Default state
    EXPECT_FALSE(ats.validTA());
    EXPECT_FALSE(ats.validTB());
    EXPECT_FALSE(ats.validTC());
    EXPECT_EQ(ats.fsci(), 0);

    // Set T0 flags
    ats.T0 = 0x70;  // TA, TB, TC valid
    EXPECT_TRUE(ats.validTA());
    EXPECT_TRUE(ats.validTB());
    EXPECT_TRUE(ats.validTC());

    // FSCI
    ats.T0 = 0x75;  // FSCI = 5
    EXPECT_EQ(ats.fsci(), 5);

    // TA - bitrate
    ats.T0 = 0x10;  // TA valid
    ats.TA = 0x33;  // DR=3 (848K), DS=3 (848K)
    EXPECT_EQ(ats.maximumBitrateDR(), Bitrate::Bps848K);
    EXPECT_EQ(ats.maximumBitrateDS(), Bitrate::Bps848K);

    ats.TA = 0x80;  // Asymmetric supported
    EXPECT_TRUE(ats.supportsAsymmetricSpeed());

    // TB - FWI/SFGI
    ats.T0 = 0x20;  // TB valid
    ats.TB = 0x75;  // FWI=7, SFGI=5
    EXPECT_EQ(ats.fwi(), 7);
    EXPECT_EQ(ats.sfgi(), 5);
    EXPECT_GT(ats.sfgt_fc(), 0u);
    EXPECT_GT(ats.sfgt_ms(13.56e6f), 0u);

    // SFGI edge cases
    ats.TB = 0x70;  // SFGI=0
    EXPECT_EQ(ats.sfgt_fc(), 0u);
    ats.TB = 0x7F;  // SFGI=15
    EXPECT_EQ(ats.sfgt_fc(), 0u);

    // TC - NAD/CID
    ats.T0 = 0x40;  // TC valid
    ats.TC = 0x03;  // NAD and CID supported
    EXPECT_TRUE(ats.supportsNAD());
    EXPECT_TRUE(ats.supportsCID());

    ats.TC = 0x00;
    EXPECT_FALSE(ats.supportsNAD());
    EXPECT_FALSE(ats.supportsCID());

    // Invalid TA/TB/TC (no valid flags)
    ats.T0 = 0x00;
    ats.TA = 0xFF;
    EXPECT_EQ(ats.maximumBitrateDR(), Bitrate::Invalid);
    EXPECT_EQ(ats.maximumBitrateDS(), Bitrate::Invalid);
    EXPECT_EQ(ats.fwi(), 0);
    EXPECT_EQ(ats.sfgi(), 0);
    EXPECT_EQ(ats.sfgt_ms(0.0f), 0u);
}

TEST(NFC_A, PICC)
{
    PICC picc{};

    // Invalid by default
    EXPECT_FALSE(picc.valid());

    // Set valid values (NTAG213)
    picc.type   = Type::NTAG_213;
    picc.size   = 7;
    picc.blocks = 45;
    std::memset(picc.uid, 0x01, 7);

    EXPECT_TRUE(picc.valid());
    EXPECT_TRUE(picc.isNTAG2());
    EXPECT_FALSE(picc.isMifareClassic());
    EXPECT_TRUE(picc.supportsNFC());
    EXPECT_TRUE(picc.supportsNDEF());
    EXPECT_TRUE(picc.canFastRead());

    // User area
    EXPECT_GT(picc.userAreaSize(), 0);
    EXPECT_EQ(picc.unitSize(), 4);  // 4 bytes per page

    // tail4
    uint8_t tail[4]{};
    picc.tail4(tail);
    EXPECT_EQ(tail[0], 0x01);

    // String conversion
    EXPECT_FALSE(picc.uidAsString().empty());
    EXPECT_FALSE(picc.typeAsString().empty());

    // Comparison
    PICC picc2 = picc;
    EXPECT_TRUE(picc == picc2);
    picc2.uid[0] = 0xFF;
    EXPECT_FALSE(picc == picc2);
    EXPECT_TRUE(picc != picc2);

    // Invalid when blocks are zero for non-file system type
    PICC picc3{};
    picc3.type   = Type::MIFARE_Classic_1K;
    picc3.size   = 10;
    picc3.blocks = 0;
    std::memset(picc3.uid, 0x01, 10);
    EXPECT_FALSE(picc3.valid());
}

TEST(NFC_A, PICCMifareClassic)
{
    PICC picc{};
    picc.type   = Type::MIFARE_Classic_1K;
    picc.size   = 4;
    picc.blocks = 64;
    std::memset(picc.uid, 0x01, 4);

    EXPECT_TRUE(picc.valid());
    EXPECT_TRUE(picc.isMifare());
    EXPECT_TRUE(picc.isMifareClassic());
    EXPECT_FALSE(picc.isMifareUltralight());
    EXPECT_FALSE(picc.isMifarePlus());
    EXPECT_FALSE(picc.isMifareDESFire());
    EXPECT_FALSE(picc.isISO14443_4());
    EXPECT_TRUE(picc.isFileSystemMemory());
    EXPECT_FALSE(picc.isFileSystemFile());
}

TEST(NFC_A, PICCMifarePlus)
{
    PICC picc{};
    picc.type           = Type::MIFARE_Plus_2K;
    picc.size           = 7;
    picc.blocks         = 128;
    picc.sub_type_plus  = SubTypePlus::X;
    picc.security_level = 3;
    std::memset(picc.uid, 0x01, 7);

    EXPECT_TRUE(picc.valid());
    EXPECT_TRUE(picc.isMifarePlus());
    EXPECT_TRUE(picc.isMifarePlusX());
    EXPECT_FALSE(picc.isMifarePlusS());
    EXPECT_FALSE(picc.isMifareClassicCompatible());
    EXPECT_TRUE(picc.isISO14443_4());

    // SL1 compatibility
    picc.security_level = 1;
    EXPECT_TRUE(picc.isMifareClassicCompatible());
    EXPECT_TRUE(picc.isMifareClassic());  // includes compatible

    // Plus S
    picc.sub_type_plus = SubTypePlus::S;
    EXPECT_TRUE(picc.isMifarePlusS());
    EXPECT_FALSE(picc.isMifarePlusX());
    EXPECT_TRUE(picc.requiresPlusSL3PlainRead());
}

TEST(NFC_A, PICCEmulate)
{
    PICC picc{};
    uint8_t uid4[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t uid7[7] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    // Valid emulation
    EXPECT_TRUE(picc.emulate(Type::NTAG_213, uid7, 7));
    EXPECT_EQ(picc.type, Type::NTAG_213);
    EXPECT_EQ(picc.size, 7);
    EXPECT_EQ(std::memcmp(picc.uid, uid7, 7), 0);

    // 4-byte UID
    EXPECT_TRUE(picc.emulate(Type::MIFARE_Classic_1K, uid4, 4));
    EXPECT_EQ(picc.size, 4);

    // Invalid UID length
    EXPECT_FALSE(picc.emulate(Type::NTAG_213, uid7, 5));  // Invalid length
    EXPECT_FALSE(picc.emulate(Type::NTAG_213, nullptr, 7));
    EXPECT_FALSE(picc.emulate(Type::NTAG_213, uid7, 0));
    EXPECT_FALSE(picc.emulate(Type::NTAG_213, uid7, 8));
    EXPECT_FALSE(picc.emulate(Type::Unknown, uid7, 7));
}

TEST(NFC_A, CalculateBcc8)
{
    uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t bcc1    = calculate_bcc8(data1, 4);
    EXPECT_EQ(bcc1, 0x01 ^ 0x02 ^ 0x03 ^ 0x04);

    uint8_t data2[] = {0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t bcc2    = calculate_bcc8(data2, 4);
    EXPECT_EQ(bcc2, 0x00);

    uint8_t data3[] = {0x00};
    uint8_t bcc3    = calculate_bcc8(data3, 1);
    EXPECT_EQ(bcc3, 0x00);

    // Null pointer should return 0
    EXPECT_EQ(calculate_bcc8(nullptr, 4), 0x00);
}

TEST(NFC_A, ST25TA)
{
    using namespace st25ta;

    // get_type
    EXPECT_EQ(get_type(IC_REFERENCE_ST25TA512B), Type::ST25TA_512B);
    EXPECT_EQ(get_type(IC_REFERENCE_ST25TA02KB), Type::ST25TA_2K);
    EXPECT_EQ(get_type(IC_REFERENCE_ST25TA02KB_D), Type::ST25TA_2K);
    EXPECT_EQ(get_type(IC_REFERENCE_ST25TA02KB_P), Type::ST25TA_2K);
    EXPECT_EQ(get_type(PRODUCT_CODE_ST25TA16K), Type::ST25TA_16K);
    EXPECT_EQ(get_type(PRODUCT_CODE_ST25TA64K), Type::ST25TA_64K);
    EXPECT_EQ(get_type(0x00), Type::Unknown);

    // SystemFile
    SystemFile sf{};
    sf.block[17] = IC_REFERENCE_ST25TA02KB;
    EXPECT_EQ(sf.type(), Type::ST25TA_2K);
}
