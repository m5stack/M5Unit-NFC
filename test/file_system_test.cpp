/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for FileSystem helpers
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include "nfc/isoDEP/file_system.hpp"
#include <cstring>

using namespace m5::nfc;

TEST(FileSystem, FCPToTLVAndParseFCI)
{
    FCP fcp{};
    fcp.fid             = 0x1234;
    fcp.file_size       = 0x0042;
    fcp.file_descriptor = 0x11;

    const auto fcp_tlv = fcp.to_tlv();
    EXPECT_FALSE(fcp_tlv.empty());
    // Pin the encoding itself: a roundtrip through parseFCI() passes even when to_tlv() and the
    // parser agree on the wrong tags. ISO 7816-4: 62 = FCP, 82 = file descriptor, 83 = file ID,
    // 80 = file size (the default of FCP::file_size_tag)
    const uint8_t expected_tlv[] = {0x62, 0x0B, 0x82, 0x01, 0x11, 0x83, 0x02, 0x12, 0x34, 0x80, 0x02, 0x00, 0x42};
    EXPECT_EQ(fcp_tlv.size(), sizeof(expected_tlv));
    if (fcp_tlv.size() == sizeof(expected_tlv)) {
        EXPECT_TRUE(std::memcmp(fcp_tlv.data(), expected_tlv, sizeof(expected_tlv)) == 0);
    }
    if (!fcp_tlv.empty()) {
        std::vector<uint8_t> fci;
        fci.push_back(0x6F);
        fci.push_back(static_cast<uint8_t>(fcp_tlv.size()));
        fci.insert(fci.end(), fcp_tlv.begin(), fcp_tlv.end());

        FCP out{};
        EXPECT_TRUE(parseFCI(out, fci.data(), fci.size()));
        EXPECT_EQ(out.fid, 0x1234);
        EXPECT_EQ(out.file_size, 0x0042);
        EXPECT_EQ(out.file_descriptor, 0x11);
    }
}

TEST(FileSystem, ParseFCIInvalid)
{
    FCP out{};

    // Null / short
    EXPECT_FALSE(parseFCI(out, nullptr, 0));
    uint8_t short_buf[] = {0x6F};
    EXPECT_FALSE(parseFCI(out, short_buf, sizeof(short_buf)));

    // Missing FCI tag
    uint8_t no_fci[] = {0x62, 0x00};
    EXPECT_FALSE(parseFCI(out, no_fci, sizeof(no_fci)));

    // Missing FCP tag inside FCI
    uint8_t fci_no_fcp[] = {0x6F, 0x02, 0x84, 0x00};
    EXPECT_FALSE(parseFCI(out, fci_no_fcp, sizeof(fci_no_fcp)));

    // Missing file id / size
    uint8_t fci_missing[] = {0x6F, 0x05, 0x62, 0x03, 0x82, 0x01, 0x11};
    EXPECT_FALSE(parseFCI(out, fci_missing, sizeof(fci_missing)));
}
