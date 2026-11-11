/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for NFC-F
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include "nfc/f/nfcf.hpp"
#include "nfc/layer/f/nfc_layer_f.hpp"
#include <cstring>
#include <memory>
#include <vector>

using namespace m5::nfc;
using namespace m5::nfc::f;

namespace {

constexpr uint8_t idm_sample[FELICA_ID_LENGTH] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
constexpr uint8_t pmm_sample[FELICA_ID_LENGTH] = {0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE};

// A card that answers the system codes it was given, and nothing else. The IDm it answers with
// carries the system's number in the top four bits of its first byte, which is what a card split
// into several systems does (FeliCa card users manual 2.21j, 2.2.1): system 0 answers 0x0?, system
// 1 answers 0x1?, and so on. Scripting it here is the only way to exercise that, since no card
// that does it is to hand.
class ScriptedCardForF : public NFCLayerF::Adapter {
public:
    // Each entry is a system this card has, in split order: entry 0 is system 0 and answers the
    // wildcard as well
    explicit ScriptedCardForF(std::vector<uint16_t> systems) : _systems{std::move(systems)}
    {
    }

    uint16_t max_fifo_depth() const override
    {
        return 512;
    }

    bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len, const uint32_t) override
    {
        if (_systems.empty()) {
            rx_len = 0;
            return false;
        }
        // Answering Request Response is what settles a card as FeliCa Standard, so a card that
        // stays silent here is never detected at all, whatever its systems answer
        if (tx[0] == m5::stl::to_underlying(CommandCode::RequestResponse) && tx_len >= 1 + FELICA_ID_LENGTH) {
            uint8_t res[11]{};
            res[0] = sizeof(res);
            res[1] = m5::stl::to_underlying(ResponseCode::RequestResponse);
            memcpy(&res[2], tx + 1, FELICA_ID_LENGTH);  // echo the IDm it was addressed to
            res[10]          = 0x00;                    // Mode 0
            const uint16_t n = (rx_len < sizeof(res)) ? rx_len : (uint16_t)sizeof(res);
            memcpy(rx, res, n);
            rx_len = n;
            return true;
        }
        if (tx_len < 5 || tx[0] != m5::stl::to_underlying(CommandCode::Polling)) {
            rx_len = 0;
            return false;
        }
        const uint16_t sc = (uint16_t)((tx[1] << 8) | tx[2]);

        // The wildcard is answered by system 0; any other code only by the system that owns it
        uint8_t system{};
        if (sc != system_code_wildcard) {
            size_t i = 0;
            for (; i < _systems.size(); ++i) {
                if (_systems[i] == sc) {
                    break;
                }
            }
            if (i == _systems.size()) {
                rx_len = 0;
                return false;  // this card has no such system
            }
            system = (uint8_t)i;
        }
        ++_answers;

        uint8_t res[18]{};
        res[0] = sizeof(res);
        res[1] = m5::stl::to_underlying(ResponseCode::Polling);
        memcpy(&res[2], idm_sample, FELICA_ID_LENGTH);
        res[2] = (uint8_t)((idm_sample[0] & 0x0F) | (system << 4));
        memcpy(&res[2 + FELICA_ID_LENGTH], pmm_sample, FELICA_ID_LENGTH);

        const uint16_t len = (rx_len < sizeof(res)) ? rx_len : (uint16_t)sizeof(res);
        memcpy(rx, res, len);
        rx_len = len;
        return true;
    }

    uint16_t answers() const
    {
        return _answers;
    }

private:
    std::vector<uint16_t> _systems;
    uint16_t _answers{};
};

}  // namespace

TEST(NFC_F, TimeSlot)
{
    EXPECT_EQ(timeslot_to_slot(TimeSlot::Slot1), 1);
    EXPECT_EQ(timeslot_to_slot(TimeSlot::Slot2), 2);
    EXPECT_EQ(timeslot_to_slot(TimeSlot::Slot4), 4);
    EXPECT_EQ(timeslot_to_slot(TimeSlot::Slot8), 8);
    EXPECT_EQ(timeslot_to_slot(TimeSlot::Slot16), 16);
    EXPECT_EQ(timeslot_to_slot(static_cast<TimeSlot>(0xFF)), 0);
}

TEST(NFC_F, Block)
{
    block_t b{0x0102, 0x03, 0x04};
    EXPECT_TRUE(b.is_3byte());
    EXPECT_FALSE(b.is_2byte());
    EXPECT_EQ(b.access_mode(), 0x03);
    EXPECT_EQ(b.order(), 0x04);
    EXPECT_EQ(b.block(), 0x0102);

    uint8_t buf[3] = {0};
    auto len       = b.store(buf);
    EXPECT_EQ(len, 3u);
    EXPECT_EQ(buf[0], b.header);
    EXPECT_EQ(buf[1], 0x02);
    EXPECT_EQ(buf[2], 0x01);

    auto b2 = block_t::from(buf);
    EXPECT_TRUE(b2.is_3byte());
    EXPECT_EQ(b2.block(), 0x0102);
    EXPECT_EQ(b2.access_mode(), 0x03);
    EXPECT_EQ(b2.order(), 0x04);

    b2.block(0x00FE);
    EXPECT_TRUE(b2.is_2byte());
    EXPECT_EQ(b2.block(), 0x00FE);

    b2.access_mode(0x07);
    b2.order(0x0F);
    EXPECT_EQ(b2.access_mode(), 0x07);
    EXPECT_EQ(b2.order(), 0x0F);
}

TEST(NFC_F, UserArea)
{
    EXPECT_EQ(get_nfc_forum_tag_type(Type::Unknown), NFCForumTag::None);
    EXPECT_EQ(get_nfc_forum_tag_type(Type::FeliCaLiteS), NFCForumTag::Type3);

    EXPECT_EQ(get_number_of_user_blocks(Type::Unknown), 0);
    EXPECT_EQ(get_number_of_user_blocks(Type::FeliCaLite), 14);
    EXPECT_EQ(get_number_of_user_blocks(Type::FeliCaLiteS), 14);

    EXPECT_EQ(get_first_user_block(Type::FeliCaLite), 0);
    EXPECT_EQ(get_last_user_block(Type::FeliCaLite), 0x0D);

    EXPECT_TRUE(is_user_block(Type::FeliCaLite, 0));
    EXPECT_TRUE(is_user_block(Type::FeliCaLite, 0x0D));
    EXPECT_FALSE(is_user_block(Type::FeliCaLite, 0x0E));

    EXPECT_EQ(get_maximum_read_blocks(Type::FeliCaStandard), 8u);
    EXPECT_EQ(get_maximum_read_blocks(Type::FeliCaLite), 4u);
    EXPECT_EQ(get_maximum_write_blocks(Type::FeliCaLiteS), 1u);
}

TEST(NFC_F, PICC)
{
    PICC picc{};
    EXPECT_FALSE(picc.valid());
    EXPECT_FALSE(picc.validEmulation());
    EXPECT_EQ(picc.firstUserBlock(), 0xFFFF);
    EXPECT_EQ(picc.lastUserBlock(), 0xFFFF);
    EXPECT_EQ(picc.userAreaSize(), 0u);
    EXPECT_EQ(picc.nfcForumTagType(), NFCForumTag::None);

    std::memcpy(picc.idm, idm_sample, sizeof(idm_sample));
    std::memcpy(picc.pmm, pmm_sample, sizeof(pmm_sample));
    picc.type         = Type::FeliCaLiteS;
    picc.format       = format_lite;
    picc.emulation_sc = system_code_lite;

    EXPECT_TRUE(picc.valid());
    EXPECT_TRUE(picc.validEmulation());
    EXPECT_EQ(picc.userAreaSize(), 16u * 14u);
    EXPECT_EQ(picc.firstUserBlock(), 0u);
    EXPECT_EQ(picc.lastUserBlock(), 0x0Du);
    EXPECT_TRUE(picc.isUserBlock(block_t{0x0D}));
    EXPECT_FALSE(picc.isUserBlock(block_t{0x0E}));

    EXPECT_EQ(picc.idmAsString(), std::string("0123456789ABCDEF"));
    EXPECT_EQ(picc.pmmAsString(), std::string("1032547698BADCFE"));
    EXPECT_EQ(picc.typeAsString(), std::string("FeliCa Lite-S"));

    PICC picc2 = picc;
    EXPECT_TRUE(picc == picc2);
    picc2.pmm[0] ^= 0x01;
    EXPECT_TRUE(picc != picc2);

    // emulation
    PICC picc3{};
    EXPECT_TRUE(picc3.emulate(Type::FeliCaLiteS, idm_sample, pmm_sample));
    EXPECT_TRUE(picc3.validEmulation());
    EXPECT_FALSE(picc3.emulate(Type::FeliCaLite, idm_sample, pmm_sample));
}

TEST(NFC_F, EmulationPollingMemory)
{
    PICC picc{};
    EXPECT_TRUE(picc.emulate(Type::FeliCaLiteS, idm_sample, pmm_sample));

    uint8_t mem[FELICA_PT_MEMORY_SIZE]{};
    EXPECT_TRUE(make_emulation_polling_memory(mem, picc));

    EXPECT_EQ(mem[0], 0x88);
    EXPECT_EQ(mem[1], 0xB4);
    EXPECT_EQ(mem[2], static_cast<uint8_t>(ResponseCode::Polling));
    EXPECT_EQ(std::memcmp(mem + 3, idm_sample, sizeof(idm_sample)), 0);
    EXPECT_EQ(std::memcmp(mem + 11, pmm_sample, sizeof(pmm_sample)), 0);
    EXPECT_EQ(mem[19], 0x00);
    EXPECT_EQ(mem[20], 0x83);

    picc.request_data = 0x1234;
    std::memset(mem, 0, sizeof(mem));
    EXPECT_TRUE(make_emulation_polling_memory(mem, picc));
    EXPECT_EQ(mem[19], 0x12);
    EXPECT_EQ(mem[20], 0x34);
}

// Builds a Read Without Encryption answer the way a conformant card would: length byte, response
// code, IDm, both status flags, the block count and then that many blocks of sixteen bytes.
static std::vector<uint8_t> make_read_response(const uint8_t blocks, const uint8_t sf1 = 0x00, const uint8_t sf2 = 0x00)
{
    std::vector<uint8_t> res(FELICA_READ_RESPONSE_HEADER_SIZE + 16U * blocks);
    res[0] = static_cast<uint8_t>(res.size());
    res[1] = static_cast<uint8_t>(ResponseCode::ReadWithoutEncryption);
    std::memcpy(res.data() + 2, idm_sample, sizeof(idm_sample));
    res[10] = sf1;
    res[11] = sf2;
    res[12] = blocks;
    for (uint32_t i = FELICA_READ_RESPONSE_HEADER_SIZE; i < res.size(); ++i) {
        res[i] = static_cast<uint8_t>(i);
    }
    return res;
}

TEST(NFC_F, ReadResponseBlocks)
{
    uint8_t blocks{0xFF};

    // A well formed answer for every block count the layer is willing to ask for
    for (uint8_t n = 1; n <= FELICA_MAX_BLOCKS; ++n) {
        auto res = make_read_response(n);
        EXPECT_TRUE(read_response_blocks(res.data(), static_cast<uint16_t>(res.size()), blocks)) << "blocks:" << (int)n;
        EXPECT_EQ(blocks, n);
    }

    // An error answer stops before the block count, so there is nothing to hand back
    auto err = make_read_response(0);
    err.resize(12);
    err[0]  = 12;
    err[10] = 0xFF;
    blocks  = 0xFF;
    EXPECT_FALSE(read_response_blocks(err.data(), static_cast<uint16_t>(err.size()), blocks));
    EXPECT_EQ(blocks, 0) << "A rejected answer reports no blocks";

    // The length that tripped the original bug: one byte short of a success, but with both status
    // flags clear. Subtracting the header from this used to wrap around
    auto shortest = make_read_response(0);
    shortest.resize(12);
    shortest[0] = 12;
    blocks      = 0xFF;
    EXPECT_FALSE(read_response_blocks(shortest.data(), static_cast<uint16_t>(shortest.size()), blocks));
    EXPECT_EQ(blocks, 0);

    // The count has to be one the request could have produced
    auto too_many = make_read_response(1);
    too_many[12]  = FELICA_MAX_BLOCKS + 1;
    blocks        = 0xFF;
    EXPECT_FALSE(read_response_blocks(too_many.data(), static_cast<uint16_t>(too_many.size()), blocks));
    EXPECT_EQ(blocks, 0);

    // A count the frame is too small to carry
    auto truncated = make_read_response(4);
    truncated.resize(truncated.size() - 1);
    blocks = 0xFF;
    EXPECT_FALSE(read_response_blocks(truncated.data(), static_cast<uint16_t>(truncated.size()), blocks));
    EXPECT_EQ(blocks, 0);

    // The length byte has to agree that there is room for a block count
    auto lying = make_read_response(1);
    lying[0]   = 12;
    blocks     = 0xFF;
    EXPECT_FALSE(read_response_blocks(lying.data(), static_cast<uint16_t>(lying.size()), blocks));

    // Wrong response code, and the status flags each on their own
    auto wrong_code = make_read_response(1);
    wrong_code[1]   = static_cast<uint8_t>(ResponseCode::WriteWithoutEncryption);
    EXPECT_FALSE(read_response_blocks(wrong_code.data(), static_cast<uint16_t>(wrong_code.size()), blocks));

    auto sf1_set = make_read_response(1, 0x01, 0x00);
    EXPECT_FALSE(read_response_blocks(sf1_set.data(), static_cast<uint16_t>(sf1_set.size()), blocks));

    auto sf2_set = make_read_response(1, 0x00, 0xA8);
    EXPECT_FALSE(read_response_blocks(sf2_set.data(), static_cast<uint16_t>(sf2_set.size()), blocks));

    // Nothing at all
    blocks = 0xFF;
    EXPECT_FALSE(read_response_blocks(nullptr, 32, blocks));
    EXPECT_EQ(blocks, 0);

    auto ok = make_read_response(1);
    EXPECT_FALSE(read_response_blocks(ok.data(), 0, blocks));

    // Zero blocks is a well formed answer that simply carries nothing
    auto empty = make_read_response(0);
    blocks     = 0xFF;
    EXPECT_TRUE(read_response_blocks(empty.data(), static_cast<uint16_t>(empty.size()), blocks));
    EXPECT_EQ(blocks, 0);
}

TEST(NFC_F, Reg)
{
    REG r{};
    r.regA(0x11223344);
    r.regB(0xA1A2A3A4);
    r.regC(0x0102030405060708ULL);

    EXPECT_EQ(r.regA(), 0x11223344u);
    EXPECT_EQ(r.regB(), 0xA1A2A3A4u);
    EXPECT_EQ(r.regC(), 0x0102030405060708ULL);

    REG o = r;
    REG n = r;
    n.regA(0x00112233);
    n.regB(0x01020304);
    EXPECT_TRUE(can_write_reg(o, n));

    n.regA(0xFFFFFFFF);
    EXPECT_FALSE(can_write_reg(o, n));
}

TEST(NFC_F, BlockPermission)
{
    EXPECT_TRUE(is_read_only_lite(lite::MAC));
    EXPECT_TRUE(is_read_only_lite(lite::SYS_C));
    EXPECT_FALSE(is_read_only_lite(lite::S_PAD1));

    EXPECT_TRUE(is_read_only_lite_s(lite_s::MAC));
    EXPECT_TRUE(is_read_only_lite_s(lite_s::D_ID));
    EXPECT_TRUE(is_read_only_lite_s(lite_s::SYS_C));
    EXPECT_TRUE(is_read_only_lite_s(lite_s::WCNT));
    EXPECT_TRUE(is_read_only_lite_s(lite_s::CRC_CHECK));

    EXPECT_FALSE(can_read_lite(lite_s::RC));
    EXPECT_FALSE(can_read_lite(lite_s::CK));
    EXPECT_TRUE(can_read_lite(lite::S_PAD0));

    EXPECT_FALSE(can_read_lite_s(lite_s::RC));
    EXPECT_FALSE(can_read_lite_s(lite_s::CK));
    EXPECT_TRUE(can_read_lite_s(lite_s::S_PAD0));
}

TEST(NFC_F, CryptoInvalid)
{
    uint8_t out[16]{};
    uint8_t key16[16]{};
    uint8_t key24[24]{};
    uint8_t rc[16]{};
    uint8_t plain[16]{};
    uint8_t block[16]{};
    uint8_t sk1[8]{};
    uint8_t sk2[8]{};

    EXPECT_FALSE(make_session_key(nullptr, key16, rc));
    EXPECT_FALSE(make_session_key(out, nullptr, rc));
    EXPECT_FALSE(make_session_key(out, key16, nullptr));

    EXPECT_FALSE(generate_mac(nullptr, plain, sizeof(plain), block, sizeof(block), sk1, sk2, rc));
    EXPECT_FALSE(generate_mac(out, nullptr, sizeof(plain), block, sizeof(block), sk1, sk2, rc));
    EXPECT_TRUE(generate_mac(out, plain, 0, block, sizeof(block), sk1, sk2, rc));
    EXPECT_FALSE(generate_mac(out, plain, sizeof(plain), nullptr, sizeof(block), sk1, sk2, rc));
    EXPECT_FALSE(generate_mac(out, plain, sizeof(plain), block, 0, sk1, sk2, rc));
    EXPECT_FALSE(generate_mac(out, plain, sizeof(plain), block, sizeof(block), nullptr, sk2, rc));
    EXPECT_FALSE(generate_mac(out, plain, sizeof(plain), block, sizeof(block), sk1, nullptr, rc));
    EXPECT_FALSE(generate_mac(out, plain, sizeof(plain), block, sizeof(block), sk1, sk2, nullptr));

    EXPECT_FALSE(make_personalized_card_key_lite_s(nullptr, key24, block));
    EXPECT_FALSE(make_personalized_card_key_lite_s(out, nullptr, block));
    EXPECT_FALSE(make_personalized_card_key_lite_s(out, key24, nullptr));
}

TEST(NFC_F, DetectSingleSystemCard)
{
    // A card with one system answers only the wildcard, so nothing is there to disagree with the
    // first answer. This is the card that already works, kept here so a fix for the multi-system
    // case cannot quietly break it
    auto card = new ScriptedCardForF({0x0003});
    NFCLayerF layer{std::unique_ptr<NFCLayerF::Adapter>(card)};

    PICC picc{};
    EXPECT_TRUE(layer.detect(picc));
    EXPECT_EQ(picc.idm[0], idm_sample[0]);  // system 0
    EXPECT_EQ(card->answers(), 1);          // only the wildcard answered
}

TEST(NFC_F, DetectCardSplitIntoSystems)
{
    // The same card with a second system on FE00. Polling FE00 answers with the system's own IDm,
    // whose first byte differs from the first answer's, and detect() has to keep the card anyway:
    // FeliCa Networks' "Handling of the manufacture ID (IDm) of mobile FeliCa IC chips" 1.10
    // section 1.3 recommends against branching on whether the IDms of different systems match
    auto card = new ScriptedCardForF({0x0003, system_code_shared});
    NFCLayerF layer{std::unique_ptr<NFCLayerF::Adapter>(card)};

    PICC picc{};
    EXPECT_TRUE(layer.detect(picc));
    EXPECT_GT(card->answers(), 1);  // FE00 did answer, so the card really is split
}
