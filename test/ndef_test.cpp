/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for NDEF
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include <nfc/ndef/ndef.hpp>
#include <nfc/ndef/ndef_tlv.hpp>
#include <nfc/ndef/ndef_record.hpp>
#include <cstring>

using namespace m5::nfc::ndef;

namespace {

constexpr char en_data[] = "Hello M5Stack";       // 13
constexpr char ja_data[] = "こんにちは M5Stack";  // 23
constexpr char zh_data[] = "你好 M5Stack";        // 14

constexpr char en_lang[] = "en";
constexpr char ja_lang[] = "ja";
constexpr char zh_lang[] = "zh";

constexpr char ftp_data[] = "ftp://anonymous:anonymous@example.com/";

}  // namespace

TEST(NDEF, Record)
{
    Record r(TNF::Wellknown);

    EXPECT_EQ(r.tnf(), TNF::Wellknown);
    EXPECT_EQ(r.required(), 3U);  // attr + type len + payload len
    EXPECT_FALSE(r.attribute().idLength());
    EXPECT_TRUE(strcmp(r.type(), "") == 0);
    EXPECT_EQ(r.identifierSize(), 0U);
    EXPECT_EQ(r.identifier(), nullptr);
    EXPECT_EQ(r.payloadSize(), 0U);
    EXPECT_EQ(r.payload(), nullptr);
    // r.dump();

    // ID
    {
        uint8_t id[7] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

        r.setIdentifier(id, 7);
        EXPECT_EQ(r.required(), 4U + 7U);  // attr + type len + payload len + id len + id[7]
        EXPECT_TRUE(r.attribute().idLength());
        EXPECT_EQ(r.identifierSize(), 7U);
        EXPECT_NE(r.identifier(), nullptr);
        // r.dump();

        uint8_t id2{0x52};
        r.setIdentifier(&id2, 1);
        EXPECT_EQ(r.required(), 4U + 1U);  // id[1]
        EXPECT_TRUE(r.attribute().idLength());
        EXPECT_EQ(r.identifierSize(), 1U);
        EXPECT_NE(r.identifier(), nullptr);
        // r.dump();

        r.clearIdentifier();
        EXPECT_EQ(r.required(), 3U);
        EXPECT_FALSE(r.attribute().idLength());
        EXPECT_EQ(r.identifierSize(), 0U);
        EXPECT_EQ(r.identifier(), nullptr);
        // r.dump();

        r.setIdentifier(id, 7);
        EXPECT_EQ(r.required(), 4U + 7U);
        EXPECT_TRUE(r.attribute().idLength());
        EXPECT_EQ(r.identifierSize(), 7U);
        EXPECT_NE(r.identifier(), nullptr);
        // r.dump();
    }

    // Payload
    {
        EXPECT_TRUE(strcmp(r.type(), "") == 0);

        r.setTextPayload(en_data, "en");
        EXPECT_TRUE(strcmp(r.type(), "T") == 0);
        EXPECT_EQ(r.required(), 4U + 1U + 7U +       // attr + type len + payload len + id len + type[1] + id[7]
                                    1U + 2U + 13U);  // status + lang[2] + txt[13]
        // r.dump();

        r.setURIPayload("https://m5stack.com", URIProtocol::HTTPS);
        EXPECT_TRUE(strcmp(r.type(), "U") == 0);

        r.setTextPayload(ja_data, "ja");
        EXPECT_TRUE(strcmp(r.type(), "T") == 0);
        EXPECT_EQ(r.required(), 4U + 1U + 7U +       //
                                    1U + 2U + 23U);  // status + lang[2] + txt[23]
        // r.dump();

        r.setTextPayload(zh_data, "zh");
        EXPECT_TRUE(strcmp(r.type(), "T") == 0);
        EXPECT_EQ(r.required(), 4U + 1U + 7U +       //
                                    1U + 2U + 14U);  // status + lang[2] + txt[14]
        // r.dump();
    }

    {
        uint8_t buf[256]{};
        auto encoded = r.encode(buf, 256);
        EXPECT_EQ(encoded, 4U + 1U + 7U +       //
                               1U + 2U + 14U);  // status + lang[2] + txt[14]
        Record r2{};
        auto decoded = r2.decode(buf, encoded);
        EXPECT_EQ(encoded, decoded);

        EXPECT_EQ(r.attribute().value, r2.attribute().value);
        auto tlen  = strlen(r.type());
        auto tlen2 = strlen(r2.type());
        EXPECT_EQ(tlen, tlen2);
        EXPECT_TRUE(std::memcmp(r.type(), r2.type(), tlen) == 0);

        auto ilen  = r.identifierSize();
        auto ilen2 = r2.identifierSize();
        EXPECT_EQ(ilen, ilen2);
        EXPECT_TRUE(std::memcmp(r.identifier(), r2.identifier(), ilen) == 0);

        auto plen  = r.payloadSize();
        auto plen2 = r2.payloadSize();
        EXPECT_EQ(plen, plen2);
        EXPECT_TRUE(std::memcmp(r.payload(), r2.payload(), plen) == 0);
    }

    // Decode error cases
    {
        uint8_t buf[256]{};
        auto encoded = r.encode(buf, 256);

        // Too short header
        Record r3{};
        EXPECT_EQ(r3.decode(buf, 2), 0u);

        // Payload length exceeds buffer
        buf[0] |= Attribute::SR;  // ensure short record
        buf[2] = 0xFF;            // payload length too large
        Record r4{};
        EXPECT_EQ(r4.decode(buf, encoded), 0u);

        // Long record but too short for 4-byte length
        uint8_t long_buf[] = {0x00, 0x01, 0x00, 0x00, 0x00};
        Record r5{};
        EXPECT_EQ(r5.decode(long_buf, sizeof(long_buf)), 0u);
    }
}

TEST(NDEF, TLV)
{
    constexpr uint8_t empty[3] = {0x03, 0x00, 0xFE};
    uint8_t buf[1024]{};
    TLV msg{Tag::Message};
    Record r0{}, r1{}, r2{};

    {
        EXPECT_EQ(msg.tag(), Tag::Message);
        EXPECT_EQ(msg.records().size(), 0U);
        EXPECT_EQ(msg.required(), 2);  // tag + record len
        // msg.dump();

        auto encoded = msg.encode(buf, 256);
        EXPECT_EQ(encoded, 2);
        EXPECT_TRUE(std::memcmp(buf, empty, 2) == 0);

        //

        // 0
        r0.setTextPayload(en_data, en_lang);
        EXPECT_TRUE(strcmp(r0.type(), "T") == 0);
        EXPECT_EQ(r0.required(), 20);
        EXPECT_TRUE(strcmp(en_data, r0.payloadAsString().c_str()) == 0);

        msg.push_back(r0);
        EXPECT_EQ(msg.records().size(), 1U);
        EXPECT_EQ(msg.required(), 2 + 20);  // tag + record len + records
        EXPECT_EQ(msg.required(), 2 + r0.required());

        encoded = msg.encode(buf, 1024);
        EXPECT_EQ(encoded, 22);
        EXPECT_EQ(encoded, msg.required());

        // 1
        r1.setTextPayload(zh_data, zh_lang);
        EXPECT_TRUE(strcmp(r1.type(), "T") == 0);
        EXPECT_EQ(r1.required(), 21);
        EXPECT_TRUE(strcmp(zh_data, r1.payloadAsString().c_str()) == 0);

        msg.push_back(r1);
        EXPECT_EQ(msg.records().size(), 2U);
        EXPECT_EQ(msg.required(), 2 + 20 + 21);  // tag + record len + records
        EXPECT_EQ(msg.required(), 2 + r0.required() + r1.required());

        encoded = msg.encode(buf, 1024);
        EXPECT_EQ(encoded, 43);
        EXPECT_EQ(encoded, msg.required());

        // 2
        r2.setURIPayload(ftp_data, URIProtocol::FTP_AA);
        EXPECT_TRUE(strcmp(r2.type(), "U") == 0);
        EXPECT_EQ(r2.required(), 17);
        EXPECT_TRUE(strcmp(ftp_data, r2.payloadAsString().c_str()) == 0);

        msg.push_back(r2);
        EXPECT_EQ(msg.records().size(), 3U);
        EXPECT_EQ(msg.required(), 2 + 20 + 21 + 17);  // tag + record len + records
        EXPECT_EQ(msg.required(), 2 + r0.required() + r1.required() + r2.required());

        encoded = msg.encode(buf, 1024);
        EXPECT_EQ(encoded, 60);
        EXPECT_EQ(encoded, msg.required());

        // M5_LOGI("[%s]", r2.payloadAsString().c_str());
        // msg.dump();
    }

    {
        auto encoded = msg.encode(buf, 256);
        TLV msg2{};
        auto decoded = msg2.decode(buf, encoded);

        EXPECT_EQ(encoded, decoded);
        auto t  = msg.tag();
        auto t2 = msg2.tag();
        EXPECT_EQ(t, t2);
        EXPECT_EQ(msg.records().size(), msg2.records().size());
        EXPECT_EQ(msg.required(), msg2.required());
        EXPECT_EQ(msg.records(), msg2.records());
    }

    // Decode error cases
    {
        // Invalid tag
        uint8_t invalid_tag[] = {0x04, 0x00};
        TLV t{};
        EXPECT_EQ(t.decode(invalid_tag, sizeof(invalid_tag)), 0u);

        // Extended length but too short
        uint8_t short_ext_len[] = {0x01, 0xFF, 0x00};
        EXPECT_EQ(t.decode(short_ext_len, sizeof(short_ext_len)), 0u);

        // Payload length exceeds buffer (non-message)
        uint8_t long_len[] = {0x01, 0xFF, 0x00, 0x10, 0xAA};
        EXPECT_EQ(t.decode(long_len, sizeof(long_len)), 0u);

        // Message TLV with MB cleared should fail
        uint8_t buf2[256]{};
        auto encoded = msg.encode(buf2, 256);
        buf2[2]      = static_cast<uint8_t>(buf2[2] & ~Attribute::MB);
        TLV msg3{};
        EXPECT_EQ(msg3.decode(buf2, encoded), 0u);

        // Second record with MB=1 should fail
        uint8_t buf3[256]{};
        auto encoded3           = msg.encode(buf3, 256);
        buf3[2 + r0.required()] = static_cast<uint8_t>(buf3[2 + r0.required()] | Attribute::MB);
        TLV msg4{};
        EXPECT_EQ(msg4.decode(buf3, encoded3), 0u);

        // Last record missing ME should fail
        uint8_t buf4[256]{};
        auto encoded4 = msg.encode(buf4, 256);
        buf4[2 + r0.required() + r1.required()] =
            static_cast<uint8_t>(buf4[2 + r0.required() + r1.required()] & ~Attribute::ME);
        TLV msg5{};
        EXPECT_EQ(msg5.decode(buf4, encoded4), 0u);
    }
}

TEST(NDEF, TagAndTagBits)
{
    // tag_to_tagbit
    EXPECT_EQ(tag_to_tagbit(Tag::Null), 1u << 0);
    EXPECT_EQ(tag_to_tagbit(Tag::LockControl), 1u << 1);
    EXPECT_EQ(tag_to_tagbit(Tag::MemoryControl), 1u << 2);
    EXPECT_EQ(tag_to_tagbit(Tag::Message), 1u << 3);
    EXPECT_EQ(tag_to_tagbit(Tag::Proprietary), 1u << 4);
    EXPECT_EQ(tag_to_tagbit(Tag::Terminator), 1u << 5);

    // make_tag_bits
    auto bits1 = make_tag_bits(Tag::Message);
    EXPECT_EQ(bits1, 1u << 3);

    auto bits2 = make_tag_bits(Tag::Message, Tag::Terminator);
    EXPECT_EQ(bits2, (1u << 3) | (1u << 5));

    // contains_tag
    EXPECT_TRUE(contains_tag(bits2, Tag::Message));
    EXPECT_TRUE(contains_tag(bits2, Tag::Terminator));
    EXPECT_FALSE(contains_tag(bits2, Tag::Null));
    EXPECT_FALSE(contains_tag(bits2, Tag::LockControl));

    // Pre-defined constants
    EXPECT_TRUE(contains_tag(tagBitsAll, Tag::LockControl));
    EXPECT_TRUE(contains_tag(tagBitsAll, Tag::MemoryControl));
    EXPECT_TRUE(contains_tag(tagBitsAll, Tag::Message));
    EXPECT_TRUE(contains_tag(tagBitsAll, Tag::Proprietary));
    EXPECT_TRUE(contains_tag(tagBitsAll, Tag::Terminator));

    EXPECT_TRUE(contains_tag(tagBitsMessage, Tag::Message));
    EXPECT_FALSE(contains_tag(tagBitsMessage, Tag::Terminator));

    // is_valid_tag
    EXPECT_TRUE(is_valid_tag(0x00));   // Null
    EXPECT_TRUE(is_valid_tag(0x01));   // LockControl
    EXPECT_TRUE(is_valid_tag(0x02));   // MemoryControl
    EXPECT_TRUE(is_valid_tag(0x03));   // Message
    EXPECT_TRUE(is_valid_tag(0xFD));   // Proprietary
    EXPECT_TRUE(is_valid_tag(0xFE));   // Terminator
    EXPECT_FALSE(is_valid_tag(0x04));  // Invalid
    EXPECT_FALSE(is_valid_tag(0xFF));  // Invalid

    // is_terminator_tag
    EXPECT_TRUE(is_terminator_tag(0xFE));
    EXPECT_FALSE(is_terminator_tag(0x00));
    EXPECT_FALSE(is_terminator_tag(0x03));
}

TEST(NDEF, URIProtocol)
{
    // get_uri_idc_string
    EXPECT_STREQ(get_uri_idc_string(URIProtocol::NA), "");
    EXPECT_STREQ(get_uri_idc_string(URIProtocol::HTTP_WWW), "http://www.");
    EXPECT_STREQ(get_uri_idc_string(URIProtocol::HTTPS_WWW), "https://www.");
    EXPECT_STREQ(get_uri_idc_string(URIProtocol::HTTP), "http://");
    EXPECT_STREQ(get_uri_idc_string(URIProtocol::HTTPS), "https://");
    EXPECT_STREQ(get_uri_idc_string(URIProtocol::TEL), "tel:");
    EXPECT_STREQ(get_uri_idc_string(URIProtocol::MAILTO), "mailto:");
    EXPECT_STREQ(get_uri_idc_string(URIProtocol::FTP_AA), "ftp://anonymous:anonymous@");
    EXPECT_STREQ(get_uri_idc_string(URIProtocol::FTP), "ftp://");
    EXPECT_STREQ(get_uri_idc_string(URIProtocol::FILE), "file://");
    EXPECT_STREQ(get_uri_idc_string(URIProtocol::NFC), "urn:nfc:");
}

TEST(NDEF, Type2CapabilityContainer)
{
    type2::CapabilityContainer cc{};

    // Invalid by default (block[0] != MAGIC_NO)
    EXPECT_FALSE(cc.valid());

    // Set valid values
    cc.block[0] = MAGIC_NO_CC4;
    cc.major_version(NDEF_MAJOR_VERSION);
    cc.minor_version(NDEF_MINOR_VERSION);
    cc.ndef_size(256);
    cc.read_access(ACCESS_FREE);
    cc.write_access(ACCESS_FREE);

    EXPECT_TRUE(cc.valid());
    EXPECT_TRUE(cc.can_read());
    EXPECT_TRUE(cc.can_write());
    EXPECT_EQ(cc.major_version(), NDEF_MAJOR_VERSION);
    EXPECT_EQ(cc.minor_version(), NDEF_MINOR_VERSION);
    EXPECT_EQ(cc.ndef_size(), 256);
    EXPECT_EQ(cc.read_access(), ACCESS_FREE);
    EXPECT_EQ(cc.write_access(), ACCESS_FREE);

    // Test read-only
    cc.write_access(ACCESS_PROPRIETARY);
    EXPECT_TRUE(cc.can_read());
    EXPECT_FALSE(cc.can_write());

    // Max NDEF size test (>2040 sets to 0)
    cc.ndef_size(2048);
    EXPECT_EQ(cc.ndef_size(), 0);
    cc.ndef_size(2040);
    EXPECT_EQ(cc.ndef_size(), 2040);
}

TEST(NDEF, Type3AttributeBlock)
{
    type3::AttributeBlock ab{};

    // Default version
    EXPECT_EQ(ab.version(), +type3::AttributeBlock::DEFAULT_VERSION);

    // Set values
    ab.max_block_to_read(4);
    ab.max_block_to_write(1);
    ab.blocks_for_ndef_storage(0x000D);  // 13 blocks
    ab.write_flag(type3::AttributeBlock::WriteFlag::Done);
    ab.access_flag(type3::AttributeBlock::AccessFlag::ReadWrite);
    ab.current_ndef_message_length(100);

    EXPECT_EQ(ab.max_block_to_read(), 4);
    EXPECT_EQ(ab.max_block_to_write(), 1);
    EXPECT_EQ(ab.blocks_for_ndef_storage(), 0x000D);
    EXPECT_EQ(ab.write_flag(), type3::AttributeBlock::WriteFlag::Done);
    EXPECT_EQ(ab.access_flag(), type3::AttributeBlock::AccessFlag::ReadWrite);
    EXPECT_EQ(ab.current_ndef_message_length(), 100u);

    // WriteFlag::InProgress
    ab.write_flag(type3::AttributeBlock::WriteFlag::InProgress);
    EXPECT_EQ(ab.write_flag(), type3::AttributeBlock::WriteFlag::InProgress);

    // Checksum
    auto checksum = ab.calculate_check_sum();
    EXPECT_NE(checksum, 0);
    ab.update_check_sum();
    EXPECT_EQ(ab.check_sum(), checksum);
}

TEST(NDEF, Type4FileControl)
{
    using namespace type4;

    // fc_to_fcbit
    EXPECT_EQ(fc_to_fcbit(FileControlTag::Message), 1u << 0);
    EXPECT_EQ(fc_to_fcbit(FileControlTag::Proprietary), 1u << 1);

    // make_fc_bits
    auto bits = make_fc_bits(FileControlTag::Message, FileControlTag::Proprietary);
    EXPECT_TRUE(contains_file_control_tag(bits, FileControlTag::Message));
    EXPECT_TRUE(contains_file_control_tag(bits, FileControlTag::Proprietary));

    EXPECT_TRUE(contains_file_control_tag(fcBitsAll, FileControlTag::Message));
    EXPECT_TRUE(contains_file_control_tag(fcBitsAll, FileControlTag::Proprietary));
    EXPECT_TRUE(contains_file_control_tag(fcBitsMessage, FileControlTag::Message));
    EXPECT_FALSE(contains_file_control_tag(fcBitsMessage, FileControlTag::Proprietary));

    // FileControlTLV
    FileControlTLV fctlv{};
    fctlv.tag = 0x04;
    EXPECT_EQ(fctlv.fctag(), FileControlTag::Message);

    // CapabilityContainer (basic)
    CapabilityContainer cc{};
    EXPECT_FALSE(cc.valid());  // Empty fctlvs
}

TEST(NDEF, Type5CapabilityContainer)
{
    type5::CapabilityContainer cc{};

    // Invalid by default
    EXPECT_FALSE(cc.valid());
    EXPECT_EQ(cc.size(), 0);

    // 4-byte CC
    cc.block[0] = MAGIC_NO_CC4;
    cc.major_version(NDEF_MAJOR_VERSION);
    cc.minor_version(NDEF_MINOR_VERSION);
    cc.ndef_size(256);
    cc.read_access(ACCESS_FREE);
    cc.write_access(ACCESS_FREE);

    EXPECT_TRUE(cc.valid());
    EXPECT_EQ(cc.size(), 4);
    EXPECT_TRUE(cc.can_read());
    EXPECT_TRUE(cc.can_write());
    EXPECT_EQ(cc.major_version(), NDEF_MAJOR_VERSION);
    EXPECT_EQ(cc.minor_version(), NDEF_MINOR_VERSION);
    EXPECT_EQ(cc.ndef_size(), 256);

    // 8-byte CC
    type5::CapabilityContainer cc8{};
    cc8.block[0] = MAGIC_NO_CC8;
    cc8.major_version(NDEF_MAJOR_VERSION);
    cc8.minor_version(NDEF_MINOR_VERSION);
    cc8.block[6] = 0x10;  // ndef_size high byte
    cc8.block[7] = 0x00;  // ndef_size low byte (4096)

    EXPECT_TRUE(cc8.valid());
    EXPECT_EQ(cc8.size(), 8);
    EXPECT_EQ(cc8.ndef_size(), 0x1000);

    // Additional feature
    cc.addtional_feature(0x01);
    EXPECT_EQ(cc.addtional_feature(), 0x01);
}

TEST(NDEF, TLVExtended)
{
    // Terminator TLV
    EXPECT_TRUE(TLV::Terminator.isTerminatorTLV());
    EXPECT_FALSE(TLV::Terminator.isMessageTLV());
    EXPECT_FALSE(TLV::Terminator.isNullTLV());
    EXPECT_EQ(TLV::Terminator.tag(), Tag::Terminator);

    // Null TLV
    TLV nullTlv{Tag::Null};
    EXPECT_TRUE(nullTlv.isNullTLV());
    EXPECT_FALSE(nullTlv.isMessageTLV());
    EXPECT_FALSE(nullTlv.isTerminatorTLV());

    // Message TLV
    TLV msgTlv{Tag::Message};
    EXPECT_TRUE(msgTlv.isMessageTLV());
    EXPECT_FALSE(msgTlv.isNullTLV());
    EXPECT_FALSE(msgTlv.isTerminatorTLV());

    // pop_back
    Record r;
    r.setTextPayload("Test", "en");
    msgTlv.push_back(r);
    EXPECT_EQ(msgTlv.records().size(), 1u);
    msgTlv.pop_back();
    EXPECT_EQ(msgTlv.records().size(), 0u);

    // clear (note: tag is reset to Null by clear())
    msgTlv.push_back(r);
    msgTlv.push_back(r);
    EXPECT_EQ(msgTlv.records().size(), 2u);
    msgTlv.clear();
    EXPECT_EQ(msgTlv.records().size(), 0u);
    EXPECT_EQ(msgTlv.tag(), Tag::Null);
    EXPECT_EQ(msgTlv.payload().size(), 0u);

    // Non-message TLV payload
    TLV lockTlv{Tag::LockControl};
    lockTlv.payload().push_back(0x01);
    lockTlv.payload().push_back(0x02);
    EXPECT_EQ(lockTlv.payload().size(), 2u);
}

TEST(NDEF, RecordLengthBoundary)
{
    Record r(TNF::Wellknown);
    r.setType("U");

    std::vector<uint8_t> payload255(255, 0xAB);
    r.setPayload(payload255.data(), payload255.size());
    EXPECT_TRUE(r.attribute().shortRecord());

    std::vector<uint8_t> buf(512);
    auto encoded = r.encode(buf.data(), buf.size());
    EXPECT_GT(encoded, 0u);

    Record r2{};
    auto decoded = r2.decode(buf.data(), encoded);
    EXPECT_EQ(decoded, encoded);
    EXPECT_TRUE(r2.attribute().shortRecord());

    std::vector<uint8_t> payload256(256, 0xCD);
    r.setPayload(payload256.data(), payload256.size());
    EXPECT_FALSE(r.attribute().shortRecord());

    encoded = r.encode(buf.data(), buf.size());
    EXPECT_GT(encoded, 0u);
    decoded = r2.decode(buf.data(), encoded);
    EXPECT_EQ(decoded, encoded);
    EXPECT_FALSE(r2.attribute().shortRecord());
}

TEST(NDEF, RecordEmptyTNF)
{
    Record r(TNF::Empty);
    uint8_t id[2]      = {0x01, 0x02};
    uint8_t payload[3] = {0xAA, 0xBB, 0xCC};

    r.setIdentifier(id, sizeof(id));
    r.setPayload(payload, sizeof(payload));

    EXPECT_EQ(r.identifierSize(), 0u);
    EXPECT_EQ(r.payloadSize(), 0u);
    EXPECT_EQ(r.required(), 3u);
}

TEST(NDEF, TLVExtendedLength)
{
    uint8_t buf[1024]{};

    TLV lockTlv{Tag::LockControl};
    lockTlv.payload().assign(0xFF, 0x11);
    auto encoded = lockTlv.encode(buf, sizeof(buf));
    EXPECT_GT(encoded, 0u);
    EXPECT_EQ(buf[0], m5::stl::to_underlying(Tag::LockControl));
    EXPECT_EQ(buf[1], 0xFF);
    EXPECT_EQ(buf[2], 0x00);
    EXPECT_EQ(buf[3], 0xFF);

    TLV lockTlv2{};
    auto decoded = lockTlv2.decode(buf, encoded);
    EXPECT_EQ(decoded, encoded);
    EXPECT_EQ(lockTlv2.payload().size(), 0xFFu);

    lockTlv.payload().assign(0x100, 0x22);
    encoded = lockTlv.encode(buf, sizeof(buf));
    EXPECT_GT(encoded, 0u);
    EXPECT_EQ(buf[1], 0xFF);
    EXPECT_EQ(buf[2], 0x01);
    EXPECT_EQ(buf[3], 0x00);

    decoded = lockTlv2.decode(buf, encoded);
    EXPECT_EQ(decoded, encoded);
    EXPECT_EQ(lockTlv2.payload().size(), 0x100u);
}

TEST(NDEF, Attribute)
{
    Attribute attr{};

    // Default state
    EXPECT_FALSE(attr.messageBegin());
    EXPECT_FALSE(attr.messageEnd());
    EXPECT_FALSE(attr.chunk());
    EXPECT_FALSE(attr.shortRecord());
    EXPECT_FALSE(attr.idLength());
    EXPECT_EQ(attr.tnf(), TNF::Empty);

    // Set flags
    attr.messageBegin(true);
    EXPECT_TRUE(attr.messageBegin());
    EXPECT_EQ(attr.value & Attribute::MB, Attribute::MB);

    attr.messageEnd(true);
    EXPECT_TRUE(attr.messageEnd());

    attr.chunk(true);
    EXPECT_TRUE(attr.chunk());

    attr.shortRecord(true);
    EXPECT_TRUE(attr.shortRecord());

    attr.idLength(true);
    EXPECT_TRUE(attr.idLength());

    attr.tnf(TNF::Wellknown);
    EXPECT_EQ(attr.tnf(), TNF::Wellknown);

    // Clear flags
    attr.messageBegin(false);
    EXPECT_FALSE(attr.messageBegin());

    // TNF values
    attr.tnf(TNF::MIMEMedia);
    EXPECT_EQ(attr.tnf(), TNF::MIMEMedia);

    attr.tnf(TNF::URI);
    EXPECT_EQ(attr.tnf(), TNF::URI);

    attr.tnf(TNF::External);
    EXPECT_EQ(attr.tnf(), TNF::External);
}

TEST(NDEF, RecordExtended)
{
    // Record comparison
    Record r1(TNF::Wellknown);
    Record r2(TNF::Wellknown);
    r1.setTextPayload("Hello", "en");
    r2.setTextPayload("Hello", "en");
    EXPECT_TRUE(r1 == r2);
    EXPECT_FALSE(r1 != r2);

    r2.setTextPayload("World", "en");
    EXPECT_FALSE(r1 == r2);
    EXPECT_TRUE(r1 != r2);

    // Different TNF
    Record r3(TNF::MIMEMedia);
    r3.setType("text/plain");
    EXPECT_FALSE(r1 == r3);

    // Record::clear
    r1.clear();
    EXPECT_EQ(r1.payloadSize(), 0u);
    EXPECT_EQ(r1.identifierSize(), 0u);
    EXPECT_TRUE(strcmp(r1.type(), "") == 0);

    // URI payload with different protocols
    Record uriRec(TNF::Wellknown);
    uriRec.setURIPayload("https://www.example.com", URIProtocol::HTTPS_WWW);
    EXPECT_STREQ(uriRec.type(), "U");
    // The protocol prefix should be stripped
    EXPECT_TRUE(uriRec.payloadSize() > 0);
}
