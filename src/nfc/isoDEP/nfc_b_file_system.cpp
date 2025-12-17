/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file desfire_file_system.cpp
  @brief File system base using isoDEP for NFC-B
*/
#include "nfc_b_file_system.hpp"
#include "nfc/layer/nfc_layer_b.hpp"
#include "nfc/isodep/isoDEP.hpp"
#include "nfc/apdu/apdu.hpp"
#include <M5Utility.hpp>

using namespace m5::nfc;
using namespace m5::nfc::apdu;
using namespace m5::nfc::isodep;

namespace m5 {
namespace nfc {

NFCBFileSystem::NFCBFileSystem(m5::nfc::NFCLayerB& layer) : FileSystem{layer.isoDEP()}
{
    const auto& picc = layer.activatedPICC();
    auto cfg             = _isoDEP.config();
    cfg.fwt_ms           = fwi_to_ms(picc.fwi(), 13.56e6f);
    cfg.fsc              = picc.maximumFrameLength();
    cfg.pcd_max_frame_tx = cfg.pcd_max_frame_rx = 256;  // TODO FIFO_DEPTH
    _isoDEP.config(cfg);
}

}  // namespace nfc
}  // namespace m5
