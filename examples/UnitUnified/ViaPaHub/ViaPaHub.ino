/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916 / WS1850S
  Detect PICCs of every NFC family the unit supports, reached through a PaHub
*/
// *************************************************************
// Choose ONE define symbol to match the unit you are using
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_UNIT_RFID2)
// For UnitNFC (U216)
// #define USING_UNIT_NFC
// For UnitRFID2 (U031-B)
// #define USING_UNIT_RFID2
#endif
#include "main/ViaPaHub.cpp"
