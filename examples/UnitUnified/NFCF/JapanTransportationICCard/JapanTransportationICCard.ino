/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916
  Read JapanTransportationICCard
*/
// *************************************************************
// Choose one define symbol to match the unit you are using
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_CAP_CC1101)
// For UnitNFC
// #define USING_UNIT_NFC
// For CapNFC
// #define USING_CAP_CC1101
#endif
#include "main/JapanTransportationICCard.cpp"
