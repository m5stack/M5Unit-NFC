# ESP-IDF component registration for M5Unit-NFC.
# Upstream: https://github.com/m5stack/M5Unit-NFC
#
# UnitNFC (= UnitST25R3916) over I2C. IRQ wiring and CapCC1101 SPI CS
# handling use the ESP-IDF native gpio_config / gpio_isr_handler_add API
# directly; this works under both pure ESP-IDF and Arduino-ESP32 builds.
file(GLOB_RECURSE SRCS "src/*.cpp")
idf_component_register(
    SRCS ${SRCS}
    INCLUDE_DIRS "src"
    REQUIRES M5UnitUnified M5Utility
    PRIV_REQUIRES driver mbedtls
)
