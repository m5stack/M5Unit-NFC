# Dependencies (M5Unit-NFC, M5Unit-HUB, M5UnitUnified, M5Unified, ...) are pulled in via
# main/idf_component.yml and auto-added as requirements by the component manager.
idf_component_register(
    SRCS "ViaPaHub.cpp"
    INCLUDE_DIRS ".")

# The unit/board variant is selected via Kconfig (main/Kconfig.projbuild -> common/Kconfig.variant)
# with `idf.py menuconfig` or sdkconfig.defaults (e.g. CONFIG_EXAMPLE_USING_UNIT_RFID2=y). The
# CONFIG_* -> USING_* mapping is shared by all UnitUnified examples. Include it after the register
# call (it needs ${COMPONENT_LIB}).
include("${CMAKE_CURRENT_LIST_DIR}/../../common/variant.cmake")
