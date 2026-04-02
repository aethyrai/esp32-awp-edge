idf_component_register(
    SRCS
        "mlkem_native.c"
        "randombytes.c"
    INCLUDE_DIRS "." "src"
    REQUIRES esp_hw_support
)

# ML-KEM-768, portable C only
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    MLK_CONFIG_PARAMETER_SET=768
)
