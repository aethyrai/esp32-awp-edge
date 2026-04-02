idf_component_register(
    SRCS
        "blake3.c"
        "blake3_dispatch.c"
        "blake3_portable.c"
    INCLUDE_DIRS "."
)

# Disable all SIMD — ESP32 is Xtensa, not x86
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    BLAKE3_NO_SSE2
    BLAKE3_NO_SSE41
    BLAKE3_NO_AVX2
    BLAKE3_NO_AVX512
    BLAKE3_NO_NEON
)
