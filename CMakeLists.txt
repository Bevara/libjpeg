cmake_minimum_required(VERSION 3.7)
project(Filters)

include(filters.cmake)

add_definitions(-fpic)

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS "-O3 -Wall -Wextra")
set(CMAKE_C_FLAGS "-O3 -Wall -Wextra")

SET(JPEG_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/img.c
#        ${CMAKE_CURRENT_SOURCE_DIR}/enc_jpg.c
        ${CMAKE_CURRENT_SOURCE_DIR}/dec_jpeg.c
        ${CMAKE_CURRENT_SOURCE_DIR}/reframe_jpeg.c
#        ${CMAKE_CURRENT_SOURCE_DIR}/convert.c
)

SET(JPEG_LIB
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/libjpeg.a
)

SET(JPEG_INC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_filter(libjpeg
        "${JPEG_SRC}"
        "${JPEG_LIB}"
        []
        GPAC_HAS_JPEG
        "${JPEG_INC}"
        ""
        "1")
